from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from dataclasses import dataclass

from divide.config import AppConfig
from divide.models import Candidate, Finding, VerificationDecision
from divide.rulesets import ChecksumRegistry


@dataclass(slots=True)
class VerificationResult:
    findings: list[Finding]
    rejected: int
    duplicates: int
    decisions: list[VerificationDecision]


class Verifier:
    def __init__(self, config: AppConfig, checksums: ChecksumRegistry | None = None):
        self.config = config
        self.checksums = checksums or ChecksumRegistry()

    def verify(self, candidates: list[Candidate], *, post_filter: bool = True) -> VerificationResult:
        accepted: list[Finding] = []
        decisions: list[VerificationDecision] = []
        rejected = 0
        for candidate in candidates:
            finding, decision = self._verify_one(candidate, post_filter=post_filter)
            decisions.append(decision)
            if finding is None:
                rejected += 1
            else:
                accepted.append(finding)

        # Candidate-stage deduplication is value + source location. Project-level
        # unique-secret normalization is intentionally confined to evaluation.
        merged: dict[tuple[str, str], Finding] = {}
        for finding in accepted:
            source = finding.sources[0]
            location_key = "\0".join((finding.root_path, source["nested_path"], source["location"]))
            key = (finding.fingerprint, location_key)
            previous = merged.get(key)
            if previous is None:
                merged[key] = finding
                continue
            previous.confidence = max(previous.confidence, finding.confidence)
            previous.structural_evidence = list(dict.fromkeys(previous.structural_evidence + finding.structural_evidence))
            previous.contextual_evidence = list(dict.fromkeys(previous.contextual_evidence + finding.contextual_evidence))
            if finding.recovery_trace.confidence > previous.recovery_trace.confidence:
                previous.recovery_trace = finding.recovery_trace
                previous.decision = finding.decision
        findings = sorted(merged.values(), key=lambda item: (-item.confidence, item.root_path, item.fingerprint))
        return VerificationResult(findings, rejected, len(accepted) - len(findings), decisions)

    def _decision(
        self, candidate: Candidate, accepted: bool, stage: str, score: float, reasons: list[str],
    ) -> VerificationDecision:
        return VerificationDecision(
            hashlib.sha256(candidate.value.encode()).hexdigest(), accepted, stage, max(0.0, min(1.0, score)),
            reasons, candidate.rule_id,
        )

    def _verify_one(self, candidate: Candidate, *, post_filter: bool) -> tuple[Finding | None, VerificationDecision]:
        metadata = candidate.rule_metadata
        reasons = [f"credential type inferred as {candidate.credential_type}"]

        # 1. type/version inference; 2. hard structural constraints.
        value_length = len(candidate.value)
        if not int(metadata.get("min_length", 1)) <= value_length <= int(metadata.get("max_length", 65536)):
            decision = self._decision(candidate, False, "hard:length", 0, [*reasons, "length constraint failed"])
            return None, decision
        prefixes = metadata.get("prefixes") or []
        if prefixes and not any(candidate.value.startswith(prefix) for prefix in prefixes):
            decision = self._decision(candidate, False, "hard:prefix", 0, [*reasons, "prefix constraint failed"])
            return None, decision
        charset = metadata.get("charset")
        if charset and re.fullmatch(str(charset), candidate.value) is None:
            decision = self._decision(candidate, False, "hard:charset", 0, [*reasons, "character-set constraint failed"])
            return None, decision
        delimiter = metadata.get("delimiter_pattern")
        if delimiter and re.fullmatch(str(delimiter), candidate.value) is None:
            decision = self._decision(candidate, False, "hard:delimiter", 0, [*reasons, "delimiter constraint failed"])
            return None, decision
        structural = [
            f"length {value_length} valid", "prefix valid" if prefixes else "no prefix constraint",
            "character set valid" if charset else "no explicit character-set constraint",
            f"format version {metadata.get('format_version') or 'unspecified'}",
        ]

        # 3. provider checksum.
        checksum = metadata.get("checksum")
        if checksum:
            valid, detail = self.checksums.validate(
                str(checksum), candidate.value, candidate.credential_type, metadata.get("format_version"),
            )
            if not valid:
                decision = self._decision(candidate, False, "hard:checksum", 0, [*reasons, detail])
                return None, decision
            structural.append(f"checksum valid ({checksum})")

        # 4. exact normalized placeholder filter. No substring rejection.
        normalized = _normalize_placeholder(candidate.value)
        placeholders = {_normalize_placeholder(value) for value in self.config.hard_placeholders}
        if normalized in placeholders:
            decision = self._decision(candidate, False, "hard:placeholder", 0, [*reasons, "exact placeholder match"])
            return None, decision

        search_space = " ".join((candidate.context, candidate.nested_path, candidate.root_path)).casefold()
        positive_hits = sorted({term for term in self.config.positive_context if term.casefold() in search_space})
        negative_hits = sorted({term for term in self.config.negative_context if term.casefold() in search_space})
        if candidate.require_positive_context and not positive_hits:
            decision = self._decision(candidate, False, "hard:required-context", 0, [*reasons, "required field context absent"])
            return None, decision

        # Disabling post-filter is the RQ2 ablation; hard provider constraints stay enabled.
        score = candidate.base_score
        evidence: list[str] = []
        if post_filter:
            if positive_hits:
                delta = min(.18, len(positive_hits) * self.config.detection.positive_context_weight)
                score += delta
                evidence.append("positive field/context: " + ", ".join(positive_hits))
            if candidate.field_relation:
                score += self.config.detection.field_relation_weight
                evidence.append(f"field relation: {candidate.field_relation}")
            if negative_hits:
                delta = min(.18, len(negative_hits) * self.config.detection.negative_context_weight)
                score -= delta
                evidence.append("soft negative code/path context: " + ", ".join(negative_hits))
            if _looks_like_repeated_filler(candidate.value):
                score -= .25
                evidence.append("soft negative repeated filler pattern")
            entropy = _shannon_entropy(candidate.value)
            if entropy >= self.config.detection.minimum_generic_entropy:
                score += .08
                evidence.append(f"string entropy {entropy:.2f}")
            carrier_delta = _carrier_score(candidate.carrier_type) * self.config.detection.carrier_weight
            score += carrier_delta
            evidence.append(f"carrier evidence {candidate.carrier_type}: {carrier_delta:+.3f}")
            recovery_delta = (candidate.trace.confidence - .5) * self.config.detection.recovery_weight
            score += recovery_delta
            evidence.append(f"recovery confidence {candidate.trace.confidence:.2f}: {recovery_delta:+.3f}")
        else:
            score = max(score, self.config.detection.minimum_score)
            evidence.append("post-filter disabled by ablation profile")
        score = max(0.0, min(1.0, score))
        if score < self.config.detection.minimum_score:
            decision = self._decision(candidate, False, "score", score, [*reasons, *structural, *evidence])
            return None, decision

        decision = self._decision(candidate, True, "accepted", score, [*reasons, *structural, *evidence])
        finding = Finding(
            value=candidate.value, credential_type=candidate.credential_type, confidence=score,
            fingerprint=decision.candidate_fingerprint, root_path=candidate.root_path,
            sources=[{
                "nested_path": candidate.nested_path, "location": candidate.location,
                "carrier_type": candidate.carrier_type, "record_ids": candidate.trace.source_record_ids,
                "source_location_key": candidate.source_location_key,
                "matched_rule_sources": metadata.get("matched_rule_sources", []),
            }],
            structural_evidence=structural, contextual_evidence=evidence, recovery_trace=candidate.trace,
            rule_id=candidate.rule_id, rule_provider=candidate.source_provider, decision=decision,
        )
        return finding, decision


def _normalize_placeholder(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip(" \t\r\n\"'`.,;:").casefold()


def _carrier_score(carrier_type: str) -> float:
    if carrier_type in {"structured", "json", "yaml", "xml", "csv", "sqlite", "xlsx"}:
        return 1.0
    if carrier_type in {"text", "docx", "pptx", "pdf", "gettext"}:
        return .6
    if carrier_type in {"related-group", "recovery-plan", "image", "pdf-page"}:
        return .2
    return 0.0


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def _looks_like_repeated_filler(value: str) -> bool:
    compact = re.sub(r"[^A-Za-z0-9]", "", value).casefold()
    return len(compact) >= 8 and (len(set(compact)) <= 2 or bool(re.fullmatch(r"(?:abcd|1234|deadbeef)+", compact)))
