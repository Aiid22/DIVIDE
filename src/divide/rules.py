from __future__ import annotations

import math
import re
from itertools import islice
from dataclasses import dataclass, field
from typing import Any

import regex as regex_engine

from divide.config import AppConfig
from divide.models import Candidate, CarrierRecord, RecoveryTrace
from divide.rulesets import CompositeRuleProvider, ConfigRuleProvider, GitleaksRuleProvider, translate_re2


@dataclass(slots=True)
class CredentialRule:
    id: str
    name: str
    pattern: str
    min_length: int = 1
    max_length: int = 65536
    prefixes: list[str] = field(default_factory=list)
    charset: str | None = None
    delimiter_pattern: str | None = None
    checksum: str | None = None
    format_version: str | None = None
    secret_group: int = 0
    base_score: float = .5
    require_positive_context: bool = False
    entropy: float | None = None
    keywords: list[str] = field(default_factory=list)
    allowlists: list[dict[str, Any]] = field(default_factory=list)
    stopwords: list[str] = field(default_factory=list)
    provider_id: str = "divide-core"
    provider_version: str = "unknown"
    source_url: str = ""
    license: str = ""
    priority: int = 0
    regex: Any = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.regex = regex_engine.compile(translate_re2(self.pattern))

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "CredentialRule":
        allowed = {field.name for field in cls.__dataclass_fields__.values() if field.init}  # type: ignore[attr-defined]
        return cls(**{key: item for key, item in value.items() if key in allowed})

    def is_allowlisted(self, value: str, path: str, match_text: str = "") -> tuple[bool, str]:
        lowered = value.casefold()
        for stopword in self.stopwords:
            if stopword.casefold() in lowered:
                return True, f"Gitleaks stopword matched: {stopword}"
        for block in self.allowlists:
            target_name = block.get("regexTarget", "secret")
            target = {"secret": value, "match": match_text, "line": match_text, "path": path}.get(target_name, value)
            for expression in block.get("regexes", []):
                if regex_engine.search(translate_re2(expression), target):
                    return True, f"rule allowlist regex matched: {expression}"
            for expression in block.get("paths", []):
                if regex_engine.search(translate_re2(expression), path):
                    return True, f"rule allowlist path matched: {expression}"
        return False, ""

    def metadata(self) -> dict[str, Any]:
        return {
            "min_length": self.min_length, "max_length": self.max_length, "prefixes": self.prefixes,
            "charset": self.charset, "delimiter_pattern": self.delimiter_pattern, "checksum": self.checksum,
            "format_version": self.format_version, "entropy": self.entropy, "provider_id": self.provider_id,
            "provider_version": self.provider_version, "source_url": self.source_url, "license": self.license,
        }


class CandidateExtractor:
    def __init__(self, config: AppConfig, provider: CompositeRuleProvider | None = None):
        self.config = config
        self.provider = provider or CompositeRuleProvider([ConfigRuleProvider(config), GitleaksRuleProvider()])
        self.rules: list[CredentialRule] = []
        self.compile_errors: list[dict[str, str]] = []
        self.runtime_errors: list[dict[str, str]] = []
        for item in self.provider.load():
            try:
                self.rules.append(CredentialRule.from_mapping(item))
            except (re.error, regex_engine.error) as exc:
                self.compile_errors.append({"rule_id": str(item.get("id")), "error": str(exc)})

    @property
    def rule_hash(self) -> str:
        return str(self.provider.audit()["content_sha256"])

    def extract(self, text: str, record: CarrierRecord, trace: RecoveryTrace) -> list[Candidate]:
        candidates: list[Candidate] = []
        for rule in self.rules:
            if rule.keywords and not any(keyword in text for keyword in rule.keywords):
                continue
            try:
                matches = list(islice(
                    rule.regex.finditer(text, timeout=self.config.detection.max_regex_seconds),
                    self.config.limits.max_rule_matches + 1,
                ))
            except TimeoutError:
                self.runtime_errors.append({"rule_id": rule.id, "error": "regex timeout"})
                continue
            if len(matches) > self.config.limits.max_rule_matches:
                self.runtime_errors.append({"rule_id": rule.id, "error": "rule match budget reached"})
                matches.pop()
            for match in matches:
                try:
                    value = match.group(rule.secret_group)
                    start, end = match.span(rule.secret_group)
                except (IndexError, TypeError):
                    continue
                allowlisted, _ = rule.is_allowlisted(
                    value, f"{record.root_path}!/{record.nested_path}", match.group(0),
                )
                if allowlisted:
                    continue
                if rule.entropy is not None and shannon_entropy(value) < float(rule.entropy):
                    continue
                local_context = text[max(0, match.start() - 120):min(len(text), match.end() + 120)]
                location = f"{record.location}@{start}:{end}"
                candidates.append(Candidate(
                    value=value, credential_type=rule.name, rule_id=rule.id,
                    root_path=record.root_path, nested_path=record.nested_path, location=location,
                    context=" ".join(filter(None, (record.context, local_context))), carrier_type=record.carrier_type,
                    structural_evidence=[], trace=trace, base_score=rule.base_score,
                    require_positive_context=rule.require_positive_context, source_provider=rule.provider_id,
                    source_location_key=f"{record.root_path}\0{record.nested_path}\0{location}",
                    field_relation=record.relationship or ("field" if record.field_path else None),
                    rule_version=rule.provider_version, rule_metadata={
                        **rule.metadata(),
                        "matched_rule_sources": [{"provider_id": rule.provider_id, "rule_id": rule.id}],
                    },
                ))
        return candidates


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())
