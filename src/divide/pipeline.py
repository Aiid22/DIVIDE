from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from divide.config import AppConfig
from divide.i18n import parse_language
from divide.localization import ArtifactLocalizer
from divide.models import Candidate, RecoveryTrace, ScanReport, ScanWarning
from divide.provenance import experiment_provenance
from divide.recovery import LLMPlanner, RecoveredText, recover_fragments, recover_record
from divide.rules import CandidateExtractor
from divide.verification import Verifier


@dataclass(frozen=True, slots=True)
class AblationProfile:
    name: str = "full"
    media_extraction: bool = True
    recovery: bool = True
    post_filter: bool = True


ABLATION_PROFILES = {
    "full": AblationProfile(),
    "no-media": AblationProfile("no-media", media_extraction=False),
    "no-recovery": AblationProfile("no-recovery", recovery=False),
    "no-post-filter": AblationProfile("no-post-filter", post_filter=False),
}


class DividePipeline:
    def __init__(self, config: AppConfig):
        self.config = config
        self.localizer = ArtifactLocalizer(config)
        self.extractor = CandidateExtractor(config)
        self.verifier = Verifier(config)
        self.planner = LLMPlanner(config)

    def scan(
        self, target: Path, timeout_seconds: float | None = None, *, ablation_profile: str = "full",
    ) -> ScanReport:
        if ablation_profile not in ABLATION_PROFILES:
            raise ValueError(f"unknown ablation profile: {ablation_profile}")
        profile = ABLATION_PROFILES[ablation_profile]
        self.extractor.runtime_errors.clear()
        deadline = time.monotonic() + timeout_seconds if timeout_seconds else None
        disabled = frozenset() if profile.media_extraction else frozenset({"image", "audio", "video"})
        localized = self.localizer.scan(
            target, timeout_seconds=timeout_seconds, disabled_carrier_types=disabled,
        )
        records = localized.records
        if not profile.media_extraction:
            records = [record for record in records if record.carrier_type not in {"image", "pdf-page", "audio", "video"}]
        candidates = []
        for record in records:
            if deadline and time.monotonic() > deadline:
                localized.warnings.append(ScanWarning("scan_timeout", record.nested_path, "Timeout reached during recovery."))
                break
            recovered_items = recover_record(record, self.config) if profile.recovery else [
                RecoveredText(record.text, RecoveryTrace([record.id], [], record.extraction_confidence))
            ]
            for recovered in recovered_items:
                candidates.extend(self.extractor.extract(recovered.text, record, recovered.trace))
        if profile.recovery and (not deadline or time.monotonic() <= deadline):
            for synthetic, recovered in recover_fragments(records):
                if deadline and time.monotonic() > deadline:
                    localized.warnings.append(ScanWarning("scan_timeout", synthetic.nested_path, "Timeout during related-group recovery."))
                    break
                candidates.extend(self.extractor.extract(recovered.text, synthetic, recovered.trace))
            planned = self.planner.recover(records)
            localized.warnings.extend(planned.warnings)
            for synthetic, recovered in planned.recovered:
                candidates.extend(self.extractor.extract(recovered.text, synthetic, recovered.trace))
        for error in self.extractor.compile_errors:
            localized.warnings.append(ScanWarning("rule_compile_error", str(error["rule_id"]), error["error"]))
        for error in self.extractor.runtime_errors:
            localized.warnings.append(ScanWarning("rule_runtime_error", str(error["rule_id"]), error["error"]))
        raw_candidate_count = len(candidates)
        candidates, candidate_duplicates = _deduplicate_candidates(candidates)
        verified = self.verifier.verify(candidates, post_filter=profile.post_filter)
        capabilities = self.localizer.capabilities()
        project_root = Path(__file__).resolve().parents[2]
        provenance = experiment_provenance(
            project_root=project_root, config=self.config.summary(), rule_hash=self.extractor.rule_hash,
            capabilities=capabilities, seed=self.config.experiment.random_seed, model_profile=self.planner.status(),
        )
        return ScanReport(
            target=str(target.resolve()) if target.exists() else str(target), findings=verified.findings,
            warnings=localized.warnings, scanned_objects=localized.scanned_objects,
            carrier_records=len(localized.records), raw_candidates=raw_candidate_count,
            duplicate_candidates=candidate_duplicates + verified.duplicates, config_summary=self.config.summary(),
            provenance=provenance, capabilities=capabilities, candidate_decisions=verified.decisions,
            ablation_profile=profile.name, engineering_assumptions=self.config.engineering_assumptions,
            display_language=parse_language(self.config.output.language).value,
        )


def _deduplicate_candidates(candidates: list[Candidate]) -> tuple[list[Candidate], int]:
    merged: dict[tuple[str, str], Candidate] = {}
    for candidate in candidates:
        location = candidate.source_location_key or "\0".join((candidate.root_path, candidate.nested_path, candidate.location))
        key = (candidate.value, location)
        previous = merged.get(key)
        if previous is None:
            merged[key] = candidate
            continue
        sources = previous.rule_metadata.setdefault("matched_rule_sources", [])
        for source in candidate.rule_metadata.get("matched_rule_sources", []):
            if source not in sources:
                sources.append(source)
        prefer_new = previous.source_provider != "divide-core" and candidate.source_provider == "divide-core"
        if prefer_new:
            candidate.rule_metadata["matched_rule_sources"] = sources
            merged[key] = candidate
    return list(merged.values()), len(candidates) - len(merged)
