from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal


CapabilityStatus = Literal["full", "partial", "fallback", "unavailable"]


@dataclass(slots=True)
class CarrierObject:
    """A byte object in the recursive carrier tree."""

    id: str
    root_path: str
    nested_path: str
    name: str
    data: bytes = field(repr=False)
    depth: int = 0
    parent_id: str | None = None
    declared_mime: str | None = None
    detected_mime: str | None = None
    detected_type: str = "unknown"
    content_sha256: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CarrierRecord:
    id: str
    root_path: str
    nested_path: str
    carrier_type: str
    location: str
    text: str
    context: str = ""
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)
    parent_object_id: str | None = None
    mime: str | None = None
    detected_type: str | None = None
    encoding: str | None = None
    byte_offset: int | None = None
    page: int | None = None
    field_path: str | None = None
    ocr_bbox: tuple[int, int, int, int] | None = None
    relationship: str | None = None
    content_sha256: str = ""
    extraction_confidence: float = 1.0
    encoding_evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RecoveryStep:
    operation: str
    detail: str
    input_sha256: str | None = None
    output_sha256: str | None = None
    depth: int = 0
    encoding: str | None = None
    confidence: float = 1.0


@dataclass(slots=True)
class RecoveryTrace:
    source_record_ids: list[str]
    steps: list[RecoveryStep] = field(default_factory=list)
    confidence: float = 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_record_ids": self.source_record_ids,
            "steps": [asdict(step) for step in self.steps],
            "confidence": round(self.confidence, 4),
        }


@dataclass(slots=True)
class Candidate:
    value: str
    credential_type: str
    rule_id: str
    root_path: str
    nested_path: str
    location: str
    context: str
    carrier_type: str
    structural_evidence: list[str]
    trace: RecoveryTrace
    base_score: float = 0.5
    require_positive_context: bool = False
    source_provider: str = "divide-core"
    source_location_key: str = ""
    field_relation: str | None = None
    rule_version: str | None = None
    rule_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RelatedGroup:
    id: str
    relation: str
    record_ids: list[str]
    ordering: list[str]
    confidence: float
    rationale: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RecoveredSequence:
    value: str
    source_record_ids: list[str]
    trace: RecoveryTrace
    unique: bool = True
    alternatives_considered: int = 1


@dataclass(slots=True)
class RecoveryPlan:
    version: str
    group_id: str
    record_ids: list[str]
    operations: list[dict[str, Any]]
    output_ref: str
    planner: str = "deterministic"


@dataclass(slots=True)
class VerificationDecision:
    candidate_fingerprint: str
    accepted: bool
    stage: str
    score: float
    reasons: list[str] = field(default_factory=list)
    rule_id: str | None = None


@dataclass(slots=True)
class Finding:
    value: str
    credential_type: str
    confidence: float
    fingerprint: str
    root_path: str
    sources: list[dict[str, Any]]
    structural_evidence: list[str]
    contextual_evidence: list[str]
    recovery_trace: RecoveryTrace
    rule_id: str = ""
    rule_provider: str = "divide-core"
    decision: VerificationDecision | None = None

    @staticmethod
    def mask(value: str) -> str:
        if "-----BEGIN" in value:
            first = value.splitlines()[0] if value.splitlines() else "PRIVATE KEY"
            return f"{first} ... [REDACTED]"
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}{'*' * min(12, len(value) - 8)}{value[-4:]}"

    def to_dict(self, show_secrets: bool = False) -> dict[str, Any]:
        return {
            "credential_type": self.credential_type,
            "confidence": round(self.confidence, 4),
            "fingerprint": self.fingerprint,
            "value": self.value if show_secrets else self.mask(self.value),
            "redacted": not show_secrets,
            "root_path": self.root_path,
            "sources": self.sources,
            "structural_evidence": self.structural_evidence,
            "contextual_evidence": self.contextual_evidence,
            "recovery_trace": self.recovery_trace.to_dict(),
            "rule_id": self.rule_id,
            "rule_provider": self.rule_provider,
            "decision": asdict(self.decision) if self.decision else None,
        }


@dataclass(slots=True)
class ScanWarning:
    code: str
    path: str
    message: str


@dataclass(slots=True)
class ScanReport:
    target: str
    findings: list[Finding]
    warnings: list[ScanWarning]
    scanned_objects: int
    carrier_records: int
    raw_candidates: int
    duplicate_candidates: int
    config_summary: dict[str, Any]
    schema_version: str = "2.0"
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    provenance: dict[str, Any] = field(default_factory=dict)
    capabilities: list[dict[str, Any]] = field(default_factory=list)
    candidate_decisions: list[VerificationDecision] = field(default_factory=list)
    ablation_profile: str = "full"
    engineering_assumptions: list[str] = field(default_factory=list)
    display_language: Literal["en", "zh"] = "en"

    def to_dict(self, show_secrets: bool = False) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "display_language": self.display_language,
            "generated_at": self.generated_at,
            "target": self.target,
            "config": self.config_summary,
            "provenance": self.provenance,
            "capabilities": self.capabilities,
            "candidate_decisions": [asdict(item) for item in self.candidate_decisions],
            "ablation_profile": self.ablation_profile,
            "engineering_assumptions": self.engineering_assumptions,
            "summary": {
                "scanned_objects": self.scanned_objects,
                "carrier_records": self.carrier_records,
                "raw_candidates": self.raw_candidates,
                "findings": len(self.findings),
                "duplicates_merged": self.duplicate_candidates,
                "warnings": len(self.warnings),
            },
            "findings": [item.to_dict(show_secrets) for item in self.findings],
            "warnings": [asdict(item) for item in self.warnings],
        }


@dataclass(slots=True)
class ExperimentResult:
    profile: str
    unit: Literal["occurrence", "project_unique"]
    true_positive: int
    false_positive: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    fdr: float
    latency_seconds: float
    provenance: dict[str, Any] = field(default_factory=dict)

