from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol, runtime_checkable

from divide.models import (
    CarrierObject,
    CapabilityStatus,
)


@dataclass(frozen=True, slots=True)
class Capability:
    handler_id: str
    formats: tuple[str, ...]
    status: CapabilityStatus
    backend: str
    reason: str = ""
    external_requirements: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "handler_id": self.handler_id,
            "formats": list(self.formats),
            "status": self.status,
            "backend": self.backend,
            "reason": self.reason,
            "external_requirements": list(self.external_requirements),
        }


@dataclass(slots=True)
class ProbeResult:
    matched: bool
    detected_type: str = "unknown"
    mime: str | None = None
    confidence: float = 0.0
    structural_valid: bool = False
    evidence: list[str] = field(default_factory=list)


@runtime_checkable
class CarrierHandler(Protocol):
    handler_id: str
    priority: int

    def capability(self) -> Capability: ...

    def probe(self, obj: CarrierObject) -> ProbeResult: ...

    def validate_structure(self, obj: CarrierObject, probe: ProbeResult) -> tuple[bool, str]: ...

    def extract_records(self, obj: CarrierObject, context: Any) -> Iterable[CarrierRecord]: ...

    def enumerate_children(self, obj: CarrierObject, context: Any) -> Iterable[CarrierObject]: ...


@runtime_checkable
class RuleProvider(Protocol):
    provider_id: str
    version: str

    def load(self) -> list[Any]: ...

    def audit(self) -> dict[str, Any]: ...


@runtime_checkable
class ChecksumValidator(Protocol):
    validator_id: str

    def supports(self, credential_type: str, format_version: str | None = None) -> bool: ...

    def validate(self, value: str, *, format_version: str | None = None) -> tuple[bool, str]: ...
