"""Protocols decoupling the pipeline from concrete handlers, rule providers, and checksum validators."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol, runtime_checkable

from divide.models import (
    CarrierObject,
    CapabilityStatus,
)


@dataclass(frozen=True, slots=True)
class Capability:
    """Adapter capability tier reported to users and provenance."""
    handler_id: str
    formats: tuple[str, ...]
    status: CapabilityStatus
    backend: str
    reason: str = ""
    external_requirements: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable view."""
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
    """Outcome of a type probe for one carrier object."""
    matched: bool
    detected_type: str = "unknown"
    mime: str | None = None
    confidence: float = 0.0
    structural_valid: bool = False
    evidence: list[str] = field(default_factory=list)


@runtime_checkable
class CarrierHandler(Protocol):
    """Protocol every carrier adapter implements."""
    handler_id: str
    priority: int

    def capability(self) -> Capability:
        """Return this handler's capability tier."""
        ...

    def probe(self, obj: CarrierObject) -> ProbeResult:
        """Probe the payload type; return a ProbeResult."""
        ...

    def validate_structure(self, obj: CarrierObject, probe: ProbeResult) -> tuple[bool, str]:
        """Return True when the payload parses as this carrier."""
        ...

    def extract_records(self, obj: CarrierObject, context: Any) -> Iterable[CarrierRecord]:
        """Yield carrier records extracted from the payload."""
        ...

    def enumerate_children(self, obj: CarrierObject, context: Any) -> Iterable[CarrierObject]:
        """Yield nested objects for recursive traversal."""
        ...


@runtime_checkable
class RuleProvider(Protocol):
    """Protocol for versioned rule sources."""
    provider_id: str
    version: str

    def load(self) -> list[Any]:
        """Return rule mappings from this source."""
        ...

    def audit(self) -> dict[str, Any]:
        """Return origin, version, and content-hash metadata."""
        ...


@runtime_checkable
class ChecksumValidator(Protocol):
    """Protocol for offline credential checksums."""
    validator_id: str

    def supports(self, credential_type: str, format_version: str | None = None) -> bool:
        """Return True when this validator handles the format."""
        ...

    def validate(self, value: str, *, format_version: str | None = None) -> tuple[bool, str]:
        """Return ``(valid, reason)`` from the offline checksum."""
        ...
