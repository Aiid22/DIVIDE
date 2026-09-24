"""DIVIDE: our auditable carrier-aware secret-discovery research artifact."""

from .pipeline import DividePipeline
from .interfaces import CarrierHandler, ChecksumValidator, RuleProvider
from .models import (
    Candidate, CarrierObject, CarrierRecord, ExperimentResult, Finding,
    RelatedGroup, VerificationDecision,
)

__all__ = [
    "DividePipeline", "CarrierHandler", "RuleProvider", "ChecksumValidator",
    "CarrierObject", "CarrierRecord", "RelatedGroup", "Candidate",
    "VerificationDecision", "Finding", "ExperimentResult",
]
__version__ = "0.3.0"
