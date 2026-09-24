"""DIVIDE: our auditable carrier-aware secret-discovery research artifact."""

from .pipeline import DividePipeline
from .interfaces import BaselineAdapter, CarrierHandler, ChecksumValidator, RecoveryPlanner, RuleProvider
from .models import (
    Candidate, CarrierObject, CarrierRecord, ExperimentResult, Finding, RecoveredSequence,
    RecoveryPlan, RelatedGroup, VerificationDecision,
)

__all__ = [
    "DividePipeline", "CarrierHandler", "RuleProvider", "ChecksumValidator", "RecoveryPlanner",
    "BaselineAdapter", "CarrierObject", "CarrierRecord", "RelatedGroup", "RecoveredSequence",
    "RecoveryPlan", "Candidate", "VerificationDecision", "Finding", "ExperimentResult",
]
__version__ = "0.3.0"

