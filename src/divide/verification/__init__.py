"""Secret verification (paper Sec. 2.3): rule sources, checksums, and the verifier."""

from .checksums import ChecksumRegistry, GitHubTokenChecksum
from .providers import CompositeRuleProvider, ConfigRuleProvider, GitleaksRuleProvider, translate_re2
from .rules import CredentialRule, shannon_entropy
from .verifier import VerificationResult, Verifier

__all__ = [
    "ChecksumRegistry", "GitHubTokenChecksum",
    "CompositeRuleProvider", "ConfigRuleProvider", "GitleaksRuleProvider", "translate_re2",
    "CredentialRule", "shannon_entropy",
    "VerificationResult", "Verifier",
]

