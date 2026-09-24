from __future__ import annotations

from divide.config import load_config
from divide.models import Candidate, CarrierRecord, RecoveryTrace
from divide.rules import CandidateExtractor
from divide.rulesets import CompositeRuleProvider, ConfigRuleProvider, GitHubTokenChecksum, GitleaksRuleProvider
from divide.verification import Verifier


def candidate(value: str, *, context: str = "api_key", path: str = "/project/src/config.py") -> Candidate:
    return Candidate(
        value=value, credential_type="Synthetic", rule_id="synthetic", root_path=path,
        nested_path="config.py", location="line:1@0:20", context=context, carrier_type="structured",
        structural_evidence=[], trace=RecoveryTrace(["R1"], confidence=.9), base_score=.70,
        source_location_key=f"{path}:1", field_relation="field-sibling",
        rule_metadata={"min_length": 3, "max_length": 512, "prefixes": [], "provider_id": "test"},
    )


def test_github_checksum_alphabet_and_zero_padding_vectors() -> None:
    plugin = GitHubTokenChecksum("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
    assert plugin.suffix("") == "000000"
    assert plugin.suffix("123456789") == "3jddVG"
    valid, _ = plugin.validate("1234567893jddVG", format_version="checksum-v1")
    assert valid


def test_exact_placeholder_is_hard_rejected_but_substring_is_not() -> None:
    config = load_config()
    verifier = Verifier(config)
    exact = candidate("YOUR_API_KEY")
    substring = candidate("prefix_your_api_key_suffix")
    exact_result = verifier.verify([exact])
    substring_result = verifier.verify([substring])
    assert not exact_result.findings
    assert exact_result.decisions[0].stage == "hard:placeholder"
    assert substring_result.decisions[0].stage != "hard:placeholder"


def test_test_directory_is_only_soft_negative_evidence() -> None:
    config = load_config()
    config.detection.minimum_score = .1
    result = Verifier(config).verify([candidate("synthetic_nonplaceholder_value", path="/project/tests/fixture.py")])
    assert result.findings
    assert any("soft negative" in item for item in result.findings[0].contextual_evidence)


def test_candidate_dedup_is_value_plus_source_location() -> None:
    config = load_config()
    verifier = Verifier(config)
    first = candidate("synthetic_value_123", path="/project/a.py")
    duplicate_same_location = candidate("synthetic_value_123", path="/project/a.py")
    other_location = candidate("synthetic_value_123", path="/project/b.py")
    result = verifier.verify([first, duplicate_same_location, other_location])
    assert len(result.findings) == 2
    assert result.duplicates == 1


def test_rule_audit_preserves_providers_conflicts_hash_and_license() -> None:
    config = load_config()
    audit = CompositeRuleProvider([ConfigRuleProvider(config), GitleaksRuleProvider()]).audit()
    assert audit["content_sha256"]
    assert {provider["provider_id"] for provider in audit["providers"]} == {"divide-core", "gitleaks"}
    gitleaks = next(provider for provider in audit["providers"] if provider["provider_id"] == "gitleaks")
    assert gitleaks["version"] == "v8.30.1"
    assert gitleaks["license"] == "MIT"
    assert gitleaks["snapshot_scope"] == "full-upstream"
    assert gitleaks["upstream_commit"] == "83d9cd684c87d95d656c1458ef04895a7f1cbd8e"
    assert all(gitleaks["integrity"].values())


def test_gitleaks_allowlist_entropy_keywords_and_secret_group_convert() -> None:
    extractor = CandidateExtractor(load_config())
    record = CarrierRecord("R1", "/root", "fixture.txt", "text", "line:1", "ghp_" + "0" * 36)
    findings = extractor.extract(record.text, record, RecoveryTrace(["R1"]))
    assert all(item.source_provider != "gitleaks" for item in findings)
