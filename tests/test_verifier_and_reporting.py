from __future__ import annotations

from divide.config import load_config
from divide.models import Candidate, RecoveryTrace, ScanReport
from divide.verification import Verifier


def candidate(value: str, context: str = "aws_access_key") -> Candidate:
    return Candidate(
        value=value,
        credential_type="AWS Access Key ID",
        rule_id="aws_access_key_id",
        root_path="/synthetic/project",
        nested_path="config.env",
        location="line:1@18:38",
        context=context,
        carrier_type="text",
        structural_evidence=["matched rule aws_access_key_id"],
        trace=RecoveryTrace(["R1"], confidence=1.0),
        base_score=0.62,
    )


def test_placeholder_is_rejected() -> None:
    config = load_config()
    item = candidate("your_api_key")

    result = Verifier(config).verify([item])

    assert not result.findings
    assert result.rejected == 1


def test_same_value_at_distinct_source_locations_is_not_candidate_deduplicated() -> None:
    config = load_config()
    first = candidate("AKIA1234567890ABCDEF")
    second = candidate("AKIA1234567890ABCDEF")
    second.location = "line:9@18:38"
    second.trace = RecoveryTrace(["R9"], confidence=0.9)

    result = Verifier(config).verify([first, second])

    assert len(result.findings) == 2
    assert result.duplicates == 0


def test_report_redacts_by_default() -> None:
    config = load_config()
    finding = Verifier(config).verify([candidate("AKIA1234567890ABCDEF")]).findings[0]
    report = ScanReport(
        target="/synthetic/project",
        findings=[finding],
        warnings=[],
        scanned_objects=1,
        carrier_records=1,
        raw_candidates=1,
        duplicate_candidates=0,
        config_summary={},
    )

    redacted = report.to_dict()["findings"][0]
    revealed = report.to_dict(show_secrets=True)["findings"][0]

    assert redacted["redacted"] is True
    assert redacted["value"] != "AKIA1234567890ABCDEF"
    assert revealed["value"] == "AKIA1234567890ABCDEF"

