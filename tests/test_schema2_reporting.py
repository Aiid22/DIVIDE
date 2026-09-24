from __future__ import annotations

from divide.models import ScanReport
from importlib.resources import files
import json
from jsonschema import Draft202012Validator


def test_schema2_defaults_to_redacted_and_exposes_audit_sections() -> None:
    report = ScanReport("/target", [], [], 0, 0, 0, 0, {})
    value = report.to_dict()
    assert value["schema_version"] == "2.0"
    assert value["display_language"] == "en"
    assert "provenance" in value
    assert "capabilities" in value
    assert "candidate_decisions" in value
    assert value["ablation_profile"] == "full"
    assert "engineering_assumptions" in value
    schema = json.loads(files("divide").joinpath("schemas/report-2.0.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(value)
