from __future__ import annotations

import base64

import pytest

from divide.config import load_config
from divide.models import CarrierRecord, RelatedGroup
from divide.recovery.decoder import RecoveryConstraint, constrained_ocr_beam, decode_exact, recover_record
from divide.recovery.encoding import infer_encoding
from divide.recovery.fragments import build_related_groups, recover_fragments
from divide.recovery.planner import DeterministicPlanExecutor
from divide.localization.localizer import reconstruct_ocr_line


def record(identifier: str, text: str, field: str) -> CarrierRecord:
    return CarrierRecord(
        identifier, "/root", "fixture.json", "structured", field, text,
        metadata={"group": "fixture.json:$.credential", "field": field},
        parent_object_id="O1", field_path=f"$.credential.{field}", relationship="field-sibling",
    )


def test_encoding_inference_records_bom_and_printability() -> None:
    result = infer_encoding("harmless".encode("utf-16"))
    assert result.encoding.startswith("utf-16")
    assert result.evidence["bom"]
    assert result.evidence["printable_ratio"] == 1.0


def test_standard_urlsafe_and_multilayer_decoding_are_bounded() -> None:
    config = load_config()
    raw = "glpat-SYNTHETICONLYVALUE1234"
    once = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
    twice = base64.b64encode(once.encode()).decode()
    recovered = recover_record(record("R1", twice, "part_1"), config)
    assert any(item.text == raw for item in recovered)
    assert all(len(item.trace.steps) <= config.limits.max_decode_depth for item in recovered)
    assert all(step.input_sha256 and step.output_sha256 for item in recovered for step in item.trace.steps if step.operation == "decode")


def test_decode_output_budget_rejects_expansion() -> None:
    value = base64.b64encode(b"A" * 256).decode()
    with pytest.raises(ValueError, match="output exceeds"):
        decode_exact(value, "base64", 32)


def test_equation_one_beam_applies_constraints_during_generation() -> None:
    constraint = RecoveryConstraint("synthetic", ("ghp_",), 12, 12, r"[A-Za-z0-9_]{12}")
    output = constrained_ocr_beam("ghp_00000000", [constraint], beam_width=4)
    assert len(output) <= 4
    assert all(value.startswith("ghp_") and len(value) == 12 for value, _penalty, _rule in output)


def test_ocr_geometry_joins_split_glyphs_and_preserves_real_spaces() -> None:
    words = [
        (0, "ghp_", 90.0, {"left": 0, "top": 4, "width": 20, "height": 10}),
        (21, "SYN", 90.0, {"left": 21, "top": 4, "width": 15, "height": 10}),
        (48, "context", 90.0, {"left": 48, "top": 4, "width": 30, "height": 10}),
    ]
    text, bbox = reconstruct_ocr_line(words)
    assert text == "ghp_SYN context"
    assert bbox == (0, 4, 78, 10)


def test_related_group_uses_parent_field_relation_and_deterministic_order() -> None:
    records = [record("R2", "BBBB", "token_part_2"), record("R1", "AAAA", "token_part_1"), record("R3", "CCCC", "token_part_3")]
    groups, _ = build_related_groups(records)
    assert len(groups) == 1
    assert groups[0].record_ids == ["R1", "R2", "R3"]
    recovered = recover_fragments(records)
    assert recovered[0][1].text == "AAAABBBBCCCC"


def test_recovery_plan_rejects_unknown_reference_and_arbitrary_operation() -> None:
    config = load_config()
    executor = DeterministicPlanExecutor(config)
    records = {"R1": record("R1", "AAAA", "part_1"), "R2": record("R2", "BBBBBBBB", "part_2")}
    group = RelatedGroup("G:1", "field-sibling", ["R1", "R2"], ["part_1", "part_2"], .9)
    unknown = {"version": "1.0", "group_id": "G:1", "record_ids": ["R9"], "operations": [
        {"op": "concat", "inputs": ["R9"], "output": "v1"}], "output_ref": "v1"}
    with pytest.raises(ValueError, match="outside"):
        executor.execute(unknown, group, records)
    malicious = {"version": "1.0", "group_id": "G:1", "record_ids": ["R1"], "operations": [
        {"op": "shell", "input": "R1", "output": "v1"}], "output_ref": "v1"}
    with pytest.raises(ValueError, match="schema"):
        executor.execute(malicious, group, records)


def test_valid_plan_has_one_deterministic_output() -> None:
    executor = DeterministicPlanExecutor(load_config())
    records = {"R1": record("R1", "AAAA", "part_1"), "R2": record("R2", "BBBBBBBB", "part_2")}
    group = RelatedGroup("G:1", "field-sibling", ["R1", "R2"], ["part_1", "part_2"], .9)
    plan = {"version": "1.0", "group_id": "G:1", "record_ids": ["R1", "R2"], "operations": [
        {"op": "concat", "inputs": ["R1", "R2"], "separator": "", "output": "v1"}], "output_ref": "v1"}
    synthetic, recovered = executor.execute(plan, group, records)
    assert recovered.text == "AAAABBBBBBBB"
    assert synthetic.content_sha256
