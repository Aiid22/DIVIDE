from __future__ import annotations

from divide.config import load_config
from divide.models import CarrierRecord
from divide.recovery import recover_fragments, recover_record


def record(identifier: str, text: str, *, carrier_type: str = "text", group: str = "g") -> CarrierRecord:
    return CarrierRecord(
        id=identifier,
        root_path="/synthetic/root",
        nested_path="fixture.txt",
        carrier_type=carrier_type,
        location=identifier,
        text=text,
        context="api_key",
        metadata={"group": group},
    )


def test_bounded_base64_recovery() -> None:
    config = load_config()
    encoded = record("R1", "QUtJQTEyMzQ1Njc4OTBBQkNERUY=")

    recovered = recover_record(encoded, config)

    assert any(item.text == "AKIA1234567890ABCDEF" for item in recovered)
    assert any(step.operation == "decode" for item in recovered for step in item.trace.steps)


def test_fragment_reassembly_preserves_source_ids() -> None:
    records = [record("R1", "ghp_"), record("R2", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")]

    recovered = recover_fragments(records)

    match = next(item for _, item in recovered if item.text.startswith("ghp_"))
    assert match.trace.source_record_ids == ["R1", "R2"]


def test_ocr_character_alternatives_are_bounded() -> None:
    config = load_config()
    config.limits.max_ocr_variants = 8
    ocr = record("R1", "AK1A1234567890ABCDEF", carrier_type="image")

    recovered = recover_record(ocr, config)

    assert any(item.text == "AKIA1234567890ABCDEF" for item in recovered)
    assert len(recovered) <= config.limits.max_ocr_variants + 1

