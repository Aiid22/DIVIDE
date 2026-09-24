from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from PIL import Image

from divide.config import load_config
from divide.localization import ArtifactLocalizer
from divide.models import CarrierRecord, RelatedGroup
from divide.recovery.planner import DeterministicPlanExecutor


def write_zip(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in members.items():
            archive.writestr(name, value)


def test_archive_path_traversal_is_not_written_to_target(tmp_path: Path) -> None:
    archive = tmp_path / "traversal.zip"
    write_zip(archive, {"../../escape.txt": b"harmless", "inside.txt": b"harmless"})
    ArtifactLocalizer(load_config()).scan(archive)
    assert not (tmp_path.parent / "escape.txt").exists()


def test_compression_ratio_limit_yields_warning(tmp_path: Path) -> None:
    archive = tmp_path / "ratio.zip"
    write_zip(archive, {"large.txt": b"A" * 200_000})
    config = load_config()
    config.limits.max_compression_ratio = 2
    result = ArtifactLocalizer(config).scan(archive)
    assert any(item.code == "compression_ratio_limit" for item in result.warnings)


def test_malformed_archive_is_isolated_as_warning(tmp_path: Path) -> None:
    malformed = tmp_path / "broken.zip"
    malformed.write_bytes(b"PK\x03\x04not-a-real-archive")
    result = ArtifactLocalizer(load_config()).scan(malformed)
    assert result.warnings


def test_plan_rejects_output_budget_and_illegal_substitution() -> None:
    config = load_config()
    config.limits.max_plan_output = 4
    executor = DeterministicPlanExecutor(config)
    records = {"R1": CarrierRecord("R1", "/root", "x", "image", "ocr", "00000")}
    group = RelatedGroup("G:1", "ocr-line", ["R1"], ["ocr"], .8)
    plan = {"version": "1.0", "group_id": "G:1", "record_ids": ["R1"], "operations": [
        {"op": "substitute", "input": "R1", "positions": {"0": "X"}, "output": "v1"}], "output_ref": "v1"}
    with pytest.raises(ValueError, match="outside the OCR confusion set"):
        executor.execute(plan, group, records)


def test_xml_entity_payload_does_not_expand(tmp_path: Path) -> None:
    payload = tmp_path / "entity.xml"
    payload.write_text('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>', encoding="utf-8")
    result = ArtifactLocalizer(load_config()).scan(payload)
    assert result.warnings
    assert all("root:" not in record.text for record in result.records)


def test_corrupt_sqlite_isolated_as_warning(tmp_path: Path) -> None:
    payload = tmp_path / "broken.db"
    payload.write_bytes(b"SQLite format 3\x00" + b"not-a-database" * 8)
    result = ArtifactLocalizer(load_config()).scan(payload)
    assert any(item.code == "handler_error" for item in result.warnings)


def test_image_pixel_budget_skips_ocr(tmp_path: Path) -> None:
    payload = tmp_path / "large.png"
    Image.new("RGB", (20, 20), "white").save(payload)
    config = load_config()
    config.limits.max_image_pixels = 100
    result = ArtifactLocalizer(config).scan(payload)
    assert any(item.code == "image_pixel_limit" for item in result.warnings)
