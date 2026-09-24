from __future__ import annotations

import gzip
import io
import zipfile

import pytest

from divide.config import load_config
from divide.localization import ArtifactLocalizer
from divide.localization.detector import detect_kind
from divide.localization.localizer import _State


@pytest.mark.parametrize(
    ("payload", "name", "expected"),
    [
        (b"%PDF-1.7\n", "disguised.bin", "pdf"),
        (b"SQLite format 3\x00" + b"\x00" * 20, "data.bin", "sqlite"),
        (b"\x89PNG\r\n\x1a\n" + b"\x00" * 20, "image.bin", "image"),
        (gzip.compress(b"hello"), "payload.bin", "gzip"),
    ],
)
def test_content_signature_precedes_extension(payload: bytes, name: str, expected: str) -> None:
    assert detect_kind(payload, name) == expected


def test_nested_zip_is_traversed_without_extraction(tmp_path) -> None:
    secret = "AKIA1234567890ABCDEF"
    inner_buffer = io.BytesIO()
    with zipfile.ZipFile(inner_buffer, "w") as inner:
        inner.writestr("config.env", f"AWS_ACCESS_KEY_ID={secret}\n")
    outer_path = tmp_path / "bundle.dat"
    with zipfile.ZipFile(outer_path, "w") as outer:
        outer.writestr("nested.zip", inner_buffer.getvalue())

    config = load_config()
    config.ocr.enabled = False
    result = ArtifactLocalizer(config).scan(outer_path)

    assert any(secret in record.text for record in result.records)
    assert any("nested.zip!/config.env" in record.nested_path for record in result.records)
    child = next(obj for obj in result.objects if obj.nested_path.endswith("config.env"))
    assert child.parent_id
    record = next(record for record in result.records if secret in record.text)
    assert record.mime
    assert record.detected_type == "text"
    assert record.content_sha256
    assert record.extraction_confidence > 0
    assert record.metadata["handler_id"] == "structured-text"


def test_json_fields_preserve_context(tmp_path) -> None:
    target = tmp_path / "config.json"
    target.write_text('{"service":{"api_key":"Z9qV7mN2pR8sT4uW6xY0"}}', encoding="utf-8")
    config = load_config()
    config.ocr.enabled = False

    result = ArtifactLocalizer(config).scan(target)

    assert any(record.context == "api_key" for record in result.records)
    assert any(record.metadata.get("group", "").endswith("$.service") for record in result.records)


def test_oversized_root_becomes_warning(tmp_path) -> None:
    target = tmp_path / "large.bin"
    target.write_bytes(b"x" * 32)
    config = load_config()
    config.limits.max_object_size = 8

    result = ArtifactLocalizer(config).scan(target)

    assert not result.records
    assert result.warnings[0].code == "object_too_large"


def test_encrypted_archive_member_is_skipped(monkeypatch) -> None:
    class EncryptedMember:
        filename = "secret.txt"
        flag_bits = 0x1
        file_size = 10

        @staticmethod
        def is_dir() -> bool:
            return False

    class FakeArchive:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        @staticmethod
        def infolist():
            return [EncryptedMember()]

    monkeypatch.setattr(zipfile, "ZipFile", lambda *_args, **_kwargs: FakeArchive())
    scanner = ArtifactLocalizer(load_config())
    state = _State()

    scanner._handle_archive(b"ignored", "zip", "/root", "bundle.zip", 0, state)

    assert state.result.warnings[0].code == "encrypted_archive_member"

