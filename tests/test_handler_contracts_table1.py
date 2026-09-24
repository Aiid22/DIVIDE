from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from divide.localization.detector import detect
from divide.localization.registry import default_registry
from divide.models import CarrierObject


def zip_bytes(names: list[str], payload: bytes = b"synthetic harmless content") -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name in names:
            archive.writestr(name, payload)
    return output.getvalue()


def tar_bytes() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        info = tarfile.TarInfo("fixture.txt")
        value = b"synthetic harmless content"
        info.size = len(value)
        archive.addfile(info, io.BytesIO(value))
    return output.getvalue()


def iso_bytes() -> bytes:
    value = bytearray(0x8010)
    value[0x8001:0x8006] = b"CD001"
    return bytes(value)


CASES = [
    ("source.py", b"value = 'synthetic'", "text"), ("fixture.txt", b"plain text", "text"),
    ("fixture.json", b'{"part_1":"abc"}', "json"), ("fixture.csv", b"key,value\na,b\n", "csv"),
    ("fixture.xml", b"<root><value>x</value></root>", "xml"), ("fixture.yaml", b"value: x\n", "yaml"),
    ("fixture.svg", b"<svg><text>x</text></svg>", "xml"), ("fixture.pem", b"SYNTHETIC PEM TEXT", "text"),
    ("fixture.zip", zip_bytes(["fixture.txt"]), "zip"), ("fixture.tar", tar_bytes(), "tar"),
    ("fixture.gz", gzip.compress(b"synthetic"), "gzip"), ("fixture.7z", b"7z\xbc\xaf\x27\x1c" + b"x" * 16, "7z"),
    ("fixture.rar", b"Rar!\x1a\x07\x01\x00" + b"x" * 16, "rar"),
    ("fixture.jar", zip_bytes(["META-INF/MANIFEST.MF"]), "jar"),
    ("fixture.apk", zip_bytes(["AndroidManifest.xml", "classes.dex"]), "apk"),
    ("fixture.rpm", b"\xed\xab\xee\xdb" + b"x" * 128, "rpm"), ("fixture.iso", iso_bytes(), "iso"),
    ("fixture.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"x" * 32, "doc"),
    ("fixture.docx", zip_bytes(["word/document.xml"]), "docx"),
    ("fixture.xls", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"x" * 32, "xls"),
    ("fixture.xlsx", zip_bytes(["xl/workbook.xml"]), "xlsx"),
    ("fixture.ppt", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"x" * 32, "ppt"),
    ("fixture.pptx", zip_bytes(["ppt/presentation.xml"]), "pptx"),
    ("fixture.odt", zip_bytes(["mimetype"], b"application/vnd.oasis.opendocument.text"), "odf"),
    ("fixture.epub", zip_bytes(["META-INF/container.xml"]), "epub"),
    ("fixture.rtf", b"{\\rtf1 harmless}", "rtf"),
    ("fixture.msg", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"x" * 32, "outlook-msg"),
    ("fixture.elf", b"\x7fELF" + b"x" * 32, "elf"), ("fixture.exe", b"MZ" + b"x" * 32, "pe"),
    ("fixture.macho", b"\xfe\xed\xfa\xcf" + b"x" * 32, "mach-o"),
    ("fixture.wasm", b"\x00asm\x01\x00\x00\x00", "wasm"),
    ("fixture.ttf", b"\x00\x01\x00\x00" + b"x" * 32, "font"),
    ("fixture.mp3", b"ID3" + b"x" * 32, "audio"), ("fixture.mp4", b"synthetic media", "video"),
    ("fixture.png", b"\x89PNG\r\n\x1a\n" + b"x" * 32, "image"),
    ("fixture.jpg", b"\xff\xd8\xff" + b"x" * 32, "image"), ("fixture.gif", b"GIF89a" + b"x" * 32, "image"),
    ("fixture.tiff", b"II*\x00" + b"x" * 32, "image"),
    ("fixture.webp", b"RIFFxxxxWEBP" + b"x" * 32, "image"),
    ("fixture.ico", b"\x00\x00\x01\x00" + b"x" * 32, "image"),
    ("fixture.psd", b"8BPS" + b"x" * 32, "image"),
    ("fixture.pdf", b"%PDF-1.7\n%%EOF", "pdf"),
    ("fixture.sqlite", b"SQLite format 3\x00" + b"x" * 64, "sqlite"),
    ("fixture.mo", b"\xde\x12\x04\x95" + b"x" * 32, "gettext"),
    ("fixture.bin", b"\x00\xff\x01\x02", "binary"),
]


@pytest.mark.parametrize(("name", "data", "expected"), CASES)
def test_table1_real_type_probe_and_handler_contract(name: str, data: bytes, expected: str) -> None:
    detection = detect(data, name)
    assert detection.kind == expected
    obj = CarrierObject("O1", "/root", name, name, data, detected_type=detection.kind)
    handler, probe = default_registry().select(obj)
    assert probe.matched
    valid, reason = handler.validate_structure(obj, probe)
    assert valid
    assert reason
    assert handler.capability().status in {"full", "partial", "fallback", "unavailable"}
    assert callable(handler.extract_records)
    assert callable(handler.enumerate_children)


def test_capability_matrix_covers_every_table1_category() -> None:
    formats = {value for row in default_registry().capabilities() for value in row["formats"]}
    required = {
        "ZIP", "TAR", "GZIP", "7z", "RAR", "JAR", "APK", "RPM", "ISO", "DOC", "DOCX", "XLS", "XLSX",
        "PPT", "PPTX", "ODF", "EPUB", "RTF", "Outlook MSG", "ELF", "PE", "Mach-O", "WASM", "fonts",
        "audio", "video", "PNG", "JPEG", "GIF", "TIFF", "WebP", "ICO", "PSD", "PDF", "SQLite",
        "GNU MO/Gettext", "unknown binary fallback",
    }
    assert required <= formats
