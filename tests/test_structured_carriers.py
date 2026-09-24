from __future__ import annotations

import sqlite3
import zipfile

import fitz
from docx import Document
from openpyxl import Workbook
from pptx import Presentation

from divide.config import load_config
from divide.localization import ArtifactLocalizer


SYNTHETIC_VALUE = "Z9qV7mN2pR8sT4uW6xY0aB3cD5eF7gH"


def localizer() -> ArtifactLocalizer:
    config = load_config()
    config.ocr.enabled = False
    return ArtifactLocalizer(config)


def test_docx_text_is_localized(tmp_path) -> None:
    path = tmp_path / "sample.docx"
    document = Document()
    document.add_paragraph(f"api_key={SYNTHETIC_VALUE}")
    document.save(path)

    result = localizer().scan(path)

    assert any(SYNTHETIC_VALUE in record.text for record in result.records)


def test_xlsx_cells_are_localized(tmp_path) -> None:
    path = tmp_path / "sample.xlsx"
    workbook = Workbook()
    sheet = workbook.active
    sheet["A1"] = "api_key"
    sheet["B1"] = SYNTHETIC_VALUE
    workbook.save(path)

    result = localizer().scan(path)

    assert any(record.text == SYNTHETIC_VALUE and record.location.endswith("B1") for record in result.records)


def test_pptx_shapes_are_localized(tmp_path) -> None:
    path = tmp_path / "sample.pptx"
    presentation = Presentation()
    slide = presentation.slides.add_slide(presentation.slide_layouts[1])
    slide.shapes[1].text = f"api_key={SYNTHETIC_VALUE}"
    presentation.save(path)

    result = localizer().scan(path)

    assert any(SYNTHETIC_VALUE in record.text for record in result.records)


def test_pdf_text_layer_is_localized(tmp_path) -> None:
    path = tmp_path / "sample.pdf"
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), f"api_key={SYNTHETIC_VALUE}")
    document.save(path)
    document.close()

    result = localizer().scan(path)

    assert any(SYNTHETIC_VALUE in record.text for record in result.records)


def test_sqlite_is_opened_read_only(tmp_path) -> None:
    path = tmp_path / "sample.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE settings (name TEXT, value TEXT)")
    connection.execute("INSERT INTO settings VALUES (?, ?)", ("api_key", SYNTHETIC_VALUE))
    connection.commit()
    connection.close()

    result = localizer().scan(path)

    assert any(record.text == SYNTHETIC_VALUE and "settings" in record.location for record in result.records)


def test_archive_member_limit_is_reported(tmp_path) -> None:
    path = tmp_path / "many.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("one.txt", "one")
        archive.writestr("two.txt", "two")
    config = load_config()
    config.ocr.enabled = False
    config.limits.max_archive_members = 1

    result = ArtifactLocalizer(config).scan(path)

    assert any(warning.code == "archive_member_limit" for warning in result.warnings)


def test_corrupt_pdf_becomes_warning(tmp_path) -> None:
    path = tmp_path / "broken.pdf"
    path.write_bytes(b"%PDF-not-a-real-document")

    result = localizer().scan(path)

    assert any(warning.code == "handler_error" for warning in result.warnings)

