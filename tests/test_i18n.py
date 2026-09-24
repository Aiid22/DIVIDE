from __future__ import annotations

import pytest
from typer.testing import CliRunner

from divide.cli import app
from divide.config import load_config
from divide.i18n import OutputLanguage, message, parse_language


def test_default_output_language_is_english() -> None:
    assert load_config().output.language == "en"
    assert parse_language("en") is OutputLanguage.ENGLISH


def test_chinese_alias_and_message_are_available() -> None:
    assert parse_language("zh-CN") is OutputLanguage.CHINESE
    rendered = message("scan_summary", "zh", objects=2, findings=1, warnings=0)
    assert rendered == "已扫描 2 个对象；发现 1 项；产生 0 条警告。"


def test_unsupported_language_is_rejected() -> None:
    with pytest.raises(ValueError, match="expected 'en' or 'zh'"):
        parse_language("fr")


def test_capabilities_json_defaults_to_english() -> None:
    result = CliRunner().invoke(app, ["capabilities", "--json"])
    assert result.exit_code == 0
    assert '"display_language": "en"' in result.stdout


def test_capabilities_cli_switches_status_labels_to_chinese() -> None:
    result = CliRunner().invoke(app, ["capabilities", "--language", "zh"])
    assert result.exit_code == 0
    assert any(label in result.stdout for label in ("完整", "部分", "回退", "不可用"))
