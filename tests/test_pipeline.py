from __future__ import annotations

from divide.config import load_config
from divide.pipeline import DividePipeline
from divide.rulesets import GitHubTokenChecksum


def test_pipeline_finds_recursively_encoded_synthetic_value(tmp_path) -> None:
    target = tmp_path / "encoded.env"
    target.write_text("AWS_ACCESS_KEY_ID=QUtJQTEyMzQ1Njc4OTBBQkNERUY=\n", encoding="utf-8")
    config = load_config()
    config.ocr.enabled = False

    report = DividePipeline(config).scan(target)

    assert any(finding.credential_type == "AWS Access Key ID" for finding in report.findings)
    output = report.to_dict(show_secrets=False)
    assert output["findings"][0]["redacted"] is True
    assert output["findings"][0]["value"] != "AKIA1234567890ABCDEF"


def test_pipeline_reassembles_synthetic_json_fragments(tmp_path) -> None:
    target = tmp_path / "fragments.json"
    payload = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123"
    token = payload + GitHubTokenChecksum().suffix(payload)
    target.write_text(
        '{"token_part_1":"' + token[:18] + '","token_part_2":"' + token[18:] + '"}',
        encoding="utf-8",
    )
    config = load_config()
    config.ocr.enabled = False

    report = DividePipeline(config).scan(target)

    assert any(finding.credential_type == "GitHub Token" for finding in report.findings)

