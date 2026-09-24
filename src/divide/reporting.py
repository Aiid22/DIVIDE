"""Redacted JSON report serialization for schema 2.0."""

from __future__ import annotations

import json
from pathlib import Path

from divide.models import ScanReport


def write_json_report(report: ScanReport, output: Path, show_secrets: bool = False) -> None:
    """Write a redacted schema-2.0 scan report to disk."""
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(report.to_dict(show_secrets=show_secrets), ensure_ascii=False, indent=2)
    output.write_text(serialized + "\n", encoding="utf-8")


def write_json_data(value: object, output: Path) -> None:
    """Write an arbitrary JSON payload to disk."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

