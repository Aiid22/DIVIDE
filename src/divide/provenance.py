from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any


def stable_hash(value: Any) -> str:
    if is_dataclass(value):
        value = asdict(value)
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_revision(root: Path) -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, check=True,
            capture_output=True, text=True, timeout=2,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def experiment_provenance(
    *, project_root: Path, config: Any, rule_hash: str, capabilities: list[dict[str, Any]], seed: int,
    model_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "code_revision": _git_revision(project_root),
        "config_sha256": stable_hash(config),
        "rule_library_sha256": rule_hash,
        "capability_matrix_sha256": stable_hash(capabilities),
        "random_seed": seed,
        "model_profile": model_profile or {"status": "model_unavailable"},
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "implementation": platform.python_implementation(),
            "locale": os.environ.get("LC_ALL") or os.environ.get("LANG") or "unknown",
        },
    }
