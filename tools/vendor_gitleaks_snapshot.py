"""Vendor a reviewed, hash-pinned Gitleaks snapshot for an empirical run.

This utility is intentionally not invoked by DIVIDE. A maintainer must obtain
the expected SHA-256 through an independent review channel and pass it here;
the script refuses mutable or hash-mismatched content.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import urllib.request
from pathlib import Path


VERSION = "v8.30.1"
UPSTREAM_COMMIT = "83d9cd684c87d95d656c1458ef04895a7f1cbd8e"
CONFIG_URL = f"https://raw.githubusercontent.com/gitleaks/gitleaks/{VERSION}/config/gitleaks.toml"
LICENSE_URL = f"https://raw.githubusercontent.com/gitleaks/gitleaks/{VERSION}/LICENSE"


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "DIVIDE-snapshot-vendor/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-config-sha256", required=True)
    parser.add_argument("--expected-license-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    config = fetch(CONFIG_URL)
    license_text = fetch(LICENSE_URL)
    config_hash = hashlib.sha256(config).hexdigest()
    license_hash = hashlib.sha256(license_text).hexdigest()
    if config_hash != args.expected_config_sha256.lower():
        raise SystemExit(f"config hash mismatch: {config_hash}")
    if license_hash != args.expected_license_sha256.lower():
        raise SystemExit(f"license hash mismatch: {license_hash}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / f"gitleaks_{VERSION}.toml").write_bytes(config)
    (args.output_dir / "LICENSE.gitleaks").write_bytes(license_text)
    manifest = {
        "provider": "gitleaks", "version": VERSION, "upstream_ref": UPSTREAM_COMMIT,
        "source_url": CONFIG_URL, "snapshot_scope": "full-upstream",
        "content_sha256": config_hash, "license": "MIT", "license_sha256": license_hash,
        "reproduction_status": "VENDORED_UNTESTED",
        "engineering_assumption": (
            "EA-006 selects this upstream version as a reproducible proxy; "
            "we do not identify the exact rule commit in the paper."
        ),
    }
    (args.output_dir / "snapshot_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
    )


if __name__ == "__main__":
    main()
