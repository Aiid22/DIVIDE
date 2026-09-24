"""Versioned rule sources: packaged defaults plus a hash-pinned Gitleaks snapshot."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from importlib.resources import files
from pathlib import Path
from typing import Any

import regex as regex_engine

from divide.config import AppConfig
from divide.provenance import stable_hash


def translate_re2(pattern: str) -> str:
    """Small, explicit RE2-to-Python compatibility layer for the pinned corpus."""
    return pattern.replace(r"\z", r"\Z")


class ConfigRuleProvider:
    """Rules defined in ``default_rules.yaml`` and user overrides."""
    provider_id = "divide-core"
    version = "2026.09.1"

    def __init__(self, config: AppConfig):
        self.config = config

    def load(self) -> list[dict[str, Any]]:
        """Return credential rules from configuration."""
        output = []
        for rule in self.config.credential_rules:
            item = dict(rule)
            item.update({
                "provider_id": self.provider_id, "provider_version": self.version,
                "source_url": "docs/RULE_SOURCES.md", "license": "project license",
                "priority": 100, "format_version": item.get("format_version"),
            })
            output.append(item)
        return output

    def audit(self) -> dict[str, Any]:
        """Return source metadata and content hash."""
        rules = self.load()
        vectors_path = Path(str(files("divide.verification.data").joinpath("core_test_vectors.json")))
        errors = []
        for rule in rules:
            try:
                regex_engine.compile(translate_re2(rule["pattern"]))
            except (re.error, regex_engine.error) as exc:
                errors.append({"rule_id": rule.get("id"), "error": str(exc)})
        return {
            "provider_id": self.provider_id, "version": self.version, "rules": len(rules),
            "content_sha256": stable_hash(rules), "compile_errors": errors, "license": "project license",
            "test_vectors_sha256": hashlib.sha256(vectors_path.read_bytes()).hexdigest(),
        }


class GitleaksRuleProvider:
    """Hash-pinned Gitleaks v8.30.1 snapshot loader."""
    provider_id = "gitleaks"
    version = "v8.30.1"

    def __init__(self, snapshot_path: Path | None = None):
        self.snapshot_path = snapshot_path or Path(str(files("divide.verification.data").joinpath("gitleaks_v8.30.1.toml")))

    def load(self) -> list[dict[str, Any]]:
        """Return rules translated from the pinned snapshot."""
        with self.snapshot_path.open("rb") as handle:
            data = tomllib.load(handle)
        global_allowlist = data.get("allowlist") or {}
        converted = []
        for raw in data.get("rules", []):
            if "regex" not in raw:
                continue  # path-only rules (e.g. pkcs12-file) flag file names, not content
            allowlists = [global_allowlist, *raw.get("allowlists", [])] if global_allowlist else raw.get("allowlists", [])
            stopwords = list(raw.get("stopwords", []))
            for block in allowlists:
                stopwords.extend(block.get("stopwords", []))
            rule_id = str(raw["id"])
            item = {
                "id": f"gitleaks:{raw['id']}", "name": raw.get("description", raw["id"]),
                "pattern": raw["regex"], "secret_group": int(raw.get("secretGroup", 0)),
                "min_length": 1, "max_length": 65536, "base_score": .58,
                "entropy": raw.get("entropy"), "keywords": raw.get("keywords", []),
                "allowlists": allowlists, "stopwords": list(dict.fromkeys(stopwords)),
                "provider_id": self.provider_id, "provider_version": self.version,
                "source_url": "https://github.com/gitleaks/gitleaks/blob/v8.30.1/config/gitleaks.toml",
                "license": "MIT", "priority": 50, "format_version": None,
            }
            if rule_id.startswith("github-"):
                item.update({"checksum": "github-crc32-base62-six", "format_version": "checksum-v1"})
            converted.append(item)
        return converted

    def audit(self) -> dict[str, Any]:
        """Return snapshot origin, hash, and license metadata."""
        raw = self.snapshot_path.read_bytes()
        manifest_path = self.snapshot_path.with_name("snapshot_manifest.json")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        actual_hash = hashlib.sha256(raw).hexdigest()
        license_path = self.snapshot_path.with_name("LICENSE.gitleaks")
        license_hash = hashlib.sha256(license_path.read_bytes()).hexdigest()
        rules = self.load()
        errors = []
        for rule in rules:
            try:
                regex_engine.compile(translate_re2(rule["pattern"]))
            except (re.error, regex_engine.error) as exc:
                errors.append({"rule_id": rule["id"], "error": str(exc)})
        return {
            "provider_id": self.provider_id, "version": self.version, "rules": len(rules),
            "content_sha256": actual_hash, "compile_errors": errors,
            "license": "MIT", "snapshot_scope": manifest.get("snapshot_scope"),
            "upstream_commit": manifest.get("upstream_ref"),
            "integrity": {
                "content_matches_manifest": actual_hash == manifest.get("content_sha256"),
                "license_matches_manifest": license_hash == manifest.get("license_sha256"),
            },
        }


class CompositeRuleProvider:
    """Merges child providers and resolves rule conflicts."""
    provider_id = "divide-composite"
    version = "2.0"

    def __init__(self, providers: list[Any]):
        self.providers = providers

    def load(self) -> list[dict[str, Any]]:
        """Return rules from all children, conflict-resolved."""
        rules = [rule for provider in self.providers for rule in provider.load()]
        return sorted(rules, key=lambda item: (-int(item.get("priority", 0)), item["id"]))

    def audit(self) -> dict[str, Any]:
        """Return merged audit metadata from all children."""
        reports = [provider.audit() for provider in self.providers]
        rules = self.load()
        by_pattern: dict[str, list[dict[str, str]]] = {}
        for rule in rules:
            by_pattern.setdefault(rule["pattern"], []).append({
                "rule_id": rule["id"], "provider_id": rule["provider_id"],
            })
        conflicts = [items for items in by_pattern.values() if len({item["provider_id"] for item in items}) > 1]
        return {
            "provider_id": self.provider_id, "version": self.version, "providers": reports,
            "rule_count": len(rules), "conflicts": conflicts, "content_sha256": stable_hash(rules),
        }
