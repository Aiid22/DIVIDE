"""Credential rule data model shared by recovery extraction and verification.

A :class:`CredentialRule` is the single source of truth for how a provider
credential looks: pattern, length bounds, prefixes, charset, checksum, and
provenance metadata.  Rules are loaded from versioned sources (see
``providers.py``) and consumed both to extract candidates during recovery and
to enforce format constraints during verification (paper Sec. 2.2-2.3).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

import regex as regex_engine

from .providers import translate_re2


@dataclass(slots=True)
class CredentialRule:
    """Declarative description of one credential format."""

    id: str
    name: str
    pattern: str
    min_length: int = 1
    max_length: int = 65536
    prefixes: list[str] = field(default_factory=list)
    charset: str | None = None
    delimiter_pattern: str | None = None
    checksum: str | None = None
    format_version: str | None = None
    secret_group: int = 0
    base_score: float = .5
    require_positive_context: bool = False
    entropy: float | None = None
    keywords: list[str] = field(default_factory=list)
    allowlists: list[dict[str, Any]] = field(default_factory=list)
    stopwords: list[str] = field(default_factory=list)
    provider_id: str = "divide-core"
    provider_version: str = "unknown"
    source_url: str = ""
    license: str = ""
    priority: int = 0
    regex: Any = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.regex = regex_engine.compile(translate_re2(self.pattern))

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "CredentialRule":
        """Build a rule from a mapping, ignoring unknown keys."""
        allowed = {field.name for field in cls.__dataclass_fields__.values() if field.init}  # type: ignore[attr-defined]
        return cls(**{key: item for key, item in value.items() if key in allowed})

    def is_allowlisted(self, value: str, path: str, match_text: str = "") -> tuple[bool, str]:
        """Return ``(True, reason)`` when the value or path is explicitly allowed."""
        lowered = value.casefold()
        for stopword in self.stopwords:
            if stopword.casefold() in lowered:
                return True, f"Gitleaks stopword matched: {stopword}"
        for block in self.allowlists:
            target_name = block.get("regexTarget", "secret")
            target = {"secret": value, "match": match_text, "line": match_text, "path": path}.get(target_name, value)
            for expression in block.get("regexes", []):
                if regex_engine.search(translate_re2(expression), target):
                    return True, f"rule allowlist regex matched: {expression}"
            for expression in block.get("paths", []):
                if regex_engine.search(translate_re2(expression), path):
                    return True, f"rule allowlist path matched: {expression}"
        return False, ""

    def metadata(self) -> dict[str, Any]:
        """Provenance and constraint fields attached to every candidate match."""
        return {
            "min_length": self.min_length, "max_length": self.max_length, "prefixes": self.prefixes,
            "charset": self.charset, "delimiter_pattern": self.delimiter_pattern, "checksum": self.checksum,
            "format_version": self.format_version, "entropy": self.entropy, "provider_id": self.provider_id,
            "provider_version": self.provider_version, "source_url": self.source_url, "license": self.license,
        }


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character; 0.0 for empty input."""
    if not value:
        return 0.0
    counts = {character: value.count(character) for character in set(value)}
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())
