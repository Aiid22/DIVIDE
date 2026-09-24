from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator


MANIFEST_SCHEMA: dict[str, Any] = {
    "type": "object", "additionalProperties": False,
    "required": ["schema_version", "dataset_id", "root", "artifacts"],
    "properties": {
        "schema_version": {"const": "1.0"}, "dataset_id": {"type": "string", "minLength": 1},
        "root": {"type": "string", "minLength": 1},
        "artifacts": {"type": "array", "items": {"type": "object", "additionalProperties": False,
            "required": ["artifact_id", "project_id", "relative_path", "sha256", "mime", "secrets"],
            "properties": {
                "artifact_id": {"type": "string"}, "project_id": {"type": "string"},
                "relative_path": {"type": "string"}, "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "mime": {"type": "string"}, "secrets": {"type": "array", "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["fingerprint", "location"],
                    "properties": {"fingerprint": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                                   "location": {"type": "string"}, "credential_type": {"type": "string"}},
                }},
            },
        }},
    },
}


@dataclass(frozen=True, slots=True)
class SecretAnnotation:
    fingerprint: str
    location: str
    credential_type: str = "unknown"


@dataclass(frozen=True, slots=True)
class ManifestArtifact:
    artifact_id: str
    project_id: str
    relative_path: str
    sha256: str
    mime: str
    secrets: tuple[SecretAnnotation, ...] = ()


@dataclass(frozen=True, slots=True)
class DatasetManifest:
    schema_version: str
    dataset_id: str
    root: Path
    artifacts: tuple[ManifestArtifact, ...]
    source_path: Path
    metadata: dict[str, Any] = field(default_factory=dict)

    def resolve_artifact(self, artifact: ManifestArtifact) -> Path:
        relative = PurePosixPath(artifact.relative_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"unsafe artifact relative_path: {artifact.relative_path}")
        resolved_root = self.root.resolve()
        target = resolved_root.joinpath(*relative.parts).resolve()
        if target != resolved_root and resolved_root not in target.parents:
            raise ValueError(f"artifact escapes dataset root: {artifact.relative_path}")
        return target


def load_manifest(path: Path) -> DatasetManifest:
    value = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator(MANIFEST_SCHEMA).validate(value)
    root = Path(value["root"])
    if not root.is_absolute():
        root = path.parent / root
    artifacts = tuple(ManifestArtifact(
        artifact_id=item["artifact_id"], project_id=item["project_id"], relative_path=item["relative_path"],
        sha256=item["sha256"], mime=item["mime"],
        secrets=tuple(SecretAnnotation(**secret) for secret in item["secrets"]),
    ) for item in value["artifacts"])
    return DatasetManifest("1.0", value["dataset_id"], root, artifacts, path)
