from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml


@dataclass(slots=True)
class Limits:
    max_depth: int = 5
    max_object_size: int = 50 * 1024 * 1024
    max_expanded_size: int = 250 * 1024 * 1024
    max_archive_members: int = 5_000
    max_sqlite_rows: int = 10_000
    max_ocr_pages: int = 100
    max_decode_depth: int = 3
    max_decode_output: int = 1024 * 1024
    max_ocr_variants: int = 32
    max_llm_groups: int = 20
    max_compression_ratio: float = 200.0
    max_image_pixels: int = 80_000_000
    max_media_frames: int = 32
    max_sqlite_vm_steps: int = 2_000_000
    max_handler_seconds: float = 15.0
    max_recovery_beam: int = 64
    max_plan_operations: int = 16
    max_plan_output: int = 1024 * 1024
    max_rule_matches: int = 10_000


@dataclass(slots=True)
class OCRSettings:
    enabled: bool = True
    language: str = "eng"
    min_confidence: float = 35.0


@dataclass(slots=True)
class LLMSettings:
    base_url: str | None = None
    model: str | None = None
    api_key_env: str = "DIVIDE_LLM_API_KEY"
    allow_remote: bool = False
    timeout_seconds: float = 30.0
    planner: str = "null"
    profile: str = "qwen3-32b-awq-vllm"
    prompt_version: str = "divide-recovery-plan-v1"


@dataclass(slots=True)
class DetectionSettings:
    minimum_score: float = 0.65
    minimum_generic_entropy: float = 3.2
    show_secrets: bool = False
    carrier_weight: float = 0.08
    field_relation_weight: float = 0.10
    recovery_weight: float = 0.20
    positive_context_weight: float = 0.06
    negative_context_weight: float = 0.06
    max_regex_seconds: float = 0.25


@dataclass(slots=True)
class ExperimentSettings:
    random_seed: int = 20250301
    raw_unit: str = "occurrence"
    unique_unit: str = "project_unique"
    status: str = "UNVALIDATED"


@dataclass(slots=True)
class AppConfig:
    limits: Limits = field(default_factory=Limits)
    ocr: OCRSettings = field(default_factory=OCRSettings)
    llm: LLMSettings = field(default_factory=LLMSettings)
    detection: DetectionSettings = field(default_factory=DetectionSettings)
    experiment: ExperimentSettings = field(default_factory=ExperimentSettings)
    credential_rules: list[dict[str, Any]] = field(default_factory=list)
    positive_context: list[str] = field(default_factory=list)
    negative_context: list[str] = field(default_factory=list)
    hard_placeholders: list[str] = field(default_factory=list)
    engineering_assumptions: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        return {
            "limits": asdict(self.limits),
            "ocr": asdict(self.ocr),
            "llm": {
                "enabled": bool(self.llm.base_url and self.llm.model),
                "model": self.llm.model,
                "allow_remote": self.llm.allow_remote,
            },
            "detection": asdict(self.detection),
            "experiment": asdict(self.experiment),
            "credential_rule_count": len(self.credential_rules),
            "engineering_assumptions": self.engineering_assumptions,
        }


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def default_config_path() -> Path:
    return Path(str(files("divide").joinpath("default_rules.yaml")))


def load_config(path: Path | None = None) -> AppConfig:
    with default_config_path().open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if path:
        with path.open("r", encoding="utf-8") as handle:
            data = _deep_merge(data, yaml.safe_load(handle) or {})
    return AppConfig(
        limits=Limits(**data.get("limits", {})),
        ocr=OCRSettings(**data.get("ocr", {})),
        llm=LLMSettings(**data.get("llm", {})),
        detection=DetectionSettings(**data.get("detection", {})),
        experiment=ExperimentSettings(**data.get("experiment", {})),
        credential_rules=data.get("credential_rules", []),
        positive_context=data.get("positive_context", []),
        negative_context=data.get("negative_context", []),
        hard_placeholders=data.get("hard_placeholders", []),
        engineering_assumptions=data.get("engineering_assumptions", []),
    )

