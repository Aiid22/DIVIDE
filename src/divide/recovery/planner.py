from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from importlib.resources import files
from typing import Any
from urllib.parse import urlparse

import httpx
from jsonschema import Draft202012Validator

from divide.config import AppConfig
from divide.models import CarrierRecord, RecoveryStep, RecoveryTrace, RelatedGroup, ScanWarning

from .decoder import RecoveredText, decode_exact
from .fragments import build_related_groups


PROMPT_VERSION = "divide-recovery-plan-v1"
SYSTEM_PROMPT = (
    files("divide.profiles").joinpath("recovery_prompt_v1.txt").read_text(encoding="utf-8").strip()
)

PLAN_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://divide.local/schema/recovery-plan-v1.json",
    "type": "object", "additionalProperties": False,
    "required": ["plans"],
    "properties": {"plans": {"type": "array", "maxItems": 1, "items": {
        "type": "object", "additionalProperties": False,
        "required": ["version", "group_id", "record_ids", "operations", "output_ref"],
        "properties": {
            "version": {"const": "1.0"}, "group_id": {"type": "string"},
            "record_ids": {"type": "array", "minItems": 1, "maxItems": 16, "uniqueItems": True,
                           "items": {"type": "string", "pattern": "^[A-Za-z]:?[A-Za-z0-9:+.-]+$"}},
            "operations": {"type": "array", "minItems": 1, "maxItems": 16, "items": {"oneOf": [
                {"type": "object", "additionalProperties": False, "required": ["op", "inputs", "output"],
                 "properties": {"op": {"const": "concat"}, "inputs": {"type": "array", "minItems": 1,
                 "maxItems": 16, "uniqueItems": True, "items": {"type": "string"}},
                 "separator": {"type": "string", "maxLength": 8}, "output": {"type": "string"}}},
                {"type": "object", "additionalProperties": False, "required": ["op", "input", "encoding", "output"],
                 "properties": {"op": {"const": "decode"}, "input": {"type": "string"},
                 "encoding": {"enum": ["base64", "base64url", "hex", "url"]}, "output": {"type": "string"}}},
                {"type": "object", "additionalProperties": False, "required": ["op", "input", "positions", "output"],
                 "properties": {"op": {"const": "substitute"}, "input": {"type": "string"},
                 "positions": {"type": "object", "maxProperties": 16,
                               "additionalProperties": {"type": "string", "minLength": 1, "maxLength": 1}},
                 "output": {"type": "string"}}},
            ]}},
            "output_ref": {"type": "string"},
        },
    }}},
}


@dataclass(slots=True)
class PlannerResult:
    recovered: list[tuple[CarrierRecord, RecoveredText]]
    warnings: list[ScanWarning]


class DeterministicPlanExecutor:
    allowed_substitutions = {
        "0": {"O"}, "O": {"0"}, "1": {"l", "I"}, "l": {"1", "I"}, "I": {"1", "l"},
    }

    def __init__(self, config: AppConfig):
        self.config = config
        self.validator = Draft202012Validator(PLAN_SCHEMA)

    def execute(
        self, plan_value: dict[str, Any], group: RelatedGroup, records: dict[str, CarrierRecord],
    ) -> tuple[CarrierRecord, RecoveredText]:
        wrapper = {"plans": [plan_value]}
        errors = sorted(self.validator.iter_errors(wrapper), key=lambda item: list(item.path))
        if errors:
            raise ValueError("invalid recovery plan schema: " + errors[0].message)
        if plan_value["group_id"] != group.id:
            raise ValueError("plan group_id does not match the supplied group")
        record_ids = plan_value["record_ids"]
        if any(identifier not in group.record_ids or identifier not in records for identifier in record_ids):
            raise ValueError("plan references a record outside the related group")
        if len(plan_value["operations"]) > self.config.limits.max_plan_operations:
            raise ValueError("plan operation budget exceeded")
        values: dict[str, str] = {identifier: records[identifier].text.strip() for identifier in record_ids}
        steps: list[RecoveryStep] = []
        for depth, operation in enumerate(plan_value["operations"], 1):
            name = operation["op"]
            output = operation["output"]
            if output in values:
                raise ValueError("operation output reference is not single-assignment")
            if name == "concat":
                inputs = operation["inputs"]
                if any(reference not in values for reference in inputs):
                    raise ValueError("concat references an unavailable input")
                before = "\0".join(values[reference] for reference in inputs)
                value = operation.get("separator", "").join(values[reference] for reference in inputs)
            elif name == "decode":
                reference = operation["input"]
                if reference not in values:
                    raise ValueError("decode references an unavailable input")
                before = values[reference]
                value = decode_exact(before, operation["encoding"], self.config.limits.max_plan_output)
            elif name == "substitute":
                reference = operation["input"]
                if reference not in values:
                    raise ValueError("substitute references an unavailable input")
                before = values[reference]
                characters = list(before)
                for raw_index, replacement in operation["positions"].items():
                    try:
                        index = int(raw_index)
                    except ValueError as exc:
                        raise ValueError("substitution index must be an integer string") from exc
                    if not 0 <= index < len(characters):
                        raise ValueError("substitution index is out of bounds")
                    if replacement not in self.allowed_substitutions.get(characters[index], set()):
                        raise ValueError("substitution is outside the OCR confusion set")
                    characters[index] = replacement
                value = "".join(characters)
            else:  # schema validation should make this unreachable
                raise ValueError(f"disallowed operation: {name}")
            if len(value.encode("utf-8")) > self.config.limits.max_plan_output:
                raise ValueError("plan output budget exceeded")
            values[output] = value
            steps.append(RecoveryStep(
                f"plan:{name}", f"validated deterministic operation {depth}",
                hashlib.sha256(before.encode()).hexdigest(), hashlib.sha256(value.encode()).hexdigest(),
                depth, operation.get("encoding"), .82,
            ))
        output_ref = plan_value["output_ref"]
        if output_ref not in values or not values[output_ref]:
            raise ValueError("plan output_ref is unavailable or empty")
        sources = [records[identifier] for identifier in record_ids]
        value = values[output_ref]
        confidence = max(.35, min(item.extraction_confidence for item in sources) - .12)
        synthetic = CarrierRecord(
            id=f"P:{group.id}", root_path=sources[0].root_path, nested_path=sources[0].nested_path,
            carrier_type="recovery-plan", location=" + ".join(item.location for item in sources), text=value,
            context=" ".join(item.context for item in sources), confidence=confidence,
            metadata={"group": group.id, "planner": plan_value.get("planner", "external")},
            parent_object_id=sources[0].parent_object_id, detected_type="recovery-plan",
            relationship=group.relation, content_sha256=hashlib.sha256(value.encode()).hexdigest(),
            extraction_confidence=confidence,
        )
        return synthetic, RecoveredText(value, RecoveryTrace(record_ids, steps, confidence))


def _profile_artifact_hashes() -> dict[str, str]:
    profile_path = files("divide.profiles").joinpath("qwen3-32b-awq-vllm.yaml")
    prompt_path = files("divide.profiles").joinpath("recovery_prompt_v1.txt")
    return {
        "profile_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
        "prompt_sha256": hashlib.sha256(prompt_path.read_bytes()).hexdigest(),
    }


class NullRecoveryPlanner:
    planner_id = "null"

    def status(self) -> dict[str, Any]:
        return {
            "planner_id": self.planner_id, "status": "model_unavailable",
            "reason": "model execution disabled by default", "profile": "qwen3-32b-awq-vllm",
            "prompt_version": PROMPT_VERSION, **_profile_artifact_hashes(),
        }

    def recover(self, records: list[CarrierRecord]) -> PlannerResult:
        return PlannerResult([], [])


class OpenAIRecoveryPlanner:
    planner_id = "openai-compatible-vllm"

    def __init__(self, config: AppConfig):
        self.config = config
        self.executor = DeterministicPlanExecutor(config)

    def status(self) -> dict[str, Any]:
        enabled = bool(self.config.llm.base_url and self.config.llm.model and self.config.llm.planner != "null")
        return {
            "planner_id": self.planner_id, "status": "available" if enabled else "model_unavailable",
            "profile": self.config.llm.profile, "model": self.config.llm.model,
            "prompt_version": PROMPT_VERSION, **_profile_artifact_hashes(),
        }

    def recover(self, records: list[CarrierRecord]) -> PlannerResult:
        if self.status()["status"] != "available":
            return PlannerResult([], [])
        endpoint = self.config.llm.base_url or ""
        hostname = urlparse(endpoint).hostname
        if hostname not in {"localhost", "127.0.0.1", "::1"} and not self.config.llm.allow_remote:
            return PlannerResult([], [ScanWarning("remote_llm_blocked", endpoint, "Remote planner requires --allow-remote-llm.")])
        groups, by_id = build_related_groups(records)
        recovered: list[tuple[CarrierRecord, RecoveredText]] = []
        warnings: list[ScanWarning] = []
        for group in groups[: self.config.limits.max_llm_groups]:
            try:
                response = self._request(group, by_id)
                Draft202012Validator(PLAN_SCHEMA).validate(response)
                plans = response["plans"]
                if len(plans) == 1:
                    recovered.append(self.executor.execute(plans[0], group, by_id))
            except Exception as exc:
                path = by_id[group.record_ids[0]].nested_path
                warnings.append(ScanWarning("recovery_plan_rejected", path, str(exc)))
        return PlannerResult(recovered, warnings)

    def _request(self, group: RelatedGroup, records: dict[str, CarrierRecord]) -> dict[str, Any]:
        supplied = [{
            "id": identifier, "text": records[identifier].text[:512], "context": records[identifier].context[:256],
            "location": records[identifier].location,
        } for identifier in group.record_ids[:16]]
        payload = {
            "model": self.config.llm.model, "temperature": 0,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": json.dumps({
                "schema_version": "1.0", "group_id": group.id, "relation": group.relation, "records": supplied,
            }, ensure_ascii=False)}],
            "response_format": {"type": "json_object"},
        }
        response = httpx.post(
            f"{(self.config.llm.base_url or '').rstrip('/')}/chat/completions", json=payload,
            headers={"Authorization": f"Bearer {os.getenv(self.config.llm.api_key_env, 'local-not-required')}"},
            timeout=self.config.llm.timeout_seconds,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"].strip()
        if content.startswith("```"):
            content = content.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
        return json.loads(content)


class LLMPlanner:
    """Compatibility facade selecting a disabled or OpenAI/vLLM planner."""

    def __init__(self, config: AppConfig):
        self.delegate = OpenAIRecoveryPlanner(config) if config.llm.planner != "null" else NullRecoveryPlanner()

    @property
    def enabled(self) -> bool:
        return self.delegate.status()["status"] == "available"

    def status(self) -> dict[str, Any]:
        return self.delegate.status()

    def recover(self, records: list[CarrierRecord]) -> PlannerResult:
        return self.delegate.recover(records)
