from __future__ import annotations

from divide.models import Candidate


class UnconfiguredBaseline:
    executable: str | None = None

    def __init__(self, adapter_id: str, model_profile: str | None = None):
        self.adapter_id = adapter_id
        self.model_profile = model_profile

    def capability(self) -> dict[str, object]:
        return {
            "adapter_id": self.adapter_id, "status": "unavailable", "configured": False,
            "model_profile": self.model_profile,
            "reason": "baseline is an interface-only adapter; no executable/model was configured",
        }

    def scan(self, target: str) -> list[Candidate]:
        raise RuntimeError(f"{self.adapter_id} baseline is not configured")


def baseline_adapters() -> list[UnconfiguredBaseline]:
    return [
        UnconfiguredBaseline("gitleaks"), UnconfiguredBaseline("trufflehog"),
        UnconfiguredBaseline("keysentinel"),
        UnconfiguredBaseline("qwen3-32b-awq-llm", "vllm/openai-compatible"),
        UnconfiguredBaseline("qwen-vl", "openai-compatible-vlm"),
    ]
