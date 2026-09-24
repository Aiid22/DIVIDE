from __future__ import annotations

from divide.config import load_config
from divide.models import CarrierRecord
from divide.recovery.planner import LLMPlanner


def records() -> list[CarrierRecord]:
    common = {
        "root_path": "/synthetic/project", "nested_path": "config.json", "carrier_type": "structured",
        "context": "token parts", "confidence": 1.0,
        "metadata": {"group": "row-1"}, "parent_object_id": "O1", "relationship": "field-sibling",
    }
    return [
        CarrierRecord(id="R1", location="field:a", text="synthetic-a", field_path="token_part_1", **common),
        CarrierRecord(id="R2", location="field:b", text="synthetic-b", field_path="token_part_2", **common),
    ]


def test_default_planner_explicitly_reports_model_unavailable() -> None:
    planner = LLMPlanner(load_config())
    assert planner.status()["status"] == "model_unavailable"
    assert planner.recover(records()).recovered == []


def test_remote_endpoint_is_blocked_without_opt_in() -> None:
    config = load_config()
    config.llm.planner = "openai-compatible"
    config.llm.base_url = "https://remote.invalid/v1"
    config.llm.model = "Qwen3-32B-AWQ"
    result = LLMPlanner(config).recover(records())
    assert not result.recovered
    assert result.warnings[0].code == "remote_llm_blocked"
