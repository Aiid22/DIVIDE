from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from divide.config import load_config
from divide.evaluation.manifest import load_manifest
from divide.evaluation.metrics import ScoreCounts, compute_metrics, score_sets
from divide.evaluation.runner import ExperimentRunner
from divide.pipeline import ABLATION_PROFILES


def test_precision_recall_f1_fdr_definition() -> None:
    metrics = compute_metrics(ScoreCounts(true_positive=3, false_positive=1, false_negative=2))
    assert metrics["precision"] == .75
    assert metrics["recall"] == .6
    assert metrics["f1"] == pytest.approx(2 * .75 * .6 / 1.35)
    assert metrics["fdr"] == .25


def test_raw_occurrence_and_project_unique_are_distinct() -> None:
    expected_raw = {("p", "a", "f", "l1"), ("p", "a", "f", "l2")}
    predicted_raw = {("p", "a", "f", "l1")}
    expected_unique = {("p", "f")}
    predicted_unique = {("p", "f")}
    assert score_sets(expected_raw, predicted_raw).false_negative == 1
    assert score_sets(expected_unique, predicted_unique).false_negative == 0


def test_manifest_rejects_path_traversal_on_resolution(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({
        "schema_version": "1.0", "dataset_id": "safe", "root": ".", "artifacts": [{
            "artifact_id": "a", "project_id": "p", "relative_path": "../escape.bin",
            "sha256": "0" * 64, "mime": "application/octet-stream", "secrets": [],
        }],
    }), encoding="utf-8")
    manifest = load_manifest(manifest_path)
    with pytest.raises(ValueError, match="unsafe"):
        manifest.resolve_artifact(manifest.artifacts[0])


def test_four_ablation_profiles_are_fixed() -> None:
    assert set(ABLATION_PROFILES) == {"full", "no-media", "no-recovery", "no-post-filter"}
    assert ABLATION_PROFILES["no-media"].media_extraction is False
    assert ABLATION_PROFILES["no-recovery"].recovery is False
    assert ABLATION_PROFILES["no-post-filter"].post_filter is False


def test_benchmark_provenance_and_latency_aggregation_contract(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifact = tmp_path / "artifact.txt"
    artifact.write_text("harmless", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({
        "schema_version": "1.0", "dataset_id": "synthetic", "root": ".", "artifacts": [{
            "artifact_id": "a", "project_id": "p", "relative_path": "artifact.txt", "sha256": digest,
            "mime": "text/plain", "secrets": [],
        }],
    }), encoding="utf-8")
    results = ExperimentRunner(load_config()).run(load_manifest(manifest_path))
    assert {result.unit for result in results} == {"occurrence", "project_unique"}
    assert all(result.latency_seconds >= 0 for result in results)
    assert all(result.provenance["manifest_sha256"] for result in results)
