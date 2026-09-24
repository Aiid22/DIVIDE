"""Experiment runner for RQ1 benchmarks and RQ2 ablation profiles."""

from __future__ import annotations

import hashlib
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from divide.config import AppConfig
from divide.models import ExperimentResult
from divide.pipeline import ABLATION_PROFILES, DividePipeline

from .manifest import DatasetManifest
from .metrics import compute_metrics, score_sets


class ExperimentRunner:
    """Runs RQ1 benchmarks and RQ2 ablations over a manifest."""
    def __init__(self, config: AppConfig):
        self.config = config

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def run(self, manifest: DatasetManifest, profile: str = "full") -> list[ExperimentResult]:
        """Execute one profile over the manifest; return per-artifact results."""
        if profile not in ABLATION_PROFILES:
            raise ValueError(f"unknown profile: {profile}")
        expected_occurrence: set[tuple[str, ...]] = set()
        predicted_occurrence: set[tuple[str, ...]] = set()
        expected_unique: set[tuple[str, ...]] = set()
        predicted_unique: set[tuple[str, ...]] = set()
        total_latency = 0.0
        last_provenance: dict[str, Any] = {}
        for artifact in manifest.artifacts:
            target = manifest.resolve_artifact(artifact)
            if self._sha256(target) != artifact.sha256:
                raise ValueError(f"artifact hash mismatch: {artifact.artifact_id}")
            for secret in artifact.secrets:
                expected_occurrence.add((artifact.project_id, artifact.artifact_id, secret.fingerprint, secret.location))
                expected_unique.add((artifact.project_id, secret.fingerprint))
            started = time.perf_counter()
            report = DividePipeline(self.config).scan(target, ablation_profile=profile)
            total_latency += time.perf_counter() - started
            last_provenance = report.provenance
            for finding in report.findings:
                predicted_unique.add((artifact.project_id, finding.fingerprint))
                for source in finding.sources:
                    predicted_occurrence.add((
                        artifact.project_id, artifact.artifact_id, finding.fingerprint,
                        f"{source['nested_path']}:{source['location']}",
                    ))
        output = []
        for unit, expected, predicted in (
            ("occurrence", expected_occurrence, predicted_occurrence),
            ("project_unique", expected_unique, predicted_unique),
        ):
            metrics = compute_metrics(score_sets(expected, predicted))
            output.append(ExperimentResult(
                profile=profile, unit=unit, latency_seconds=total_latency, provenance={
                    **last_provenance, "dataset_id": manifest.dataset_id,
                    "manifest_sha256": self._sha256(manifest.source_path),
                }, **metrics,
            ))
        return output

    def ablate(self, manifest: DatasetManifest) -> dict[str, list[dict[str, Any]]]:
        """Execute every ablation profile; return per-profile results."""
        return {profile: [asdict(result) for result in self.run(manifest, profile)] for profile in ABLATION_PROFILES}
