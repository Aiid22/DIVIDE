"""Evaluation protocol: dataset manifests, RQ1 metrics, and the ablation runner."""

from .manifest import DatasetManifest, ManifestArtifact, SecretAnnotation, load_manifest
from .metrics import ScoreCounts, compute_metrics
from .runner import ExperimentRunner

__all__ = [
    "DatasetManifest", "ManifestArtifact", "SecretAnnotation", "load_manifest",
    "ScoreCounts", "compute_metrics", "ExperimentRunner",
]
