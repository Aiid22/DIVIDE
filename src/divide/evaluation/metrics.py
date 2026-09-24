from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScoreCounts:
    true_positive: int
    false_positive: int
    false_negative: int


def compute_metrics(counts: ScoreCounts) -> dict[str, float | int]:
    tp, fp, fn = counts.true_positive, counts.false_positive, counts.false_negative
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fdr = fp / (tp + fp) if tp + fp else 0.0
    return {
        "true_positive": tp, "false_positive": fp, "false_negative": fn,
        "precision": precision, "recall": recall, "f1": f1, "fdr": fdr,
    }


def score_sets(expected: set[tuple[str, ...]], predicted: set[tuple[str, ...]]) -> ScoreCounts:
    return ScoreCounts(len(expected & predicted), len(predicted - expected), len(expected - predicted))
