"""Ranking metrics suited to a rare-positive, top-k problem.

Accuracy is useless here: predicting "never exploited" for every row is 99.85% accurate and finds
nothing. What matters is how many real positives land in the small list a team can actually patch."""
from __future__ import annotations

import numpy as np
from scipy.stats import rankdata
from sklearn.metrics import average_precision_score, roc_auc_score

from . import config


def k_for(n: int, fraction: float = config.TOP_FRACTION) -> int:
    return int(round(n * fraction))


def top_k_hits(y, scores, k: int) -> int:
    """Positives among the k highest scores. Ties keep row order (rows are sorted by cve_id)."""
    order = np.argsort(-np.asarray(scores, dtype=float), kind="stable")
    return int(np.asarray(y)[order[:k]].sum())


def ranking_metrics(y, scores, fraction: float = config.TOP_FRACTION) -> dict:
    y, scores = np.asarray(y), np.asarray(scores, dtype=float)
    k = k_for(len(y), fraction)
    hits = top_k_hits(y, scores, k)
    constant = np.allclose(scores, scores[0])
    return {"k": k, "positives": int(y.sum()), "hits@k": hits,
            "precision@k": hits / k, "recall@k": hits / max(int(y.sum()), 1),
            "average_precision": np.nan if constant else average_precision_score(y, scores),
            "roc_auc": np.nan if constant else roc_auc_score(y, scores)}


def bootstrap_hits(y, scores, n: int = 1000, seed: int = config.SEED, ci: float = 0.90) -> tuple[int, int]:
    """Range of hits@k over resampled row sets: how much the score could move by luck of the sample."""
    y = np.asarray(y); k = k_for(len(y))
    rank = rankdata(-np.asarray(scores, dtype=float), method="ordinal")
    rng = np.random.default_rng(seed)
    h = [y[i][np.argpartition(rank[i], k)[:k]].sum() for i in (rng.integers(0, len(y), len(y)) for _ in range(n))]
    return int(np.quantile(h, (1 - ci) / 2)), int(np.quantile(h, 1 - (1 - ci) / 2))


def paired_difference(y, scores_a, scores_b, n: int = 1000, seed: int = config.SEED, ci: float = 0.90) -> dict:
    """hits@k(A) - hits@k(B) on the same resamples. If the range excludes 0, A's lead is probably real."""
    y = np.asarray(y); k = k_for(len(y))
    ra = rankdata(-np.asarray(scores_a, dtype=float), method="ordinal")
    rb = rankdata(-np.asarray(scores_b, dtype=float), method="ordinal")
    rng = np.random.default_rng(seed); d = np.empty(n)
    for j in range(n):
        i = rng.integers(0, len(y), len(y))
        d[j] = y[i][np.argpartition(ra[i], k)[:k]].sum() - y[i][np.argpartition(rb[i], k)[:k]].sum()
    return {"diff": top_k_hits(y, scores_a, k) - top_k_hits(y, scores_b, k),
            "low": int(np.quantile(d, (1 - ci) / 2)), "high": int(np.quantile(d, 1 - (1 - ci) / 2))}
