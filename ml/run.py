"""End-to-end baseline run: data -> features -> leakage checks -> models -> metrics -> saved results.

    python -m ml.run            # from the repo root
"""
from __future__ import annotations

import json
import os
import platform
import random
import time

import numpy as np
import pandas as pd
import sklearn

from . import config, data, evaluate, leakage, models
from .featureset import FeatureBuilder, feature_matrix


def set_seeds(seed: int = config.SEED) -> None:
    random.seed(seed); np.random.seed(seed); os.environ["PYTHONHASHSEED"] = str(seed)


def build_datasets():
    con = data.connect()
    train_rows, valid_rows = data.load_splits(con)
    fb = FeatureBuilder(con)
    import features as F  # team module, importable once FeatureBuilder has added scripts/ to the path
    score_rows = F.scoreboard_frame(con).sort_values("cve_id").reset_index(drop=True)
    return train_rows, valid_rows, fb.transform(train_rows), fb.transform(valid_rows), fb.transform(score_rows)


def evaluate_models(train: pd.DataFrame, valid: pd.DataFrame, seed: int = config.SEED):
    """Fit every model on the training rows only; record training and validation performance."""
    Xtr, Xva = feature_matrix(train), feature_matrix(valid)
    rows, val_scores = [], {}
    for name, pipe in models.make_models(seed).items():
        t0 = time.time()
        pipe.fit(Xtr, train["y"])
        fit_s = time.time() - t0
        s_tr, s_va = pipe.predict_proba(Xtr)[:, 1], pipe.predict_proba(Xva)[:, 1]
        val_scores[name] = s_va
        tr_m, va_m = evaluate.ranking_metrics(train["y"], s_tr), evaluate.ranking_metrics(valid["y"], s_va)
        lo, hi = evaluate.bootstrap_hits(valid["y"], s_va, seed=seed)
        rows.append({"model": name, "fit_seconds": round(fit_s, 1),
                     "train hits@k": tr_m["hits@k"], "train AUC": tr_m["roc_auc"], "train AP": tr_m["average_precision"],
                     "valid hits@k": va_m["hits@k"], "valid 90% range": f"{lo}-{hi}",
                     "valid precision@k": va_m["precision@k"], "valid recall@k": va_m["recall@k"],
                     "valid AUC": va_m["roc_auc"], "valid AP": va_m["average_precision"]})
    results = pd.DataFrame(rows).set_index("model")
    base = val_scores["Baseline: exploit code then EPSS"]
    vs = {n: evaluate.paired_difference(valid["y"], s, base, seed=seed) for n, s in val_scores.items()
          if n != "Baseline: exploit code then EPSS"}
    results["valid vs. baseline"] = [f"{vs[n]['diff']:+d} ({vs[n]['low']:+d} to {vs[n]['high']:+d})" if n in vs else ""
                                     for n in results.index]
    return results, val_scores


def run(seed: int = config.SEED, save: bool = True):
    set_seeds(seed)
    train_rows, valid_rows, train, valid, score = build_datasets()
    leaks = leakage.run_all(train_rows, valid_rows, train, valid, score)
    results, val_scores = evaluate_models(train, valid, seed)
    info = {"seed": seed, "python": platform.python_version(), "scikit-learn": sklearn.__version__,
            "numpy": np.__version__, "pandas": pd.__version__,
            "train": {"rows": len(train), "positives": int(train.y.sum()), "k": evaluate.k_for(len(train))},
            "valid": {"rows": len(valid), "positives": int(valid.y.sum()), "k": evaluate.k_for(len(valid))},
            "scoreboard_rows": len(score), "features": config.FEATURES, "leakage_checks_passed": bool(leaks.passed.all())}
    if save:
        config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        results.to_csv(config.OUTPUT_DIR / "results.csv")
        leaks.to_csv(config.OUTPUT_DIR / "leakage_checks.csv", index=False)
        (config.OUTPUT_DIR / "run_info.json").write_text(json.dumps(info, indent=2))
    return {"results": results, "leakage": leaks, "info": info, "val_scores": val_scores,
            "train": train, "valid": valid, "score": score}


if __name__ == "__main__":
    out = run()
    pd.set_option("display.width", 200)
    print(out["leakage"].to_string(index=False)); print(); print(out["results"].round(3).to_string())
