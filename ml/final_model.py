"""The submission model: the team's LR + LightGBM rank blend, with the IBM Granite text score as a feature.

    python -m ml.final_model                       # uses config.TEXT_SCORES_DIR (the submitted recipe)
    python -m ml.final_model lora-149m             # or another recipe from config.TEXT_SCORES

Reads the text-score folder's text_oof_final.csv (training rows, out-of-fold) and text_2026.csv
(scoreboard), trains on 2024 + 2025, and writes outputs/top500.csv.
"""
from __future__ import annotations

import sys

import lightgbm as lgb
import numpy as np
import pandas as pd
from scipy.stats import rankdata
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from . import config, data
from .featureset import FeatureBuilder


def add_text_features(df: pd.DataFrame, text_file) -> pd.DataFrame:
    """Join a text-score file (cve_id, text_score) and add the two Granite features:
    text_pct = percentile within the snapshot month (puts different text-model fits on one scale);
    id_age = publish year minus the CVE ID's year (old bugs re-filed under new IDs)."""
    t = pd.read_csv(text_file)
    out = df.drop(columns=["text_score", "text_pct", "id_age"], errors="ignore").merge(t, on="cve_id", how="left")
    assert out["text_score"].notna().all(), f"{out.text_score.isna().sum()} rows have no text score"
    out["text_pct"] = out.groupby("snap")["text_score"].rank(pct=True)
    out["id_age"] = (pd.to_datetime(out["published"]).dt.year - out["cve_id"].str.slice(4, 8).astype(int)).clip(0, 20)
    return out


def train_and_score(train: pd.DataFrame, score: pd.DataFrame, extra=config.GRANITE, seeds: int = config.GBM_SEEDS):
    """Fit both models on `train`, blend their ranks on `score` (higher = riskier)."""
    c_lr = config.TEAM_LR + list(extra)
    c_gb = config.TEAM_LR + config.TEAM_GBM_EXTRA + list(extra)
    lr = make_pipeline(StandardScaler(), LogisticRegression(C=config.LR_C, class_weight="balanced", max_iter=5000))
    p_lr = lr.fit(train[c_lr], train.y).predict_proba(score[c_lr])[:, 1]
    p_gb = np.mean([lgb.LGBMClassifier(**config.GBM_PARAMS, random_state=s)
                    .fit(train.iloc[np.random.default_rng(s).permutation(len(train))][c_gb],
                         train.iloc[np.random.default_rng(s).permutation(len(train))].y)
                    .predict_proba(score[c_gb])[:, 1] for s in range(seeds)], axis=0)
    return 0.5 * rankdata(p_lr) / len(score) + 0.5 * rankdata(p_gb) / len(score)


def build_top500(text_dir=config.TEXT_SCORES_DIR) -> pd.DataFrame:
    con = data.connect()
    tr_rows, va_rows = data.load_splits(con)
    fb = FeatureBuilder(con)
    import features as F  # team module; importable once FeatureBuilder has added scripts/ to the path
    L = pd.concat([fb.transform(tr_rows), fb.transform(va_rows)], ignore_index=True).sort_values("cve_id", ignore_index=True)
    sb = fb.transform(F.scoreboard_frame(con).sort_values("cve_id").reset_index(drop=True))
    L, sb = add_text_features(L, text_dir / "text_oof_final.csv"), add_text_features(sb, text_dir / "text_2026.csv")
    top = sb.assign(score=train_and_score(L, sb)).nlargest(500, "score")
    assert len(top) == 500 and top.cve_id.is_unique and top.cve_id.isin(sb.cve_id).all()
    return top


if __name__ == "__main__":
    recipe = sys.argv[1] if len(sys.argv) > 1 else None
    text_dir = config.TEXT_SCORES[recipe] if recipe else config.TEXT_SCORES_DIR
    top = build_top500(text_dir)
    out = config.ROOT / "outputs"; out.mkdir(exist_ok=True)
    top[["cve_id"]].to_csv(out / "top500.csv", index=False)
    print(f"Wrote outputs/top500.csv from text scores in {text_dir.name}: 500 CVEs, "
          f"{top.any_exploit.mean():.0%} with public exploit code")
