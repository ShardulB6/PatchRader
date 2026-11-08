"""Automated leakage checks. Each returns (check name, passed, detail)."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

from . import config, data
from .featureset import FeatureBuilder


def banned_columns() -> tuple:
    found = sorted(set(config.FEATURES) & config.BANNED_COLUMNS)
    blank_flags = [f for f in config.FEATURES if f.endswith("_missing") and f != "signal_missing"]
    ok = not found and not blank_flags
    return "No banned or 'is blank' columns are model inputs", ok, f"banned found: {found or 'none'}; blank flags: {blank_flags or 'none'}"


def time_order(train: pd.DataFrame, valid: pd.DataFrame) -> tuple:
    last_train_label = pd.Timestamp(config.TRAIN_WINDOW["deadline"])
    first_valid = pd.to_datetime(valid["published"]).min()
    ok = pd.to_datetime(train["published"]).max() < first_valid and last_train_label < first_valid
    return ("Training rows and labels all end before validation starts", ok,
            f"train published to {pd.to_datetime(train.published).max().date()}, labels to {last_train_label.date()}; "
            f"validation starts {first_valid.date()}")


def no_overlap(*frames: pd.DataFrame) -> tuple:
    ids = [set(f["cve_id"]) for f in frames]
    shared = sum(len(a & b) for i, a in enumerate(ids) for b in ids[i + 1:])
    return "No CVE appears in more than one set", shared == 0, f"shared IDs: {shared}"


def exclusion_rule(*frames: pd.DataFrame) -> tuple:
    bad = 0
    for f in frames:
        month_end = pd.to_datetime(f["published"]) + pd.offsets.MonthEnd(0)
        bad += int((pd.to_datetime(f["kev_date"]) <= month_end).sum())
    return "No row was already on KEV at its snapshot", bad == 0, f"rows on KEV by month end: {bad}"


def planted_future_kev(rows: pd.DataFrame, n_fake: int = 3000, seed: int = config.SEED) -> tuple:
    """Add fake KEV entries dated 2030 (for many assigners, products and weakness types) and rebuild the
    features for the same rows. If any feature changes, the feature code is reading the future."""
    con = data.connect()
    built = FeatureBuilder(con).transform(rows)
    kev = con.sql("SELECT * FROM known_exploited").df()
    non_kev = con.sql("SELECT cve_id FROM vulnerabilities WHERE cve_id NOT IN (SELECT cve_id FROM known_exploited)").df()
    fake = non_kev.sample(n_fake, random_state=seed).reset_index(drop=True)
    fake["product"] = kev["product"].sample(n_fake, replace=True, random_state=seed).to_numpy()
    fake["vendor"] = kev["vendor"].sample(n_fake, replace=True, random_state=seed).to_numpy()
    fake["date_added"] = pd.Timestamp("2030-01-01").date()
    poisoned = FeatureBuilder(data.connect(kev_extra=fake)).transform(rows)
    cols = config.NUMERIC + config.BINARY
    changed = [c for c in cols if not np.allclose(poisoned[c].to_numpy(float), built[c].to_numpy(float), equal_nan=True)]
    return (f"{n_fake:,} fake KEV entries dated 2030 change no feature", not changed, f"changed: {changed or 'none'}")


def single_feature_screen(train: pd.DataFrame, threshold: float = 0.90) -> tuple:
    """A single input that almost perfectly separates the classes on its own is a classic leak signature."""
    aucs = {}
    for c in config.NUMERIC + config.BINARY:
        x = train[c].fillna(train[c].median())
        if x.nunique() > 1:
            a = roc_auc_score(train["y"], x)
            aucs[c] = max(a, 1 - a)
    worst = max(aucs, key=aucs.get)
    return (f"No single feature has AUC above {threshold} on its own", aucs[worst] <= threshold,
            f"highest: {worst} = {aucs[worst]:.3f}")


def run_all(train_rows, valid_rows, train, valid, score) -> pd.DataFrame:
    sample = valid_rows.sample(2000, random_state=config.SEED).sort_values("cve_id").reset_index(drop=True)
    checks = [banned_columns(), time_order(train, valid), no_overlap(train, valid, score),
              exclusion_rule(train, valid), planted_future_kev(sample), single_feature_screen(train)]
    return pd.DataFrame(checks, columns=["check", "passed", "detail"])
