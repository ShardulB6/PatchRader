"""Point-in-time feature construction, reusing the team's leak-checked code in scripts/."""
from __future__ import annotations

import importlib
import sys

import duckdb
import numpy as np
import pandas as pd

from . import config


def _team_modules():
    if str(config.SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(config.SCRIPTS_DIR))
    return importlib.import_module("features"), importlib.import_module("features_extra")


class FeatureBuilder:
    """Loads KEV / assigner / product / CWE history once, then adds features to any row set.

    Every history feature counts only events dated on or before the end of the row's snapshot month,
    so the builder is stateless with respect to labels: it never looks at the `y` column."""

    def __init__(self, con: duckdb.DuckDBPyConnection):
        self.F, self.FX = _team_modules()
        self.hist, self.hx = self.F.History(con), self.FX.ExtraHistory(con)

    def transform(self, rows: pd.DataFrame) -> pd.DataFrame:
        df = self.FX.add_engineered_features(self.F.build_features(rows, self.hist), self.hx)
        df["log_product_kev_prior"] = np.log1p(df["product_kev_prior"])
        for c in config.CATEGORICAL:  # unify missing values so the imputer sees NaN, not None
            df[c] = df[c].astype("object").where(df[c].notna(), np.nan)
        return df


def feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Only the model inputs, in a fixed column order, plus the raw `epss` used by the rule baseline."""
    return df[config.FEATURES + ["epss"]].copy()
