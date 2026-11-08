"""Preprocessing and the candidate models, each wrapped in a scikit-learn Pipeline.

Hyperparameters are library defaults on purpose: these are baselines, not tuned models. The only
non-default choices handle class imbalance (about 1 positive per 700 rows) and fix random seeds."""
from __future__ import annotations

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.compose import ColumnTransformer
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from . import config


def make_preprocessor(scale: bool) -> ColumnTransformer:
    """Imputation, encoding and (optionally) scaling, all learned from the training rows only.

    - Numeric: median imputation (robust to skew), then standardization for linear models.
    - Binary: most-frequent imputation (they're rarely missing), no scaling needed for trees.
    - Categorical: most-frequent imputation, then one-hot. Missing values are NOT made their own
      category: a blank CVSS part mostly means "NIST hasn't reviewed it", which leaks the label.
      handle_unknown="ignore" keeps an unseen category (e.g. in 2026) from crashing the model.
    """
    numeric = Pipeline([("impute", SimpleImputer(strategy="median")),
                        ("scale", StandardScaler() if scale else "passthrough")])
    binary = Pipeline([("impute", SimpleImputer(strategy="most_frequent")),
                       ("scale", StandardScaler() if scale else "passthrough")])
    categorical = Pipeline([("impute", SimpleImputer(strategy="most_frequent")),
                            ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False))])
    return ColumnTransformer([("num", numeric, config.NUMERIC),
                              ("bin", binary, config.BINARY),
                              ("cat", categorical, config.CATEGORICAL)],
                             remainder="drop", verbose_feature_names_out=False)


class ExploitThenEPSS(ClassifierMixin, BaseEstimator):
    """The benchmark's best standard ranking, as an estimator: public exploit code first, then EPSS.
    It learns nothing, so it shows what a model has to beat."""

    def fit(self, X, y):
        self.classes_ = np.array([0, 1])
        return self

    def predict_proba(self, X):
        score = X["any_exploit"].to_numpy() * 10 + X["epss"].fillna(0).to_numpy()  # EPSS is in [0, 1]
        score = score / 11.0
        return np.column_stack([1 - score, score])


def make_models(seed: int = config.SEED) -> dict[str, Pipeline]:
    models = {
        "Random ranking (DummyClassifier)": Pipeline([
            ("prep", make_preprocessor(scale=False)),
            ("model", DummyClassifier(strategy="stratified", random_state=seed))]),
        "Baseline: exploit code then EPSS": Pipeline([("model", ExploitThenEPSS())]),
        "Logistic regression": Pipeline([
            ("prep", make_preprocessor(scale=True)),
            ("model", LogisticRegression(class_weight="balanced", max_iter=5000, random_state=seed))]),
        "Random forest": Pipeline([
            ("prep", make_preprocessor(scale=False)),
            ("model", RandomForestClassifier(class_weight="balanced_subsample", random_state=seed, n_jobs=-1))]),
        "Histogram gradient boosting": Pipeline([
            ("prep", make_preprocessor(scale=False)),
            ("model", HistGradientBoostingClassifier(class_weight="balanced", random_state=seed))]),
    }
    try:
        import lightgbm as lgb
        models["LightGBM"] = Pipeline([
            ("prep", make_preprocessor(scale=False)),
            ("model", lgb.LGBMClassifier(class_weight="balanced", random_state=seed, deterministic=True,
                                         force_row_wise=True, n_jobs=1, verbose=-1))])
    except (ImportError, OSError):  # LightGBM needs the OpenMP runtime; skip it where unavailable
        pass
    return models
