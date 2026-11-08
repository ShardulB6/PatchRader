"""Single source of truth for the pipeline: paths, seed, split windows and feature lists."""
from __future__ import annotations

from pathlib import Path

SEED = 42

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
SCRIPTS_DIR = ROOT / "scripts"            # team feature code: features.py, features_extra.py
OUTPUT_DIR = ROOT / "outputs" / "ml_baselines"

# The benchmark keeps 500 of 72,670 scoreboard rows (0.69%); every evaluation uses the same share.
TOP_FRACTION = 500 / 72_670

# Time-based split that copies the benchmark's rules (see notebooks/phase3_backtest.ipynb):
# published January-September, label = added to KEV after the publish month and by December 31.
TRAIN_WINDOW = dict(start="2024-01-01", end="2024-09-30", deadline="2024-12-31", signals="exploit_signals_2024")
VALID_WINDOW = dict(start="2025-01-01", end="2025-09-30", deadline="2025-12-31", signals="exploit_signals_2025")

# Columns that leak NIST's review or later events. They must never reach a model.
BANNED_COLUMNS = {"nvd_status", "n_affected_cpes", "n_references", "cvss3_source", "last_modified",
                  "cwe_missing",  # "CWE is blank" = "NIST hasn't reviewed it" = almost never exploited
                  }

# ---- Model inputs, by type --------------------------------------------------------------------
# Continuous values: imputed with the training median, scaled for linear models.
NUMERIC = [
    "epss_pct",               # EPSS percentile within its snapshot month (raw EPSS changes scale over time)
    "cvss3_score",            # severity; blanks imputed, never flagged (a blank score leaks NIST review)
    "log_assigner_kev_rate",  # point-in-time KEV rate of whoever issued the CVE
    "log_assigner_rate_12m",  # the same over the last 12 months
    "log_batch_size",         # CVEs from the same assigner on the same day (one advisory)
    "log_cwe_kev_rate",       # point-in-time KEV rate of the weakness type
    "log_product_kev_prior",  # KEV entries for the product named in the description, before the snapshot
]
# 0/1 indicators: already numeric, no scaling needed beyond what the linear model's scaler does.
BINARY = [
    "any_exploit", "exploitdb", "metasploit", "nuclei", "poc_github",   # public exploit code at the snapshot
    "signal_missing",                                                   # no EPSS row that month (feed gap, not NIST)
    "batch_exploit_others",                                             # exploit code for a sibling CVE in the same advisory
    "kw_unauth", "kw_rce", "kw_path_traversal", "kw_deserialization", "kw_cmd_injection", "kw_edge_device",
    "kw_privesc_local", "kw_sqli", "kw_xss", "kw_dos", "kw_wordpress", "kw_linux_kernel",
    "cwe_auth", "cwe_path", "cwe_deser", "cwe_injection", "cwe_memory", "cwe_xss",
]
# Low-cardinality text categories: one-hot encoded.
CATEGORICAL = ["attack_vector", "attack_complexity", "privileges_required", "user_interaction", "scope"]

FEATURES = NUMERIC + BINARY + CATEGORICAL

# ---- The submission model (team blend + IBM Granite text score) --------------------------------
# Team features, chosen by evidence (see notebooks/demo_findings_and_model.ipynb).
TEAM_LR = ["any_exploit", "poc_github", "nuclei", "log_assigner_kev_rate", "kw_unauth", "pr_none", "ui_none",
           "cvss_filled", "cwe_auth", "cwe_path"]
TEAM_GBM_EXTRA = ["net_preauth", "log_batch_size", "log_cwe_kev_rate", "product_has_kev"]
# Granite features added to both models (notebooks/trackb_6_stacking.ipynb, variant C).
GRANITE = ["text_pct", "id_age"]
GBM_PARAMS = dict(n_estimators=200, learning_rate=0.03, num_leaves=4, max_depth=2, min_child_samples=40, subsample=0.8,
                  subsample_freq=1, colsample_bytree=0.8, reg_lambda=5, scale_pos_weight=50, verbose=-1)
LR_C = 0.1
GBM_SEEDS = 30

# Text-score files: one folder per text-model recipe, each with the same four files
# (text_oof_train, text_val_2025, text_oof_final, text_2026). The final model reads TEXT_SCORES_DIR.
# The submitted recipe's files are committed in ml/text_scores/ (7 MB), so the final model reproduces
# without re-running Granite; the others live under data/ (gitignored) and are rebuilt by the trackb notebooks.
TEXT_DIR = DATA_DIR / "trackb"
TEXT_SCORES = {
    "frozen-small": ROOT / "ml" / "text_scores" / "frozen-small",  # frozen granite-embedding-small + logistic regression
    "finetuned-small": TEXT_DIR / "handoff",           # full fine-tune of granite-embedding-small
    "lora-149m": TEXT_DIR / "handoff_lora149",         # LoRA on granite-embedding-english-r2 (149M)
}
TEXT_SCORES_DIR = TEXT_SCORES["frozen-small"]          # the recipe the current submission uses

# LoRA fine-tuning of a larger Granite model (ml/text_model.py). Fixed before any 2025 result was seen.
LORA = dict(
    model="ibm-granite/granite-embedding-english-r2",  # 149M parameters (vs. 47M for the small model)
    r=16, alpha=32, dropout=0.1,                       # adapter size and scaling
    target_modules=["Wqkv", "Wo", "Wi"],               # attention and feed-forward layers
    modules_to_save=["head", "classifier"],            # the new classification head is trained in full
    lr=2e-4,                                           # LoRA trains far fewer weights, so a larger step is standard
    epochs=1,                                          # the small model's held-out loss was lowest after epoch 1
    max_length=256, batch_size=32, micro_batch=8,      # 4 chunks of 8 = a batch of 32, fits the Mac's memory
    neg_per_pos=20, pos_weight=4.0, warmup=0.06, weight_decay=0.01, holdout=0.10, seed=0,
)
