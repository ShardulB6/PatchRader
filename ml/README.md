# ML pipeline: reproducing the submission

This folder builds `outputs/top500.csv`, the 500 CVEs from the 2026 scoreboard we predict CISA will add to KEV.

## Reproduce the submission (a few minutes, CPU only)

```bash
pip install -r ml/requirements.txt
python scripts/fetch_data.py          # downloads the dataset into data/ (gitignored)
python -m ml.final_model              # writes outputs/top500.csv
```

The result should match the committed `outputs/top500.csv` exactly: the same 500 CVEs in the same order.

**On a Mac:** if LightGBM fails with `Library not loaded: libomp.dylib`, install libomp (`brew install libomp`), or point LightGBM at the copy that scikit-learn ships with:
`install_name_tool -add_rpath <venv>/lib/python3.9/site-packages/sklearn/.dylibs <venv>/lib/python3.9/site-packages/lightgbm/lib/lib_lightgbm.dylib`, then `codesign --force -s - <same dylib>`.

## The final model

A 50/50 rank blend of two models, trained on CVEs published January-September of 2024 and 2025 (64,120 rows, 85 later added to KEV):

| Model | Inputs | Settings |
|---|---|---|
| Logistic regression | the team's 10 features + `text_pct`, `id_age` | `C=0.1`, balanced class weights |
| LightGBM | the team's 14 features + `text_pct`, `id_age` | 200 depth-2 trees, `scale_pos_weight=50`, averaged over 30 seeds |

- **The team's features** come from `scripts/features.py` and `scripts/features_extra.py`; `ml/featureset.py` wraps them. Every feature is point-in-time: it uses only what was known at the end of the CVE's publication month.
- **`text_pct`** is the IBM Granite text score as a percentile within the publication month. The score comes from frozen `granite-embedding-small-english-r2` embeddings plus a logistic regression (`notebooks/trackb_5_frozen_handoff.ipynb`).
- **`id_age`** is the publish year minus the CVE ID's year. It discounts old bugs re-filed under new IDs.

All settings live in `ml/config.py`.

**Granite text scores:** `ml/text_scores/frozen-small/` holds the four score files the final model reads. Each training row's score comes from a text model that never saw that row's label (out-of-fold), and 2026 is scored by a model trained on 2018-2025 only. They're committed so the final model reproduces without running Granite, which would take about an hour on a GPU.

## Results (details in the notebooks)

| Test | Final model | Best standard ranking (exploit code, then EPSS) |
|---|---|---|
| Train 2024, test 2025 (top 243 of 35,281; 52 exploited) | 19 | 14 |
| Repeated grouped cross-validation (top 442; 85 exploited) | 36.4 | 22 |
| Rolling 12-month test, team model before Granite (64 exploited) | 22 | 16 |

With 52-85 exploited CVEs per test, differences of fewer than about 6 hits can't be told apart from luck.

## Files

| File | What it does |
|---|---|
| `config.py` | Paths, split windows, banned columns, feature lists, model settings |
| `data.py` | Loads the raw CSVs into DuckDB and builds the labeled 2024 and 2025 sets |
| `featureset.py` | Wraps the team's feature code |
| `final_model.py` | The submission model: `python -m ml.final_model` |
| `run.py`, `models.py`, `evaluate.py`, `leakage.py` | Baseline comparison and six leakage checks: `python -m ml.run` writes `outputs/ml_baselines/` |
| `text_model.py` | LoRA fine-tuning of a larger Granite model (optional, needs a GPU; not in the submission) |
| `text_scores/` | The submitted Granite text scores |

## Notebooks (in `notebooks/`, run in this order to follow the work)

1. `phase3_backtest.ipynb`, `phase3_validation.ipynb`: how the backtest copies the benchmark's rules, and the baselines.
2. `demo_findings_and_model.ipynb`: the team model (feature evidence, LR + LightGBM).
3. `trackb_1` to `trackb_7`: the IBM Granite text track (frozen, fine-tuned, LoRA), the Tiger Data vector search, and stacking.
4. `final_model_with_granite.ipynb`: the submitted model.
5. `model_diagnosis.ipynb`, `exp1_feature_pruning.ipynb`, `exp2_rolling_forward_test.ipynb`: diagnosis and experiments.
6. `eda_report_evidence.ipynb`: every number in the report's EDA sections.
7. `shap_interpretation.ipynb`: what the final model learned, with per-CVE explanations in `outputs/shap/top500_contributions.csv`.

Notebooks marked with Granite training (`trackb_2*`, `trackb_7`) read intermediate files from `data/trackb/` and take hours on a laptop GPU. Their executed outputs are saved in the notebooks.

## Columns never used (leakage)

`nvd_status`, affected products and CPE counts, reference links and counts, `cvss3_source`, `last_modified`, and "blank CVSS/CWE" flags. Each reflects NIST's later review or post-attack edits. "Exploited in the wild" wording is removed from descriptions before Granite reads them. `python -m ml.run` checks this automatically.
