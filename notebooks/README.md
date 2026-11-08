# Model notebooks

SYD's exploration and ranking-model notebooks for the IBM "Before the Breach" track. The task: pick 500 CVEs from `scoreboard_2026.csv` that are most likely to be added to CISA KEV later.

## Running them

1. Download the dataset once from the repo root: `python3 scripts/fetch_data.py`.
2. Install the Python packages: `pip install pandas numpy scipy scikit-learn lightgbm xgboost matplotlib sentence-transformers torch`.
3. Open a notebook and run it top to bottom. The notebooks find `data/` whether they run from this folder or from the repo root.

The Granite notebooks download `ibm-granite` embedding models from Hugging Face and embed every CVE description, so they are slow on a CPU. Run them on Colab or a cloud GPU, not a laptop. The CSVs and caches they write (`top500*.csv`, `outputs/`, `neighbor_outputs/`) are git-ignored.

## The notebooks

| Notebook | What it does |
| --- | --- |
| `data_exploration.ipynb` | Loads every CSV in `data/` and prints its shape and columns. |
| `before_the_breach_exploration.ipynb` | Explores the data and compares simple rankings (CVSS, EPSS, vendor momentum) on a 2025 cohort. Writes `top500_baseline.csv`. |
| `ibm_before_the_breach_model.ipynb` | The main model notebook. Time-aware backtests of LightGBM, Granite-embedding heads, XGBoost and an ML reranker against the "exploit code first, then EPSS" baseline. Writes `top500.csv`. |
| `granite_reranker_STANDALONE.ipynb` | Re-ranks the baseline with a Granite embedding head, then exports a dashboard-ready ranking to `outputs/`. |
| `granite_reranker_and_production.ipynb` | An earlier version of the standalone notebook. It has no saved outputs. |
| `granite_neighbor_challenger.ipynb` | Tests whether being similar to already-exploited CVEs is a useful signal. It has no saved outputs. |
| `source_evidence_bayesian_experiment.ipynb` | Learns separate weights for each exploit source (Exploit-DB, Metasploit, Nuclei, GitHub PoC) instead of treating any exploit code the same. |

## Results

**The submitted ranking doesn't come from the seven notebooks above.** It's `outputs/top500.csv`, a blend of logistic regression and LightGBM with a Granite text score, built by `python -m ml.final_model`. Trained on 2024 and tested on 2025, it found 19 of the 52 exploited CVEs in its top 243, against 14 for "exploit code first, then EPSS". That's a gain of 5 with a 90% range of -1 to +10, so it could still be luck. See [`ml/README.md`](../ml/README.md) for the full results and the later notebooks in this folder.

The seven notebooks above didn't beat the baseline. In rolling 2025 Q1 to Q3 backtests (label: added to KEV within 90 days), "exploit code first, then EPSS" caught 11 exploited CVEs in total. Plain EPSS caught 8, Granite + XGBoost caught 6, and the Granite head alone caught 2. The 25% ML reranker tied the baseline at 11. Every one of their selection rules chose the baseline, so the `top500.csv` they write is the baseline ranking, not the submitted file.

These numbers come from the saved notebook outputs and have not been rerun. The Granite notebooks also warn that current NVD descriptions may include text written after the snapshot date, which can leak future information into the embeddings. Treat the Granite results as exploratory.
