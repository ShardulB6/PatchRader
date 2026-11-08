# PatchRadar — IBM Granite CVE Analyst

A runnable Streamlit web app for the **Before the Breach** challenge. Includes a transparent vulnerability priority queue, conversational dataset analytics backed by DuckDB, CVE investigator, and an optional IBM Granite/watsonx AI layer.

## Quick start (Windows PowerShell)

Put the supplied CSVs inside `data/` beside `app.py`:

```
patchradar_app/
  app.py
  analyst.py
  db.py
  semantic.py
  data/
    vulnerabilities.csv
    affected_products.csv
    known_exploited.csv
    scoreboard_2026.csv
    weakness_types.csv
    references.csv
    exploit_signals_2024.csv
    exploit_signals_2025.csv
```

From the project folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Open the local URL Streamlit displays, usually http://localhost:8501.

### Optional IBM watsonx Granite chatbot

The app works **without credentials** using a deterministic, constrained intent router. For Granite-driven question routing and narrative answers:

```powershell
python -m pip install -r requirements-ai.txt
Copy-Item .env.example .env
```

Edit `.env` (never commit it):

```
WATSONX_API_KEY=your_api_key
WATSONX_PROJECT_ID=your_project_id
WATSONX_URL=https://us-south.ml.cloud.ibm.com
WATSONX_MODEL_ID=ibm/granite-4-h-small
```

Restart Streamlit and enable **IBM watsonx Granite chatbot** in the sidebar. The model's availability depends on your IBM account and region. The model is *not* given arbitrary SQL execution; it selects from predefined query operations, with server-side validation of parameters.

### Optional IBM Granite similarity search

Install `requirements-ai.txt`, open **CVE Investigator**, enter a CVE ID, then click **Find similar CVEs using Granite embeddings**. This loads `ibm-granite/granite-embedding-30m-english` from Hugging Face and compares against historical KEV and a sample of top 2026 candidates. It is deliberately CPU-friendly, not a whole-dataset vector index.

## Features

- **Overview:** CVE metrics, publication-year trends, and highest-ranked scoreboard vulnerabilities.
- **Ask the Data:** natural-language questions about vendor counts, KEV rates, CWE types, per-year trends, CVE details, EPSS signal history, and the 2026 priority queue. All computed via DuckDB.
- **Priority Queue:** transparent exploit-presence-first, EPSS-second ranking; export competition-format top-500 list.
- **CVE Investigator:** description, CVSS, current affected products, available historical signals, and optional Granite similarities.
- **Dataset Explorer:** schema and explicit caveats about late NIST updates.

## Query examples

- Which vendor had the most vulnerabilities in 2025?
- Which vendors have the highest KEV listing rates?
- Show the 20 highest-priority CVEs with exploit code.
- What are the most common CWE weakness types?
- How many CVEs were published each year?
- What is CVE-2024-3400?
- Show the monthly history of CVE-2024-3400.

In **local mode**, questions outside the supported patterns show help rather than inventing an answer. **Granite mode** routes queries to the same fixed analytics operations and can phrase the numerical results in natural language.

## Evaluation and limitations

- The prioritization algorithm is a **reproduction of exploit-first → EPSS**, not a claimed improvement over IBM's official 8/500 benchmark.
- KEV is incomplete as a global exploitation ground truth; provided KEV stops in December 2025.
- NIST current records contain temporal leakage; interpret present-day descriptions and CVSS accordingly.
- The semantic retrieval tool is exploratory and similarity is not evidence that a CVE has been or will be exploited.
- The local mode intentionally doesn't translate arbitrary freeform questions into SQL. Granite mode is constrained for security and factual reliability.
- No real IBM API calls are possible until you supply valid credentials.

## Data privacy

All CSV analytics run locally. If IBM watsonx is enabled, the **question and a limited subset of the query result** are sent to IBM for explanation. In Granite similarity mode, descriptions are passed to a locally running embedding model (it downloads model weights on initial run).
