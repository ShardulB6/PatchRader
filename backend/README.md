# PatchRader AI backend (CSV-backed development edition)

This directory contains the constrained CVE assistant. A model on IBM watsonx.ai
selects from a fixed set of queries; database SQL is predefined in `db.py`.

## Requirements
- Python 3.10+
- The competition CSVs in the repo-root `data/` folder. Download them with
  `python3 scripts/fetch_data.py` from the repo root.

## Local setup

From `backend/`:

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
cp .env.example .env # Windows PowerShell: Copy-Item .env.example .env
python -m uvicorn api:app --reload --port 8000
```

To use watsonx.ai, install `requirements-ai.txt` and add your IBM credentials
in `backend/.env`; do not commit them. Without credentials the assistant still
works, using a keyword router and plain-text answers.

The default settings use a Toronto (ca-tor) project with
`meta-llama/llama-3-3-70b-instruct`, because Toronto does not offer Granite chat
models. For Granite chat, use a us-south project and `ibm/granite-4-h-small`. `GET /health` checks liveness;
`GET /ready` triggers dataset load and checks data readiness;
`POST /api/chat` accepts `{ "message": "Which vendor had the most vulnerabilities in 2025?" }`.

## Integration and production blockers

- This data layer is still local-CSV-based and is not ready for the deployed
  Vultr server unless those CSVs are provisioned. Prefer migrating to Tiger
  Cloud after inspecting all table schemas and coverage.
- Put FastAPI behind a private reverse proxy as `/api/*` on the web origin.
- Add authentication / authorization and rate limits before exposing publicly.
- Verify the model ID is available in your watsonx.ai region.
- Name/branding is intentionally not changed in the existing website.
