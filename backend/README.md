# Vulture AI backend (CSV-backed development edition)

This directory contains the constrained CVE assistant. Granite selects from a
fixed set of queries; database SQL is predefined in `db.py`. `app.py` (Streamlit)
is not used by the website.

## Requirements
- Python 3.10+
- Four competition CSVs in `backend/data/`: `vulnerabilities.csv`,
  `affected_products.csv`, `known_exploited.csv`, `scoreboard_2026.csv`

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

If using Granite, install `requirements-ai.txt` and add your IBM credentials
in `backend/.env`; do not commit them. `GET /health` checks liveness;
`GET /ready` triggers dataset load and checks data readiness;
`POST /api/chat` accepts `{ "message": "Which vendor had the most vulnerabilities in 2025?" }`.

## Integration and production blockers

- This data layer is still local-CSV-based and is not ready for the deployed
  Vultr server unless those CSVs are provisioned. Prefer migrating to Tiger
  Cloud after inspecting all table schemas and coverage.
- Put FastAPI behind a private reverse proxy as `/api/*` on the web origin.
- Add authentication / authorization and rate limits before exposing publicly.
- Verify the IBM model ID is actually available in the watsonx project.
- Remove `app.py` from the product after confirming the web dashboard has its
  required functionality; do not delete it if still used for offline QA.
- Name/branding is intentionally not changed in the existing website.
