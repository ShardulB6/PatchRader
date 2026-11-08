"""FastAPI interface for the PatchRader constrained CVE analytics assistant.

Runs independently from the TanStack Start frontend. For production, put this
service behind the application's reverse proxy and configure allowed origins.
The DataStore is currently CSV-backed; Tiger Cloud migration is separate.
"""

import json
import logging
import os
from functools import lru_cache
from pathlib import Path
from threading import Lock

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from analyst import classify, execute_plan, grounded_answer, watsonx_enabled
from db import DataStore

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
logger = logging.getLogger(__name__)

# A comma-separated list of complete origins, e.g.
# CORS_ORIGINS=https://example.com,https://www.example.com
allowed_origins = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "CORS_ORIGINS", "http://localhost:3001,http://127.0.0.1:3001"
    ).split(",")
    if origin.strip()
]

app = FastAPI(title="Vulnerability Analytics API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Only one thread should initialize the (potentially expensive) CSV store.
_store_lock = Lock()


@lru_cache(maxsize=1)
def _cached_store():
    configured = Path(os.getenv("PATCHRADAR_DATA_DIR", "../data")).expanduser()
    data_dir = configured if configured.is_absolute() else BASE_DIR / configured
    return DataStore(data_dir)


def get_store():
    with _store_lock:
        return _cached_store()


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)

    @field_validator("message")
    @classmethod
    def non_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Message cannot be blank")
        return value


@app.get("/health")
def health():
    """Liveness only. Does not imply database/model availability."""
    return {"status": "ok"}


@app.get("/ready")
def ready():
    """Check that the local dataset can be initialized and queried."""
    try:
        store = get_store()
        store.query("SELECT 1 AS ok")
    except Exception:
        logger.exception("Readiness check failed")
        raise HTTPException(status_code=503, detail="Data service unavailable")
    return {"status": "ready", "watsonx_configured": watsonx_enabled()}


@app.post("/api/chat")
def chat(request: ChatRequest):
    try:
        store = get_store()
        use_ai = watsonx_enabled()
        plan, mode = classify(request.message, use_ai=use_ai)
        table, note = execute_plan(store, plan)
        answer = grounded_answer(request.message, table, note, use_ai)

        # Convert pandas values to JSON-safe types (NaN -> null) and return
        # actual records rather than a JSON string embedded inside JSON.
        rows = json.loads(table.to_json(orient="records", date_format="iso"))
        return {
            "answer": answer,
            "mode": mode,
            "operation": plan["tool"],
            "note": note,
            "rows": rows,
        }
    except Exception:
        logger.exception("Chat request failed")
        raise HTTPException(status_code=500, detail="Chat request failed")
