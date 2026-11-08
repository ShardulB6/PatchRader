"""FastAPI interface for the PatchRader constrained CVE analytics assistant.

Runs independently from the TanStack Start frontend. For production, put this
service behind the application's reverse proxy and configure allowed origins.
The DataStore is currently CSV-backed; Tiger Cloud migration is separate.
"""

import json
import logging
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from threading import Lock

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from analyst import classify, execute_plan, grounded_answer, set_vendor_names, watsonx_enabled
from db import DataStore
from impact import top500_impact

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


# Each AI answer makes two watsonx.ai calls against a small Lite token
# allowance, so the public endpoint limits each visitor and the whole day.
# Past the daily cap, answers still work but skip watsonx.ai.
CHAT_PER_MINUTE = max(1, int(os.getenv("CHAT_PER_MINUTE", "6")))
WATSONX_DAILY_LIMIT = int(os.getenv("WATSONX_DAILY_LIMIT", "100"))
_limit_lock = Lock()
_recent = defaultdict(deque)
# systemd sets STATE_DIRECTORY, so the daily count survives restarts and deploys.
_state_dir = os.getenv("STATE_DIRECTORY")
_AI_COUNT_FILE = Path(_state_dir) / "watsonx_daily.json" if _state_dir else None


def _load_ai_day():
    try:
        saved = json.loads(_AI_COUNT_FILE.read_text())
        return {"date": saved["date"], "count": int(saved["count"])}
    except Exception:
        return {"date": None, "count": 0}


_ai_day = _load_ai_day() if _AI_COUNT_FILE else {"date": None, "count": 0}


def _client_ip(request: Request) -> str:
    host = request.client.host if request.client else "unknown"
    # Caddy replaces X-Forwarded-For with the real client address, so trust it
    # only when the request came through the local proxy.
    forwarded = request.headers.get("x-forwarded-for")
    if host in ("127.0.0.1", "::1") and forwarded:
        return forwarded.split(",")[-1].strip()
    return host


def _allow_request(ip: str) -> bool:
    now = time.monotonic()
    with _limit_lock:
        for key in [k for k, times in _recent.items() if times[-1] < now - 60]:
            del _recent[key]
        times = _recent[ip]
        while times and times[0] < now - 60:
            times.popleft()
        if len(times) >= CHAT_PER_MINUTE:
            return False
        times.append(now)
        return True


def _take_ai_quota() -> bool:
    today = datetime.now(timezone.utc).date().isoformat()
    with _limit_lock:
        if _ai_day["date"] != today:
            _ai_day.update(date=today, count=0)
        if _ai_day["count"] >= WATSONX_DAILY_LIMIT:
            return False
        _ai_day["count"] += 1
        if _AI_COUNT_FILE:
            try:
                _AI_COUNT_FILE.write_text(json.dumps(_ai_day))
            except OSError:
                logger.exception("Could not save the watsonx.ai daily count")
        return True


@lru_cache(maxsize=1)
def _cached_store():
    configured = Path(os.getenv("PATCHRADAR_DATA_DIR", "../data")).expanduser()
    data_dir = configured if configured.is_absolute() else BASE_DIR / configured
    store = DataStore(data_dir)
    set_vendor_names(store.vendor_names())
    return store


def get_store():
    with _store_lock:
        return _cached_store()


def _top500_path() -> Path:
    """top500.csv in the project root, or TOP500_PATH if set."""
    configured = (os.getenv("TOP500_PATH") or "").strip()
    if not configured:
        return BASE_DIR.parent / "top500.csv"
    p = Path(configured).expanduser()
    return p if p.is_absolute() else BASE_DIR.parent / p


_top500_cache = {}


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
def chat(request: ChatRequest, http_request: Request):
    if not _allow_request(_client_ip(http_request)):
        raise HTTPException(status_code=429, detail="Too many questions; wait a minute")
    try:
        store = get_store()
        use_ai = watsonx_enabled() and _take_ai_quota()
        plan, mode = classify(request.message, use_ai=use_ai)
        cves = []
        table, note = execute_plan(store, plan, request.message, cards=cves)
        answer, summary, wrote_with_ai = grounded_answer(request.message, table, note, use_ai)

        # Convert pandas values to JSON-safe types (NaN -> null) and return
        # actual records rather than a JSON string embedded inside JSON.
        rows = json.loads(table.to_json(orient="records", date_format="iso"))
        return {
            "answer": answer,
            # Label the answer by who wrote its text, which is what the page shows.
            "mode": "IBM watsonx.ai" if wrote_with_ai else "Local intent router",
            "operation": plan["tool"],
            "note": note,
            "rows": rows,
            # Optional extras the page draws as cards; it falls back to answer and rows.
            "summary": summary,
            "cves": cves,
        }
    except Exception:
        logger.exception("Chat request failed")
        raise HTTPException(status_code=500, detail="Chat request failed")


@app.get("/api/impact/top500")
def impact_top500(http_request: Request):
    """Impact profiles for top500.csv in the project root, if it exists."""
    if not _allow_request(_client_ip(http_request)):
        raise HTTPException(status_code=429, detail="Too many requests; wait a minute")
    path = _top500_path()
    if not path.is_file():
        raise HTTPException(status_code=404, detail="top500.csv not found in the project root")
    try:
        key = path.stat().st_mtime_ns
        if _top500_cache.get("key") != key:
            _top500_cache.update(key=key, data=top500_impact(get_store(), path))
        return _top500_cache["data"]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        logger.exception("Top 500 impact failed")
        raise HTTPException(status_code=500, detail="Impact analysis failed")
