
from pathlib import Path
from functools import lru_cache

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from db import DataStore
from analyst import (
    classify,
    execute_plan,
    grounded_answer,
    watsonx_enabled,
)

app = FastAPI(title="PatchRadar API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

BASE = Path(__file__).resolve().parent

@lru_cache(maxsize=1)
def get_store():
    return DataStore(BASE / "data")

class ChatRequest(BaseModel):
    message: str

@app.post("/api/chat")
def chat(request: ChatRequest):
    try:
        store = get_store()
        use_ai = watsonx_enabled()

        plan, mode = classify(request.message, use_ai)
        table, note = execute_plan(store, plan)
        answer = grounded_answer(
            request.message, table, note, use_ai
        )

        return {
            "answer": answer,
            "mode": mode,
            "operation": plan["tool"],
            "note": note,
            "rows": table.to_json(orient="records"),
        }
    except Exception as exc:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=str(exc)
        ) from exc