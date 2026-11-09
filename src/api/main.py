from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

from src.agents.llm import build_llm
from src.agents.orchestrator import investigate_alert
from src.config import get_settings
from src.guardrails.injection_guard import InjectionGuard
from src.guardrails.input_validation import validate_alert
from src.indexing import build_reranker, build_store
from src.security.audit import AuditLog

_state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    _state["settings"] = settings
    _state["store"] = build_store(settings)
    _state["reranker"] = build_reranker(settings)
    _state["llm"] = build_llm(settings)
    _state["guard"] = InjectionGuard(threshold=settings.pipeline.injection_guard.threshold)
    _state["audit"] = AuditLog(settings.log_dir)
    yield
    _state.clear()


app = FastAPI(title="secops-rag-copilot", lifespan=lifespan)


@app.get("/health")
def health() -> dict:
    store = _state.get("store")
    return {"status": "ok", "chunks": len(store.chunks) if store else 0}


@app.post("/investigate")
def investigate(payload: dict) -> dict:
    try:
        alert = validate_alert(payload).model_dump()
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=[{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()],
        )

    result = investigate_alert(
        alert,
        _state["store"],
        _state["reranker"],
        _state["llm"],
        _state["settings"].pipeline,
        _state["guard"],
        _state["audit"],
    )
    return {
        "report": result.report,
        "grounded": result.grounded,
        "grounded_reason": result.grounded_reason,
        "citations": result.citations,
        "iterations": result.iterations,
        "used_retrieval": result.used_retrieval,
        "flagged_chunks": result.flagged_chunks,
        "execution_id": result.execution_id,
    }
