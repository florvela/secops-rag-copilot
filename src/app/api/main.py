from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

from triage_copilot.llm.client import build_llm
from triage_copilot.investigation.orchestrator import investigate_alert
from app.config import get_settings
from triage_copilot.validation.injection_guard import InjectionGuard
from triage_copilot.validation.input_validation import validate_alert
from triage_copilot.rag.indexing import build_reranker
from app.adapters.local.corpus_loader import load_store
from app.adapters.local.mock_tools import build_default_registry
from app.adapters.local.audit import AuditLog

_state: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    _state["settings"] = settings
    _state["store"] = load_store(settings)
    _state["reranker"] = build_reranker(settings)
    _state["llm"] = build_llm(settings)
    _state["guard"] = InjectionGuard(threshold=settings.pipeline.injection_guard.threshold)
    _state["audit"] = AuditLog(settings.log_dir)
    _state["tools"] = build_default_registry()
    yield
    _state.clear()


app = FastAPI(title="triage-copilot", lifespan=lifespan)


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

    # No approver over HTTP: destructive actions come back as pending_approval
    # instead of being executed autonomously.
    result = investigate_alert(
        alert,
        _state["store"],
        _state["reranker"],
        _state["llm"],
        _state["settings"].pipeline,
        _state["guard"],
        _state["audit"],
        tools=_state["tools"],
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
        "closure": result.closure,
        "actions": [
            {
                "tool": a.tool,
                "args": a.args,
                "destructive": a.destructive,
                "status": a.status,
                "reason": a.reason,
                "result": a.result,
            }
            for a in result.actions
        ],
    }
