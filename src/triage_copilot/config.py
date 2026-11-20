from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict


class Chunking(BaseModel):
    max_tokens: int
    overlap: int


class ModelRef(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    model_name: str


class Retrieval(BaseModel):
    top_retrieve: int
    top_final: int
    rrf_k: int
    per_doc_cap: int


class Evidence(BaseModel):
    min_rerank_score: float


class InjectionGuard(BaseModel):
    threshold: float
    max_tokens_segment: int


class Orchestration(BaseModel):
    max_iterations: int


class Eval(BaseModel):
    ks: list[int]


class PipelineConfig(BaseModel):
    chunking: Chunking
    embedding: ModelRef
    reranker: ModelRef
    retrieval: Retrieval
    evidence: Evidence
    injection_guard: InjectionGuard
    orchestration: Orchestration
    eval: Eval


class LLMSettings(BaseModel):
    backend: str
    provider: str
    base_url: str
    model: str
    # Bedrock-only (ignored by the Ollama backends).
    region: str | None = None
    guardrail_id: str | None = None
    guardrail_version: str | None = None
    max_tokens: int = 1024
    # Optional per-role model map (e.g. {"report": "...pro...", "planner": "...micro..."}).
    models: dict[str, str] = {}


class Settings(BaseModel):
    config_path: Path
    log_dir: Path
    llm: LLMSettings
    hf_token: str | None
    pipeline: PipelineConfig
