from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
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


class Settings(BaseModel):
    config_path: Path
    log_dir: Path
    llm: LLMSettings
    hf_token: str | None
    pipeline: PipelineConfig


def _load_pipeline(config_path: Path) -> PipelineConfig:
    data = json.loads(config_path.read_text(encoding="utf-8"))
    return PipelineConfig.model_validate(data)


@lru_cache
def get_settings() -> Settings:
    load_dotenv()
    config_path = Path(os.getenv("CONFIG_PATH", "config/config.json"))
    return Settings(
        config_path=config_path,
        log_dir=Path(os.getenv("LOG_DIR", "logs")),
        llm=LLMSettings(
            backend=os.getenv("LLM_BACKEND", "native"),
            provider=os.getenv("LLM_PROVIDER", "ollama"),
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            model=os.getenv("OLLAMA_MODEL", "llama3.1:8b"),
        ),
        hf_token=os.getenv("HF_TOKEN") or None,
        pipeline=_load_pipeline(config_path),
    )


if __name__ == "__main__":
    print(get_settings().model_dump_json(indent=2))
