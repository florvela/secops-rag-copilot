from __future__ import annotations

from dataclasses import dataclass

from src.config import PipelineConfig
from src.guardrails.injection_guard import InjectionGuard, score_text
from src.models import Chunk
from src.retrieval.pipeline import ScoredChunk, retrieve


@dataclass
class Evidence:
    query: str
    scored: list[ScoredChunk]
    flagged: list[tuple[Chunk, float]]
    top_score: float
    sufficient: bool


def format_citation(chunk: Chunk) -> str:
    meta = chunk.metadata
    version = f" {meta['version']}" if meta.get("version") else ""
    return f"[{meta['documento']} — {meta['seccion']} (p.{meta['pagina']}{version})]"


def build_context(scored: list[ScoredChunk]) -> str:
    return "\n\n".join(f"{format_citation(s.chunk)}\n{s.chunk.text}" for s in scored)


class Investigator:
    def __init__(self, store, reranker, cfg: PipelineConfig, guard: InjectionGuard) -> None:
        self._store = store
        self._reranker = reranker
        self._cfg = cfg
        self._guard = guard

    def investigate(self, query: str, tecnicas: list[str] | None = None) -> Evidence:
        results = retrieve(self._store, self._reranker, query, self._cfg, tecnicas=tecnicas)

        clean: list[ScoredChunk] = []
        flagged: list[tuple[Chunk, float]] = []
        for item in results:
            if self._guard.is_flagged(item.chunk.text):
                flagged.append((item.chunk, score_text(item.chunk.text)))
            else:
                clean.append(item)

        top_score = clean[0].score if clean else float("-inf")
        sufficient = bool(clean) and top_score >= self._cfg.evidence.min_rerank_score
        return Evidence(query, clean, flagged, top_score, sufficient)
