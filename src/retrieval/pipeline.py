from __future__ import annotations

from dataclasses import dataclass

from src.config import PipelineConfig
from src.models import Chunk
from src.retrieval.fusion import reciprocal_rank_fusion
from src.retrieval.metadata_filter import allowed_ids


@dataclass
class ScoredChunk:
    chunk: Chunk
    score: float


def _fused_candidates(
    store,
    query: str,
    cfg: PipelineConfig,
    tecnicas: list[str] | None,
    fuentes: list[str] | None,
) -> list[Chunk]:
    r = cfg.retrieval
    bm25_hits = store.bm25.search(query, r.top_retrieve)
    dense_hits = store.dense.search(query, r.top_retrieve)

    allow = None
    if tecnicas or fuentes:
        allow = allowed_ids(store.chunks.values(), tecnicas=tecnicas, fuentes=fuentes)

    def filtered_ids(hits: list[tuple[str, float]]) -> list[str]:
        ids = [doc_id for doc_id, _ in hits]
        return ids if allow is None else [i for i in ids if i in allow]

    fused = reciprocal_rank_fusion(
        [filtered_ids(bm25_hits), filtered_ids(dense_hits)], r.rrf_k
    )
    return [store.chunks[i] for i, _ in fused if i in store.chunks]


def retrieve(
    store,
    reranker,
    query: str,
    cfg: PipelineConfig,
    tecnicas: list[str] | None = None,
    fuentes: list[str] | None = None,
    top_final: int | None = None,
) -> list[ScoredChunk]:
    limit = top_final if top_final is not None else cfg.retrieval.top_final
    candidates = _fused_candidates(store, query, cfg, tecnicas, fuentes)
    ranked = reranker.rerank(query, candidates, limit, cfg.retrieval.per_doc_cap)
    return [ScoredChunk(chunk=chunk, score=score) for chunk, score in ranked]


def retrieve_stages(
    store,
    reranker,
    query: str,
    cfg: PipelineConfig,
    tecnicas: list[str] | None = None,
    fuentes: list[str] | None = None,
    top_final: int | None = None,
) -> tuple[list[Chunk], list[ScoredChunk]]:
    """Return the fused candidates (pre re-ranking) and the reranked result (post)."""
    limit = top_final if top_final is not None else cfg.retrieval.top_final
    candidates = _fused_candidates(store, query, cfg, tecnicas, fuentes)
    ranked = reranker.rerank(query, candidates, limit, cfg.retrieval.per_doc_cap)
    post = [ScoredChunk(chunk=chunk, score=score) for chunk, score in ranked]
    return candidates, post
