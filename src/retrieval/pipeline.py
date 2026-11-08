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


def retrieve(
    store,
    reranker,
    query: str,
    cfg: PipelineConfig,
    tecnicas: list[str] | None = None,
    fuentes: list[str] | None = None,
    top_final: int | None = None,
) -> list[ScoredChunk]:
    r = cfg.retrieval
    limit = top_final if top_final is not None else r.top_final

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
    candidates = [store.chunks[i] for i, _ in fused if i in store.chunks]
    ranked = reranker.rerank(query, candidates, limit, r.per_doc_cap)
    return [ScoredChunk(chunk=chunk, score=score) for chunk, score in ranked]
