from __future__ import annotations

from dataclasses import dataclass

from triage_copilot.config import Settings
from triage_copilot.investigation.models import Chunk, Section
from triage_copilot.rag.bm25_index import BM25Index
from triage_copilot.rag.chunking import chunk_sections
from triage_copilot.rag.dense_index import DenseIndex
from triage_copilot.rag.rerank import Reranker


@dataclass
class RagStore:
    chunks: dict[str, Chunk]
    bm25: BM25Index
    dense: DenseIndex


def build_store(
    sections: list[Section], settings: Settings, cache_dir: str | None = ".cache"
) -> RagStore:
    cfg = settings.pipeline
    chunks = chunk_sections(sections, cfg.chunking.max_tokens, cfg.chunking.overlap)
    return RagStore(
        chunks={c.id: c for c in chunks},
        bm25=BM25Index(chunks),
        dense=DenseIndex(chunks, cfg.embedding.model_name, cache_dir=cache_dir),
    )


def build_reranker(settings: Settings) -> Reranker:
    return Reranker(settings.pipeline.reranker.model_name)
