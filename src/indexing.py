from __future__ import annotations

from dataclasses import dataclass

from src.config import Settings
from src.ingest.chunker import chunk_sections
from src.ingest.parser import parse_corpus
from src.models import Chunk
from src.retrieval.bm25_index import BM25Index
from src.retrieval.dense_index import DenseIndex
from src.retrieval.reranker import Reranker


@dataclass
class RagStore:
    chunks: dict[str, Chunk]
    bm25: BM25Index
    dense: DenseIndex


def build_store(
    settings: Settings, corpus_dir: str = "corpus", cache_dir: str | None = ".cache"
) -> RagStore:
    cfg = settings.pipeline
    sections = parse_corpus(corpus_dir)
    chunks = chunk_sections(sections, cfg.chunking.max_tokens, cfg.chunking.overlap)
    return RagStore(
        chunks={c.id: c for c in chunks},
        bm25=BM25Index(chunks),
        dense=DenseIndex(chunks, cfg.embedding.model_name, cache_dir=cache_dir),
    )


def build_reranker(settings: Settings) -> Reranker:
    return Reranker(settings.pipeline.reranker.model_name)
