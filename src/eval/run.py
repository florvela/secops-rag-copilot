from __future__ import annotations

import json
from pathlib import Path
from statistics import mean

from src.config import get_settings
from src.eval import metrics
from src.indexing import build_reranker, build_store
from src.models import Chunk
from src.retrieval.pipeline import ScoredChunk, retrieve_stages

GOLDENS_PATH = "src/eval/goldens.json"


def _unique_docs(doc_ids: list[str]) -> list[str]:
    ordered: list[str] = []
    for doc_id in doc_ids:
        if doc_id not in ordered:
            ordered.append(doc_id)
    return ordered


def _docs_from_chunks(chunks: list[Chunk]) -> list[str]:
    return _unique_docs([c.doc_id for c in chunks])


def _docs_from_scored(scored: list[ScoredChunk]) -> list[str]:
    return _unique_docs([s.chunk.doc_id for s in scored])


def evaluate(use_filter: bool = False) -> dict[str, float]:
    settings = get_settings()
    cfg = settings.pipeline
    store = build_store(settings)
    reranker = build_reranker(settings)
    goldens = json.loads(Path(GOLDENS_PATH).read_text(encoding="utf-8"))

    ks = cfg.eval.ks
    k_retrieve = max(ks)
    rows: dict[str, list[float]] = {}

    for case in goldens:
        tecnicas = case.get("tecnicas") if use_filter else None
        pre_chunks, post_scored = retrieve_stages(
            store, reranker, case["query"], cfg, tecnicas=tecnicas, top_final=k_retrieve
        )
        pre = _docs_from_chunks(pre_chunks)
        post = _docs_from_scored(post_scored)
        relevant = set(case["relevant_docs"])

        for k in ks:
            rows.setdefault(f"P@{k} pre", []).append(metrics.precision_at_k(pre, relevant, k))
            rows.setdefault(f"P@{k} post", []).append(metrics.precision_at_k(post, relevant, k))
            rows.setdefault(f"R@{k} pre", []).append(metrics.recall_at_k(pre, relevant, k))
            rows.setdefault(f"R@{k} post", []).append(metrics.recall_at_k(post, relevant, k))
            rows.setdefault(f"nDCG@{k} pre", []).append(metrics.ndcg_at_k(pre, relevant, k))
            rows.setdefault(f"nDCG@{k} post", []).append(metrics.ndcg_at_k(post, relevant, k))
        rows.setdefault("MRR pre", []).append(metrics.mrr(pre, relevant))
        rows.setdefault("MRR post", []).append(metrics.mrr(post, relevant))

    return {name: round(mean(values), 4) for name, values in rows.items()}


def _print_table(summary: dict[str, float]) -> None:
    names = sorted({name.rsplit(" ", 1)[0] for name in summary})
    print(f"  {'metric':10} {'pre':>8} {'post':>8}")
    for name in names:
        pre = summary.get(f"{name} pre", 0.0)
        post = summary.get(f"{name} post", 0.0)
        print(f"  {name:10} {pre:>8} {post:>8}")


def main() -> None:
    print("Baseline (no metadata filter):")
    _print_table(evaluate(use_filter=False))
    print("\nWith MITRE technique filter:")
    _print_table(evaluate(use_filter=True))


if __name__ == "__main__":
    main()
