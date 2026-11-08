from __future__ import annotations

import json
from pathlib import Path
from statistics import mean

from src.config import get_settings
from src.eval import metrics
from src.indexing import build_reranker, build_store
from src.retrieval.pipeline import ScoredChunk, retrieve

GOLDENS_PATH = "src/eval/goldens.json"


def _retrieved_docs(scored: list[ScoredChunk]) -> list[str]:
    ordered: list[str] = []
    for item in scored:
        if item.chunk.doc_id not in ordered:
            ordered.append(item.chunk.doc_id)
    return ordered


def evaluate(use_filter: bool = False) -> dict[str, float]:
    settings = get_settings()
    cfg = settings.pipeline
    store = build_store(settings)
    reranker = build_reranker(settings)
    goldens = json.loads(Path(GOLDENS_PATH).read_text(encoding="utf-8"))

    ks = cfg.eval.ks
    k_retrieve = max(ks)
    rows: dict[str, list[float]] = {}
    rr: list[float] = []

    for case in goldens:
        tecnicas = case.get("tecnicas") if use_filter else None
        scored = retrieve(
            store, reranker, case["query"], cfg, tecnicas=tecnicas, top_final=k_retrieve
        )
        retrieved = _retrieved_docs(scored)
        relevant = set(case["relevant_docs"])
        for k in ks:
            rows.setdefault(f"P@{k}", []).append(
                metrics.precision_at_k(retrieved, relevant, k)
            )
            rows.setdefault(f"R@{k}", []).append(
                metrics.recall_at_k(retrieved, relevant, k)
            )
            rows.setdefault(f"nDCG@{k}", []).append(
                metrics.ndcg_at_k(retrieved, relevant, k)
            )
        rr.append(metrics.mrr(retrieved, relevant))

    summary = {name: round(mean(values), 4) for name, values in rows.items()}
    summary["MRR"] = round(mean(rr), 4)
    return summary


def main() -> None:
    print("Baseline (no metadata filter):")
    for name, value in evaluate(use_filter=False).items():
        print(f"  {name:8} {value}")
    print("\nWith MITRE technique filter:")
    for name, value in evaluate(use_filter=True).items():
        print(f"  {name:8} {value}")


if __name__ == "__main__":
    main()
