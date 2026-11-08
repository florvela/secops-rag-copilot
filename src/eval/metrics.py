from __future__ import annotations

import math
from collections.abc import Sequence


def _hits(retrieved: Sequence[str], relevant: set[str], k: int) -> list[int]:
    return [1 if doc in relevant else 0 for doc in retrieved[:k]]


def precision_at_k(retrieved: Sequence[str], relevant: set[str], k: int) -> float:
    if k == 0:
        return 0.0
    return sum(_hits(retrieved, relevant, k)) / k


def recall_at_k(retrieved: Sequence[str], relevant: set[str], k: int) -> float:
    if not relevant:
        return 0.0
    return sum(_hits(retrieved, relevant, k)) / len(relevant)


def dcg_at_k(retrieved: Sequence[str], relevant: set[str], k: int) -> float:
    return sum(
        hit / math.log2(rank + 2)
        for rank, hit in enumerate(_hits(retrieved, relevant, k))
    )


def ndcg_at_k(retrieved: Sequence[str], relevant: set[str], k: int) -> float:
    ideal = sum(1.0 / math.log2(rank + 2) for rank in range(min(len(relevant), k)))
    if ideal == 0:
        return 0.0
    return dcg_at_k(retrieved, relevant, k) / ideal


def mrr(retrieved: Sequence[str], relevant: set[str]) -> float:
    for rank, doc in enumerate(retrieved, start=1):
        if doc in relevant:
            return 1.0 / rank
    return 0.0
