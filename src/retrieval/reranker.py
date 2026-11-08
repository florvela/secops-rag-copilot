from __future__ import annotations

from collections import defaultdict

from sentence_transformers import CrossEncoder

from src.models import Chunk


class Reranker:
    def __init__(self, model_name: str) -> None:
        self._model = CrossEncoder(model_name)

    def rerank(
        self,
        query: str,
        chunks: list[Chunk],
        top_final: int,
        per_doc_cap: int,
    ) -> list[tuple[Chunk, float]]:
        if not chunks:
            return []

        scores = self._model.predict([(query, chunk.text) for chunk in chunks])
        ranked = sorted(
            zip(chunks, scores), key=lambda pair: float(pair[1]), reverse=True
        )

        selected: list[tuple[Chunk, float]] = []
        per_doc: dict[str, int] = defaultdict(int)
        for chunk, score in ranked:
            if per_doc[chunk.doc_id] >= per_doc_cap:
                continue
            per_doc[chunk.doc_id] += 1
            selected.append((chunk, float(score)))
            if len(selected) >= top_final:
                break
        return selected
