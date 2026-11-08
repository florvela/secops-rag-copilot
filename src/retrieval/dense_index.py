from __future__ import annotations

import numpy as np
from sentence_transformers import SentenceTransformer

from src.models import Chunk


class DenseIndex:
    def __init__(self, chunks: list[Chunk], model_name: str) -> None:
        self._ids = [c.id for c in chunks]
        self._model = SentenceTransformer(model_name)
        self._matrix = self._model.encode(
            [c.text for c in chunks],
            normalize_embeddings=True,
            convert_to_numpy=True,
        )

    def search(self, query: str, k: int) -> list[tuple[str, float]]:
        vector = self._model.encode(
            [query], normalize_embeddings=True, convert_to_numpy=True
        )[0]
        scores = self._matrix @ vector
        order = np.argsort(scores)[::-1][:k]
        return [(self._ids[i], float(scores[i])) for i in order]
