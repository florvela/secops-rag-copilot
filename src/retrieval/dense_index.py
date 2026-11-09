from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
from sentence_transformers import SentenceTransformer

from src.models import Chunk


def _fingerprint(model_name: str, chunks: list[Chunk]) -> str:
    digest = hashlib.sha256()
    digest.update(model_name.encode("utf-8"))
    for chunk in chunks:
        digest.update(chunk.id.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(chunk.text.encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()


class DenseIndex:
    def __init__(self, chunks: list[Chunk], model_name: str, cache_dir: str | None = ".cache") -> None:
        self._ids = [c.id for c in chunks]
        self._model = SentenceTransformer(model_name)
        self._matrix = self._load_or_encode(chunks, model_name, cache_dir)

    def _load_or_encode(self, chunks: list[Chunk], model_name: str, cache_dir: str | None):
        fingerprint = _fingerprint(model_name, chunks)
        matrix_path = meta_path = None
        if cache_dir:
            base = Path(cache_dir)
            matrix_path = base / "dense_index.npy"
            meta_path = base / "dense_index.json"
            if matrix_path.exists() and meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                    if meta.get("fingerprint") == fingerprint:
                        return np.load(matrix_path)
                except (ValueError, OSError):
                    pass

        matrix = self._model.encode(
            [c.text for c in chunks],
            normalize_embeddings=True,
            convert_to_numpy=True,
        ).astype("float32")

        if cache_dir:
            base.mkdir(parents=True, exist_ok=True)
            np.save(matrix_path, matrix)
            meta_path.write_text(
                json.dumps({"fingerprint": fingerprint, "count": len(chunks)}),
                encoding="utf-8",
            )
        return matrix

    def search(self, query: str, k: int) -> list[tuple[str, float]]:
        vector = self._model.encode(
            [query], normalize_embeddings=True, convert_to_numpy=True
        )[0]
        scores = self._matrix @ vector
        order = np.argsort(scores)[::-1][:k]
        return [(self._ids[i], float(scores[i])) for i in order]
