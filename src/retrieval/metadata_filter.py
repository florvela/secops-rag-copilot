from __future__ import annotations

import re
from collections.abc import Iterable

from src.models import Chunk

_VERSION_NUM = re.compile(r"(\d+(?:\.\d+)?)")


def allowed_ids(
    chunks: Iterable[Chunk],
    tecnicas: list[str] | None = None,
    fuentes: list[str] | None = None,
) -> set[str]:
    tecnicas_set = set(tecnicas) if tecnicas else None
    fuentes_set = set(fuentes) if fuentes else None

    allowed: set[str] = set()
    for chunk in chunks:
        if tecnicas_set is not None and not (set(chunk.tecnicas) & tecnicas_set):
            continue
        if fuentes_set is not None and chunk.metadata.get("fuente") not in fuentes_set:
            continue
        allowed.add(chunk.id)
    return allowed


def version_rank(version: str) -> float:
    match = _VERSION_NUM.search(version or "")
    return float(match.group(1)) if match else 0.0
