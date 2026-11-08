from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Section:
    text: str
    metadata: dict[str, Any]


@dataclass
class Chunk:
    id: str
    text: str
    metadata: dict[str, Any]
    embedding: list[float] | None = field(default=None, repr=False)

    @property
    def doc_id(self) -> str:
        return self.metadata["doc_id"]

    @property
    def tecnicas(self) -> list[str]:
        return self.metadata.get("tecnicas", [])
