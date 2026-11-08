from __future__ import annotations

import json
import re
from dataclasses import dataclass

from src.models import Chunk

# Heuristic indirect-prompt-injection patterns (EN + ES). This is a lightweight,
# explainable stand-in for a classifier such as Meta Prompt Guard 2 (see notas/).
_PATTERNS = [
    r"ignore (all|any|the)? ?(previous|prior)? ?(instructions|context)",
    r"disregard (the|all|any|previous).*(instruction|policy|rule)",
    r"you are now",
    r"\bsystem\s*:",
    r"override.*(policy|instruction|rule)",
    r"mark this (event|alert) as (safe|benign)",
    r"close it with no action",
    r"olvid[ao].*(instruccion|indicacion|regla)",
    r"ignor[ao].*(instruccion|indicacion|regla)",
]
_COMPILED = [re.compile(pattern, re.IGNORECASE) for pattern in _PATTERNS]


def score_text(text: str) -> float:
    if not text:
        return 0.0
    matches = sum(1 for pattern in _COMPILED if pattern.search(text))
    return min(1.0, matches / 2.0)


@dataclass
class InjectionGuard:
    threshold: float

    def is_flagged(self, text: str) -> bool:
        return score_text(text) >= self.threshold

    def screen_chunks(
        self, chunks: list[Chunk]
    ) -> tuple[list[Chunk], list[tuple[Chunk, float]]]:
        clean: list[Chunk] = []
        flagged: list[tuple[Chunk, float]] = []
        for chunk in chunks:
            score = score_text(chunk.text)
            if score >= self.threshold:
                flagged.append((chunk, score))
            else:
                clean.append(chunk)
        return clean, flagged

    def score_event(self, matched_event: dict) -> float:
        return score_text(json.dumps(matched_event))
