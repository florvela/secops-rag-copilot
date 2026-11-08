from __future__ import annotations

from src.models import Chunk, Section


def _split_words(text: str) -> list[str]:
    return text.split()


def chunk_section(section: Section, max_tokens: int, overlap: int) -> list[Chunk]:
    words = _split_words(section.text)
    if not words:
        return []

    step = max(1, max_tokens - overlap)
    chunks: list[Chunk] = []
    for index, start in enumerate(range(0, len(words), step)):
        window = words[start : start + max_tokens]
        if not window:
            break
        meta = dict(section.metadata)
        meta["chunk_index"] = index
        chunk_id = f"{meta['doc_id']}_p{meta['pagina']}_c{index}"
        chunks.append(Chunk(id=chunk_id, text=" ".join(window), metadata=meta))
        if start + max_tokens >= len(words):
            break
    return chunks


def chunk_sections(sections: list[Section], max_tokens: int, overlap: int) -> list[Chunk]:
    chunks: list[Chunk] = []
    for section in sections:
        chunks.extend(chunk_section(section, max_tokens, overlap))
    return chunks
