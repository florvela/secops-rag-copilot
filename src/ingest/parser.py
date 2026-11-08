from __future__ import annotations

from pathlib import Path

from src.models import Section

_FRONT_MATTER_DELIM = "---"


def _parse_front_matter(raw: str) -> tuple[dict, str]:
    lines = raw.splitlines()
    if not lines or lines[0].strip() != _FRONT_MATTER_DELIM:
        return {}, raw

    meta: dict = {}
    body_start = len(lines)
    for i in range(1, len(lines)):
        if lines[i].strip() == _FRONT_MATTER_DELIM:
            body_start = i + 1
            break
        if ":" in lines[i]:
            key, value = lines[i].split(":", 1)
            meta[key.strip()] = value.strip()

    if "tecnicas" in meta:
        meta["tecnicas"] = [t.strip() for t in meta["tecnicas"].split(",") if t.strip()]

    return meta, "\n".join(lines[body_start:])


def _split_sections(body: str) -> list[tuple[str, str]]:
    sections: list[tuple[str, str]] = []
    heading = ""
    buffer: list[str] = []

    def flush() -> None:
        text = "\n".join(buffer).strip()
        if text:
            sections.append((heading, text))

    for line in body.splitlines():
        if line.startswith("#"):
            flush()
            heading = line.lstrip("#").strip()
            buffer = []
        else:
            buffer.append(line)
    flush()
    return sections


def parse_document(path: Path) -> list[Section]:
    raw = path.read_text(encoding="utf-8")
    front, body = _parse_front_matter(raw)

    sections: list[Section] = []
    for page, (heading, text) in enumerate(_split_sections(body), start=1):
        sections.append(
            Section(
                text=f"{heading}\n{text}" if heading else text,
                metadata={
                    "doc_id": path.stem,
                    "documento": front.get("documento", path.stem),
                    "seccion": heading,
                    "pagina": page,
                    "version": front.get("version", ""),
                    "fuente": front.get("fuente", ""),
                    "tecnicas": front.get("tecnicas", []),
                },
            )
        )
    return sections


def parse_corpus(corpus_dir: str | Path) -> list[Section]:
    corpus_path = Path(corpus_dir)
    sections: list[Section] = []
    for path in sorted(corpus_path.glob("*.md")):
        sections.extend(parse_document(path))
    return sections
