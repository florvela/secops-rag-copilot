from src.ingest.chunker import chunk_section
from src.models import Section


def _section(n_words: int) -> Section:
    return Section(
        text=" ".join(f"w{i}" for i in range(n_words)),
        metadata={
            "doc_id": "d",
            "documento": "D",
            "seccion": "S",
            "pagina": 1,
            "version": "",
            "fuente": "mitre",
            "tecnicas": [],
        },
    )


def test_chunk_overlap_and_size():
    chunks = chunk_section(_section(500), max_tokens=200, overlap=60)
    assert len(chunks) >= 2
    assert all(len(c.text.split()) <= 200 for c in chunks)
    first = chunks[0].text.split()
    second = chunks[1].text.split()
    assert first[-60:] == second[:60]


def test_unique_ids():
    chunks = chunk_section(_section(500), 200, 60)
    assert len({c.id for c in chunks}) == len(chunks)


def test_short_section_single_chunk():
    assert len(chunk_section(_section(10), 200, 60)) == 1
