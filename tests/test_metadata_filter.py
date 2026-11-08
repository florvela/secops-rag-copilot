from src.models import Chunk
from src.retrieval.metadata_filter import allowed_ids, version_rank


def _chunk(cid: str, tecnicas: list[str], fuente: str) -> Chunk:
    return Chunk(id=cid, text="x", metadata={"doc_id": cid, "tecnicas": tecnicas, "fuente": fuente})


def test_filter_by_technique():
    chunks = [_chunk("a", ["T1078.004"], "mitre"), _chunk("b", ["T1110.001"], "mitre")]
    assert allowed_ids(chunks, tecnicas=["T1078.004"]) == {"a"}


def test_filter_by_source():
    chunks = [_chunk("a", ["T1"], "mitre"), _chunk("b", ["T1"], "playbook")]
    assert allowed_ids(chunks, fuentes=["playbook"]) == {"b"}


def test_version_rank():
    assert version_rank("ATT&CK v15") == 15.0
    assert version_rank("2.1") == 2.1
    assert version_rank("final") == 0.0
