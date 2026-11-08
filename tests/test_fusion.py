from src.retrieval.fusion import reciprocal_rank_fusion


def test_rrf_rewards_consensus():
    fused = reciprocal_rank_fusion([["a", "b", "c"], ["a", "c", "b"]], k=60)
    assert fused[0][0] == "a"


def test_rrf_keeps_all_docs():
    fused = reciprocal_rank_fusion([["a", "b"], ["c"]], k=60)
    assert {doc for doc, _ in fused} == {"a", "b", "c"}
