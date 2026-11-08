from src.eval import metrics

RETRIEVED = ["A", "X", "B"]
RELEVANT = {"A", "B", "C"}


def test_precision_at_k():
    assert metrics.precision_at_k(RETRIEVED, RELEVANT, 2) == 0.5


def test_recall_at_k():
    assert round(metrics.recall_at_k(RETRIEVED, RELEVANT, 3), 4) == round(2 / 3, 4)


def test_mrr():
    assert metrics.mrr(RETRIEVED, RELEVANT) == 1.0


def test_ndcg_in_bounds():
    assert 0.0 <= metrics.ndcg_at_k(RETRIEVED, RELEVANT, 3) <= 1.0
