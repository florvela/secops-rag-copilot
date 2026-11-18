from triage_copilot.agents.judge import Judge


class StubLLM:
    def __init__(self, data: dict) -> None:
        self._data = data

    def generate_json(self, prompt: str, system: str | None = None):
        return self._data

    def generate(self, prompt: str, system: str | None = None, temperature: float = 0.2) -> str:
        return ""


def _verdict(data):
    return Judge(StubLLM(data)).assess("report", "context")


def test_hedged_claim_is_not_unsupported():
    # A hedged hypothesis the model wrongly flagged must be dropped -> grounded.
    data = {
        "grounded": False,
        "unsupported": ["The deletion may indicate an attempt to evade detection."],
        "reason": "x",
    }
    assert _verdict(data).grounded is True


def test_factual_unsupported_claim_fails():
    data = {"grounded": False, "unsupported": ["The account is compromised."], "reason": "x"}
    verdict = _verdict(data)
    assert verdict.grounded is False
    assert "compromised" in verdict.reason


def test_grounded_when_no_unsupported():
    assert _verdict({"grounded": True, "unsupported": [], "reason": "ok"}).grounded is True


def test_mixed_keeps_only_factual():
    data = {
        "grounded": False,
        "unsupported": [
            "This could be a brute-force attempt.",  # hedged -> dropped
            "The user is an attacker.",  # factual -> kept
        ],
        "reason": "x",
    }
    assert _verdict(data).grounded is False
