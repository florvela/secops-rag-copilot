from src.agents.remediator import Remediator
from src.mcp_tools import build_default_registry


class StubLLM:
    def __init__(self, data: dict) -> None:
        self._data = data

    def generate_json(self, prompt: str, system: str | None = None):
        return self._data

    def generate(self, prompt: str, system: str | None = None, temperature: float = 0.2) -> str:
        return ""


_ALERT = {"severity": "high", "mitre_techniques": [], "description": "d", "matched_event": {}}


def test_propose_filters_unknown_tools_and_args():
    data = {
        "actions": [
            {
                "tool": "block_ip",
                "args": {"ip": "1.2.3.4", "duration_hours": "24", "bogus": "x"},
                "reason": "block the attacker",
            },
            {"tool": "does_not_exist", "args": {}, "reason": "invented"},
        ]
    }
    remediator = Remediator(StubLLM(data), build_default_registry())
    actions = remediator.propose(_ALERT, "report")

    assert len(actions) == 1
    action = actions[0]
    assert action.tool == "block_ip"
    assert action.destructive is True
    assert action.args == {"ip": "1.2.3.4", "duration_hours": "24"}  # 'bogus' dropped


def test_propose_empty_plan():
    remediator = Remediator(StubLLM({"actions": []}), build_default_registry())
    assert remediator.propose(_ALERT, "report") == []
