from triage_copilot.agents.remediator import ProposedAction
from triage_copilot.investigation.approval import run_with_approval
from app.adapters.local.mock_tools import build_default_registry


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def log(self, execution_id: str, event: str, **fields) -> dict:
        self.events.append((event, fields))
        return {}


def _run(action, approve):
    registry = build_default_registry()
    audit = FakeAudit()
    outcomes = run_with_approval([action], registry, audit, "exec1", approve=approve)
    return outcomes[0], audit


def test_destructive_pending_without_approver():
    action = ProposedAction(tool="block_ip", args={"ip": "1.1.1.1"}, destructive=True)
    outcome, audit = _run(action, approve=None)
    assert outcome.status == "pending_approval"
    assert outcome.result is None
    assert ("action_pending_approval", {"tool": "block_ip", "args": {"ip": "1.1.1.1"}}) in audit.events


def test_destructive_executed_when_approved():
    action = ProposedAction(tool="block_ip", args={"ip": "1.1.1.1"}, destructive=True)
    outcome, _ = _run(action, approve=lambda a: True)
    assert outcome.status == "executed"
    assert outcome.result["status"] == "simulated"


def test_destructive_skipped_when_declined():
    action = ProposedAction(tool="revoke_sessions", args={"principal": "u"}, destructive=True)
    outcome, _ = _run(action, approve=lambda a: False)
    assert outcome.status == "skipped"
    assert outcome.result is None


def test_non_destructive_runs_without_approval():
    action = ProposedAction(tool="create_ticket", args={"title": "t", "severity": "high"})
    outcome, _ = _run(action, approve=None)
    assert outcome.status == "executed"
    assert outcome.result["action"] == "create_ticket"
