from __future__ import annotations

from triage_copilot.agents.remediator import ProposedAction


def cli_approver(action: ProposedAction) -> bool:
    """Interactive approver for the CLI: prompt the analyst before a destructive action."""
    prompt = f"\n  Approve destructive action '{action.tool}' {action.args}? [y/N] "
    try:
        answer = input(prompt)
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes"}
