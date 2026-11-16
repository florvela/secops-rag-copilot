"""Human-in-the-loop guardrail for remediation actions.

Destructive tools (disable a credential, block an IP, revoke sessions, isolate a host)
must not run autonomously — this mitigates "excessive agency". Each destructive action
is gated by an approver; non-destructive actions (notify, create a ticket) run directly.
Every decision is written to the audit log.

- ``approve=None`` (e.g. the API): destructive actions are returned as ``pending_approval``
  and never executed.
- ``approve=<callable>`` (e.g. the interactive CLI): the callback decides per action;
  declined actions are ``skipped``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from src.agents.remediator import ProposedAction
from src.mcp_tools.registry import ToolRegistry
from src.security.audit import AuditLog

logger = logging.getLogger(__name__)

Approver = Callable[[ProposedAction], bool]


@dataclass
class ActionOutcome:
    tool: str
    args: dict = field(default_factory=dict)
    destructive: bool = False
    status: str = "executed"  # executed | pending_approval | skipped
    reason: str = ""
    result: dict[str, Any] | None = None


def run_with_approval(
    actions: list[ProposedAction],
    registry: ToolRegistry,
    audit: AuditLog,
    execution_id: str,
    approve: Approver | None = None,
) -> list[ActionOutcome]:
    outcomes: list[ActionOutcome] = []
    for action in actions:
        tool = registry.get(action.tool)
        if tool is None:
            continue

        if tool.destructive:
            if approve is None:
                logger.info("[%s] action pending approval: %s %s", execution_id, action.tool, action.args)
                audit.log(execution_id, "action_pending_approval", tool=action.tool, args=action.args)
                outcomes.append(_outcome(action, tool.destructive, "pending_approval"))
                continue
            if not approve(action):
                logger.info("[%s] action declined: %s", execution_id, action.tool)
                audit.log(execution_id, "action_declined", tool=action.tool, args=action.args)
                outcomes.append(_outcome(action, tool.destructive, "skipped"))
                continue

        result = tool.run(action.args)
        logger.info(
            "[%s] action executed: %s %s (destructive=%s)",
            execution_id,
            action.tool,
            action.args,
            tool.destructive,
        )
        audit.log(
            execution_id,
            "action_executed",
            tool=action.tool,
            args=action.args,
            destructive=tool.destructive,
        )
        outcomes.append(_outcome(action, tool.destructive, "executed", result))
    return outcomes


def _outcome(
    action: ProposedAction,
    destructive: bool,
    status: str,
    result: dict[str, Any] | None = None,
) -> ActionOutcome:
    return ActionOutcome(
        tool=action.tool,
        args=action.args,
        destructive=destructive,
        status=status,
        reason=action.reason,
        result=result,
    )


def cli_approver(action: ProposedAction) -> bool:
    """Interactive approver for the CLI: prompt the analyst before a destructive action."""
    prompt = f"\n  Approve destructive action '{action.tool}' {action.args}? [y/N] "
    try:
        answer = input(prompt)
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes"}
