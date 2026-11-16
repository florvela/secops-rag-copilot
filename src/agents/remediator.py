from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from src.agents.llm import LLMUnavailable, LocalLLM
from src.mcp_tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

_SYSTEM = (
    "You are a SOC remediation planner. You choose response actions from the available "
    "tools only. Output strict JSON only, no prose."
)


@dataclass
class ProposedAction:
    tool: str
    args: dict = field(default_factory=dict)
    destructive: bool = False
    reason: str = ""


class Remediator:
    """Third agent: turns the investigation report into a proposed response plan.

    It selects actions from the available tools (function-calling style) but never
    executes them — execution is gated by the human-in-the-loop guardrail.
    """

    def __init__(self, llm: LocalLLM, registry: ToolRegistry) -> None:
        self._llm = llm
        self._registry = registry

    def propose(self, alert: dict, report: str) -> list[ProposedAction]:
        data = self._generate(alert, report)
        logger.debug("thinking (remediation): %s", json.dumps(data)[:1500])
        # The model may return {"actions": [...]} or a bare [...] list.
        if isinstance(data, dict):
            raw_actions = data.get("actions", [])
        elif isinstance(data, list):
            raw_actions = data
        else:
            raw_actions = []
        actions: list[ProposedAction] = []
        for item in raw_actions:
            if not isinstance(item, dict):
                continue
            tool = self._registry.get(str(item.get("tool", "")).strip())
            if tool is None:
                continue  # ignore anything the model invented
            allowed = set(tool.parameters.get("properties", {}))
            raw_args = item.get("args")
            args = (
                {k: v for k, v in raw_args.items() if k in allowed}
                if isinstance(raw_args, dict)
                else {}
            )
            actions.append(
                ProposedAction(
                    tool=tool.name,
                    args=args,
                    destructive=tool.destructive,
                    reason=str(item.get("reason", "")).strip(),
                )
            )
        return actions

    def _generate(self, alert: dict, report: str) -> dict:
        prompt = self._prompt(alert, report)
        try:
            return self._llm.generate_json(prompt, system=_SYSTEM)
        except (ValueError, KeyError, TypeError):
            # Small local models occasionally emit malformed JSON; retry once.
            try:
                return self._llm.generate_json(prompt, system=_SYSTEM)
            except (ValueError, KeyError, TypeError) as exc:
                raise LLMUnavailable(f"remediator: could not parse model output ({exc})") from exc

    def _prompt(self, alert: dict, report: str) -> str:
        schemas = json.dumps(self._registry.schemas(), indent=2)
        event = json.dumps(alert.get("matched_event", {}))[:1000]
        return (
            "Given a security alert, its investigation report, and the available response "
            "tools, choose the response actions to take. Use ONLY the listed tools and their "
            "parameters. Return an empty list if no action is warranted.\n\n"
            f"Available tools (JSON schemas):\n{schemas}\n\n"
            f"Alert severity: {alert.get('severity')}\n"
            f"MITRE techniques: {', '.join(alert.get('mitre_techniques', []))}\n"
            f"Description: {alert.get('description')}\n"
            f"Matched event: {event}\n\n"
            f"Investigation report:\n{report}\n\n"
            'Return JSON: {"actions": [{"tool": "name", "args": {"param": "value"}, '
            '"reason": "why this action"}]}'
        )
