from __future__ import annotations

import json
from dataclasses import dataclass

from src.agents.llm import LLMUnavailable, LocalLLM

_SYSTEM = "You are a SOC triage planner. Output strict JSON only, no prose."


@dataclass
class Plan:
    needs_retrieval: bool
    tecnicas: list[str]
    subquestions: list[str]


class Planner:
    def __init__(self, llm: LocalLLM) -> None:
        self._llm = llm

    def plan(self, alert: dict) -> Plan:
        tecnicas = list(alert.get("mitre_techniques", []))
        baseline = self._deterministic_subquestions(alert, tecnicas)
        try:
            data = self._llm.generate_json(self._prompt(alert), system=_SYSTEM)
            subs = [str(q).strip() for q in data.get("subquestions", []) if str(q).strip()]
            return Plan(
                needs_retrieval=bool(data.get("needs_retrieval", True)),
                tecnicas=tecnicas,
                subquestions=subs or baseline,
            )
        except (LLMUnavailable, ValueError, KeyError, TypeError):
            return Plan(needs_retrieval=True, tecnicas=tecnicas, subquestions=baseline)

    def replan(self, alert: dict) -> Plan:
        tecnicas = list(alert.get("mitre_techniques", []))
        focus = ", ".join(tecnicas) if tecnicas else "this alert"
        return Plan(
            needs_retrieval=True,
            tecnicas=tecnicas,
            subquestions=[f"Related detection and mitigation details for {focus}"],
        )

    def _deterministic_subquestions(self, alert: dict, tecnicas: list[str]) -> list[str]:
        focus = ", ".join(tecnicas) if tecnicas else "this activity"
        description = alert.get("description", "")
        return [
            f"What is {focus} and why is it a risk?",
            f"Is this event suspicious: {description}",
            f"What playbook or remediation applies to {focus}?",
        ]

    def _prompt(self, alert: dict) -> str:
        fields = {
            key: alert[key]
            for key in ("severity", "description", "mitre_techniques", "matched_event")
            if key in alert
        }
        return (
            "Given this security alert, produce 2-4 focused retrieval subquestions.\n"
            'Return JSON: {"needs_retrieval": true, "subquestions": ["..."]}\n\n'
            + json.dumps(fields)
        )
