from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from triage_copilot.llm.client import LLMUnavailable, LocalLLM
from triage_copilot.prompts.planner import SYSTEM as _SYSTEM

logger = logging.getLogger(__name__)


@dataclass
class Plan:
    needs_retrieval: bool
    tecnicas: list[str]
    subquestions: list[str]
    remediation: list[str]


class Planner:
    def __init__(self, llm: LocalLLM) -> None:
        self._llm = llm

    def plan(self, alert: dict) -> Plan:
        tecnicas = list(alert.get("mitre_techniques", []))
        data = self._generate_plan(alert)
        subs = [str(q).strip() for q in data.get("subquestions", []) if str(q).strip()]
        if not subs:
            raise LLMUnavailable("planner: the model returned no usable subquestions")
        remediation = [str(q).strip() for q in data.get("remediation", []) if str(q).strip()]
        if not remediation:
            remediation = [self._default_remediation(alert)]
        return Plan(
            needs_retrieval=bool(data.get("needs_retrieval", True)),
            tecnicas=tecnicas,
            subquestions=subs,
            remediation=remediation,
        )

    def _default_remediation(self, alert: dict) -> str:
        return f"Remediation and response steps for: {alert.get('description', 'this alert')}"

    def _generate_plan(self, alert: dict) -> dict:
        prompt = self._prompt(alert)
        try:
            data = self._llm.generate_json(prompt, system=_SYSTEM)
            logger.debug("thinking (plan): %s", json.dumps(data)[:1500])
            return data
        except (ValueError, KeyError, TypeError):
            # Small local models occasionally emit malformed JSON; retry once.
            try:
                return self._llm.generate_json(prompt, system=_SYSTEM)
            except (ValueError, KeyError, TypeError) as exc:
                raise LLMUnavailable(f"planner: could not parse model output ({exc})") from exc

    def replan(self, alert: dict) -> Plan:
        # Broadens the investigation query when the first pass found weak evidence.
        # Remediation is retrieved separately, so it stays empty here.
        tecnicas = list(alert.get("mitre_techniques", []))
        focus = ", ".join(tecnicas) if tecnicas else "this alert"
        return Plan(
            needs_retrieval=True,
            tecnicas=tecnicas,
            subquestions=[f"Related detection and mitigation details for {focus}"],
            remediation=[],
        )

    def _prompt(self, alert: dict) -> str:
        fields = {
            key: alert[key]
            for key in ("severity", "description", "mitre_techniques", "matched_event")
            if key in alert
        }
        return (
            "Given this security alert, produce focused retrieval queries.\n"
            "- `subquestions`: 2-3 questions to understand what happened and whether it is "
            "suspicious.\n"
            "- `remediation`: 1-2 questions about how to respond to, remediate or contain it.\n"
            'Return JSON: {"needs_retrieval": true, "subquestions": ["..."], '
            '"remediation": ["..."]}\n\n'
            + json.dumps(fields)
        )
