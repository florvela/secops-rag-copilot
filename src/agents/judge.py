from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from src.agents.llm import LLMUnavailable, LocalLLM

logger = logging.getLogger(__name__)

_SYSTEM = (
    "You are a strict grounding verifier for SOC investigation reports. "
    "Output strict JSON only, no prose."
)

# Hedging markers: a claim carrying any of these is a hypothesis / lead, not a stated
# fact, so it is acceptable in a triage report and must not count as unsupported.
_HEDGE = (
    "may ",
    "might ",
    "could ",
    "possibly",
    "possible",
    "perhaps",
    "consistent with",
    "worth investigating",
    "worth reviewing",
    "appears to",
    "suggests",
    "potential",
)


def _is_hedged(claim: str) -> bool:
    text = f" {claim.lower()} "
    return any(marker in text for marker in _HEDGE)


@dataclass
class Verdict:
    grounded: bool
    reason: str


class Judge:
    def __init__(self, llm: LocalLLM) -> None:
        self._llm = llm

    def assess(self, report: str, context: str) -> Verdict:
        prompt = self._prompt(report, context)
        try:
            data = self._llm.generate_json(prompt, system=_SYSTEM)
        except (ValueError, KeyError, TypeError):
            # Small local models occasionally emit malformed JSON; retry once.
            try:
                data = self._llm.generate_json(prompt, system=_SYSTEM)
            except (LLMUnavailable, ValueError, KeyError, TypeError) as exc:
                raise LLMUnavailable(f"judge: grounding check failed ({exc})") from exc

        logger.debug("thinking (grounding): %s", json.dumps(data)[:1500])

        # Keep only unsupported FACTUAL claims; drop hedged hypotheses the model may have
        # wrongly flagged (small models misapply the fact-vs-hypothesis rule).
        unsupported = [
            claim
            for claim in (str(c).strip() for c in (data.get("unsupported") or []))
            if claim and not _is_hedged(claim)
        ]
        grounded = not unsupported
        reason = str(data.get("reason", "")).strip()
        if unsupported:
            reason = (reason + " | unsupported: " + "; ".join(unsupported[:5])).strip(" |")
        return Verdict(grounded, reason)

    def _prompt(self, report: str, context: str) -> str:
        return (
            "Check whether the REPORT's statements of FACT are supported by the EVIDENCE below. "
            "Distinguish facts from hypotheses.\n\n"
            "Rules:\n"
            "- A statement asserted as an established FACT must be supported by the evidence or "
            "the alert; if it is not, list it in `unsupported`. Example of unsupported fact: "
            "'the account is compromised' or 'the deletion was performed by an attacker' stated "
            "plainly.\n"
            "- A HEDGED hypothesis or lead to investigate is ACCEPTABLE and must NOT be listed as "
            "unsupported, as long as the observation it builds on (a field or pattern) appears in "
            "the evidence. Hedging looks like 'may indicate', 'could be', 'possibly', 'consistent "
            "with', 'a possible interpretation', 'worth investigating'. These leads are expected "
            "in a triage report.\n"
            "- Generic security guidance drawn from cited evidence is fine.\n\n"
            "EVIDENCE:\n"
            f"{context}\n\n"
            "REPORT:\n"
            f"{report}\n\n"
            'Return JSON: {"grounded": true/false, "unsupported": ["claim", ...], "reason": "..."}\n'
            "Put only unsupported FACTUAL claims (not hedged hypotheses) in `unsupported`; set "
            "`grounded` to false only if that list is non-empty."
        )
