from __future__ import annotations

from dataclasses import dataclass

from src.agents.llm import LLMUnavailable, LocalLLM

_SYSTEM = (
    "You are a strict grounding verifier for SOC investigation reports. "
    "Output strict JSON only, no prose."
)


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

        unsupported = [str(c).strip() for c in (data.get("unsupported") or []) if str(c).strip()]
        grounded = bool(data.get("grounded", False)) and not unsupported
        reason = str(data.get("reason", "")).strip()
        if unsupported:
            reason = (reason + " | unsupported: " + "; ".join(unsupported[:5])).strip(" |")
        return Verdict(grounded, reason)

    def _prompt(self, report: str, context: str) -> str:
        return (
            "Decide whether every factual claim in the REPORT is directly supported by the "
            "EVIDENCE below.\n\n"
            "Rules:\n"
            "- A claim is supported ONLY if the evidence states it. Ignore outside knowledge.\n"
            "- Inferences or assumptions stated as fact count as UNSUPPORTED. In particular, "
            "attributions such as calling an account 'compromised', an IP 'malicious/untrusted', "
            "or an action 'performed by an attacker' are unsupported unless the evidence says so.\n"
            "- Generic security guidance is fine when it comes from the cited evidence.\n\n"
            "EVIDENCE:\n"
            f"{context}\n\n"
            "REPORT:\n"
            f"{report}\n\n"
            'Return JSON: {"grounded": true/false, "unsupported": ["claim", ...], "reason": "..."}\n'
            "List every unsupported claim in `unsupported`; set `grounded` to false if that list "
            "is non-empty."
        )
