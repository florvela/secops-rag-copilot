from __future__ import annotations

from dataclasses import dataclass

from src.agents.llm import LLMUnavailable, LocalLLM

_SYSTEM = "You verify whether a report is grounded in the given evidence. Output strict JSON only."


@dataclass
class Verdict:
    grounded: bool
    reason: str


class Judge:
    def __init__(self, llm: LocalLLM) -> None:
        self._llm = llm

    def assess(self, report: str, context: str) -> Verdict:
        try:
            data = self._llm.generate_json(self._prompt(report, context), system=_SYSTEM)
            return Verdict(bool(data.get("grounded", False)), str(data.get("reason", "")))
        except (LLMUnavailable, ValueError, KeyError, TypeError):
            return self._heuristic(report, context)

    def _heuristic(self, report: str, context: str) -> Verdict:
        has_citation = "[" in report and "]" in report
        grounded = has_citation and bool(context.strip())
        return Verdict(
            grounded=grounded,
            reason="heuristic: report cites evidence present in the context"
            if grounded
            else "heuristic: report lacks citations backed by the evidence",
        )

    def _prompt(self, report: str, context: str) -> str:
        return (
            "Evidence:\n"
            f"{context}\n\n"
            "Report:\n"
            f"{report}\n\n"
            "Is every claim in the report supported by the evidence above?\n"
            'Return JSON: {"grounded": true/false, "reason": "..."}'
        )
