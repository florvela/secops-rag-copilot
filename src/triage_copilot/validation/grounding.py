from __future__ import annotations

from triage_copilot.agents.judge import Judge, Verdict


def enforce_grounding(report: str, context: str, judge: Judge) -> Verdict:
    return judge.assess(report, context)
