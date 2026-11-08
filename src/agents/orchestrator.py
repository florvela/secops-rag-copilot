from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

from src.agents.investigator import Investigator, build_context, format_citation
from src.agents.judge import Judge
from src.agents.llm import LLMUnavailable, LocalLLM
from src.agents.planner import Planner
from src.config import PipelineConfig
from src.guardrails.grounding import enforce_grounding
from src.guardrails.injection_guard import InjectionGuard
from src.retrieval.pipeline import ScoredChunk
from src.security.audit import AuditLog

_REPORT_SYSTEM = (
    "You are a SOC analyst. Write a concise investigation report using ONLY the provided "
    "evidence. Cite sources using their bracketed [ ... ] markers. If the evidence is "
    "insufficient, state that explicitly."
)


@dataclass
class InvestigationResult:
    report: str
    grounded: bool
    grounded_reason: str
    citations: list[str]
    iterations: int
    used_retrieval: bool
    flagged_chunks: int
    execution_id: str


def _dedup_top(scored: list[ScoredChunk], n: int) -> list[ScoredChunk]:
    best: dict[str, ScoredChunk] = {}
    for item in scored:
        current = best.get(item.chunk.id)
        if current is None or item.score > current.score:
            best[item.chunk.id] = item
    return sorted(best.values(), key=lambda s: s.score, reverse=True)[:n]


def _report_prompt(alert: dict, context: str) -> str:
    return (
        f"Alert severity: {alert.get('severity')}\n"
        f"Description: {alert.get('description')}\n"
        f"MITRE techniques: {', '.join(alert.get('mitre_techniques', []))}\n"
        f"Matched event: {json.dumps(alert.get('matched_event', {}))}\n\n"
        f"Evidence:\n{context}\n\n"
        "Write the report: what the technique means, whether this event is suspicious given "
        "its fields, and the recommended response. Cite sources with their [ ... ] markers."
    )


def _fallback_report(alert: dict, context: str, citations: list[str]) -> str:
    lines = [
        f"Investigation summary for a {alert.get('severity')} alert.",
        f"Description: {alert.get('description')}",
        f"MITRE techniques: {', '.join(alert.get('mitre_techniques', [])) or 'n/a'}.",
        "",
    ]
    if context:
        lines.append("Relevant evidence retrieved from the knowledge base:")
        lines.extend(f"  - {c}" for c in citations)
        lines.append("")
        lines.append("Recommended response follows the cited playbook and runbook guidance.")
    else:
        lines.append("No external knowledge was required for this alert.")
    return "\n".join(lines)


def investigate_alert(
    alert: dict,
    store,
    reranker,
    llm: LocalLLM,
    cfg: PipelineConfig,
    guard: InjectionGuard,
    audit: AuditLog,
) -> InvestigationResult:
    execution_id = uuid.uuid4().hex[:12]
    planner = Planner(llm)
    investigator = Investigator(store, reranker, cfg, guard)
    judge = Judge(llm)

    event_score = guard.score_event(alert.get("matched_event", {}))
    if event_score >= cfg.injection_guard.threshold:
        audit.log(execution_id, "injection_suspected", source="matched_event", score=event_score)

    plan = planner.plan(alert)
    audit.log(
        execution_id,
        "plan_created",
        needs_retrieval=plan.needs_retrieval,
        subquestions=len(plan.subquestions),
        tecnicas=plan.tecnicas,
    )

    if not plan.needs_retrieval:
        audit.log(execution_id, "completed", used_retrieval=False, grounded=True)
        return InvestigationResult(
            report=_fallback_report(alert, "", []),
            grounded=True,
            grounded_reason="no external knowledge required",
            citations=[],
            iterations=0,
            used_retrieval=False,
            flagged_chunks=0,
            execution_id=execution_id,
        )

    collected: list[ScoredChunk] = []
    flagged_total = 0
    iterations = 0
    for iteration in range(1, cfg.orchestration.max_iterations + 1):
        iterations = iteration
        for question in plan.subquestions:
            evidence = investigator.investigate(question, tecnicas=plan.tecnicas or None)
            flagged_total += len(evidence.flagged)
            collected.extend(evidence.scored)
        if any(item.score >= cfg.evidence.min_rerank_score for item in collected):
            break
        plan = planner.replan(alert)

    best = _dedup_top(collected, cfg.retrieval.top_final)
    context = build_context(best)
    citations = [format_citation(item.chunk) for item in best]

    try:
        report = llm.generate(_report_prompt(alert, context), system=_REPORT_SYSTEM)
        if not report:
            report = _fallback_report(alert, context, citations)
    except LLMUnavailable:
        report = _fallback_report(alert, context, citations)

    verdict = enforce_grounding(report, context, judge)
    if not verdict.grounded:
        audit.log(execution_id, "grounding_failed", reason=verdict.reason)
    audit.log(
        execution_id,
        "completed",
        used_retrieval=True,
        grounded=verdict.grounded,
        flagged=flagged_total,
        citations=len(citations),
    )

    return InvestigationResult(
        report=report,
        grounded=verdict.grounded,
        grounded_reason=verdict.reason,
        citations=citations,
        iterations=iterations,
        used_retrieval=True,
        flagged_chunks=flagged_total,
        execution_id=execution_id,
    )
