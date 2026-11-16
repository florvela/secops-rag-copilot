from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from src.agents.investigator import Investigator, build_context, format_citation
from src.agents.judge import Judge
from src.agents.llm import LLMUnavailable, LocalLLM
from src.agents.planner import Planner
from src.agents.remediator import Remediator
from src.config import PipelineConfig
from src.guardrails.grounding import enforce_grounding
from src.guardrails.human_approval import ActionOutcome, Approver, run_with_approval
from src.guardrails.injection_guard import InjectionGuard
from src.mcp_tools.registry import ToolRegistry
from src.retrieval.pipeline import ScoredChunk
from src.security.audit import AuditLog

logger = logging.getLogger(__name__)

_REPORT_SYSTEM = (
    "You are a SOC analyst. Write a concise investigation report using ONLY the provided "
    "evidence and the alert fields. Cite sources using their bracketed [ ... ] markers. "
    "Do not assert facts that are not in the evidence or the alert. In particular, do not "
    "claim an account is compromised, an IP is malicious or untrusted, or that an action was "
    "performed by an attacker, unless the evidence states it. Describe such items as observed "
    "fields to review, not as established facts. If the evidence is insufficient, state that "
    "explicitly."
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
    actions: list[ActionOutcome] = field(default_factory=list)
    closure: str = ""


# Called with (report, grounded, grounded_reason) after the investigation report is ready
# and before any response action runs, so a caller can show it to the analyst first.
ReportCallback = Callable[[str, bool, str], None]

_CLOSURE_SYSTEM = (
    "You are a SOC analyst writing a brief incident closure note. Summarize what the alert "
    "was, the key finding from the investigation, and the response actions taken. Use ONLY the "
    "provided report and action list; do not invent actions or facts. Be concise."
)


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


def _event_anchor(alert: dict) -> str:
    """Retrieval anchor built from the event itself.

    Used when the alert carries no MITRE technique: without a technique filter the
    search has nothing concrete to latch onto, so we enrich the query with what
    actually happened (description + the event's activity/object/source).
    """
    event = alert.get("matched_event", {})
    parts = [
        alert.get("description", ""),
        str(event.get("activity_name", "")),
        str(event.get("object_type", "")),
        str(event.get("log_source", "")),
    ]
    return " ".join(p for p in parts if p and p != "-").strip()


def _write_report(llm: LocalLLM, alert: dict, context: str) -> str:
    report = llm.generate(_report_prompt(alert, context), system=_REPORT_SYSTEM)
    if not report:
        raise LLMUnavailable("report generation returned empty output")
    return report


def _write_closure(llm: LocalLLM, alert: dict, report: str, actions: list[ActionOutcome]) -> str:
    """Final closure note summarizing the incident and what was actually done."""
    action_lines = "\n".join(f"- {a.status}: {a.tool} {a.args}" for a in actions) or "(no response actions)"
    prompt = (
        f"Alert severity: {alert.get('severity')}\n"
        f"Description: {alert.get('description')}\n\n"
        f"Investigation report:\n{report}\n\n"
        f"Response actions (status: tool args):\n{action_lines}\n\n"
        "Write a short closure note: incident summary, the response actions taken (or left "
        "pending/declined), and the resulting status."
    )
    try:
        return llm.generate(prompt, system=_CLOSURE_SYSTEM)
    except LLMUnavailable:
        return ""


def investigate_alert(
    alert: dict,
    store,
    reranker,
    llm: LocalLLM,
    cfg: PipelineConfig,
    guard: InjectionGuard,
    audit: AuditLog,
    tools: ToolRegistry | None = None,
    approver: Approver | None = None,
    on_report: ReportCallback | None = None,
) -> InvestigationResult:
    execution_id = uuid.uuid4().hex[:12]
    logger.info(
        "[%s] investigating alert severity=%s mitre=%s",
        execution_id,
        alert.get("severity"),
        alert.get("mitre_techniques"),
    )
    planner = Planner(llm)
    investigator = Investigator(store, reranker, cfg, guard)
    judge = Judge(llm)

    logger.info("[%s] screening matched_event for prompt injection", execution_id)
    event_score = guard.score_event(alert.get("matched_event", {}))
    if event_score >= cfg.injection_guard.threshold:
        logger.warning("[%s] injection suspected in matched_event (score=%.2f)", execution_id, event_score)
        audit.log(execution_id, "injection_suspected", source="matched_event", score=event_score)

    logger.info("[%s] planning (LLM)...", execution_id)
    plan = planner.plan(alert)
    logger.info(
        "[%s] plan ready: %d subquestions, needs_retrieval=%s",
        execution_id,
        len(plan.subquestions),
        plan.needs_retrieval,
    )
    for i, question in enumerate(plan.subquestions, start=1):
        logger.info("[%s]   subquestion %d: %s", execution_id, i, question)
    for i, question in enumerate(plan.remediation, start=1):
        logger.info("[%s]   remediation %d: %s", execution_id, i, question)
    audit.log(
        execution_id,
        "plan_created",
        needs_retrieval=plan.needs_retrieval,
        subquestions=len(plan.subquestions),
        tecnicas=plan.tecnicas,
    )

    if not plan.needs_retrieval:
        logger.info("[%s] no retrieval needed; writing report (LLM)...", execution_id)
        report = _write_report(llm, alert, "")
        if on_report is not None:
            on_report(report, True, "no external knowledge required")
        actions = _remediate(alert, report, llm, tools, approver, audit, execution_id)
        closure = _write_closure(llm, alert, report, actions) if tools is not None else ""
        logger.info("[%s] done (no retrieval)", execution_id)
        audit.log(execution_id, "completed", used_retrieval=False, grounded=True, actions=len(actions))
        return InvestigationResult(
            report=report,
            grounded=True,
            grounded_reason="no external knowledge required",
            citations=[],
            iterations=0,
            used_retrieval=False,
            flagged_chunks=0,
            execution_id=execution_id,
            actions=actions,
            closure=closure,
        )

    # Event anchor (description + activity/object/source). Used from the start when the
    # alert has no technique, and as a fallback when the technique filter finds nothing
    # (e.g. an inferred technique that isn't in the corpus).
    anchor = _event_anchor(alert)
    anchor_from_start = not plan.tecnicas
    if anchor and anchor_from_start:
        logger.info("[%s] no MITRE technique; anchoring retrieval to event: %r", execution_id, anchor)

    # Remediation queries are retrieved once, routed to playbooks/runbooks (captured before
    # the loop reassigns `plan` during replanning).
    remediation_queries = list(plan.remediation)

    collected: list[ScoredChunk] = []
    flagged_total = 0
    iterations = 0
    for iteration in range(1, cfg.orchestration.max_iterations + 1):
        iterations = iteration
        logger.info(
            "[%s] retrieval iteration %d/%d: %d subquestions (hybrid RAG)",
            execution_id,
            iteration,
            cfg.orchestration.max_iterations,
            len(plan.subquestions),
        )
        for question in plan.subquestions:
            tec = plan.tecnicas or None
            query = f"{question} {anchor}".strip() if (anchor_from_start and anchor) else question
            logger.info("[%s]   query: %r (filter tecnicas=%s)", execution_id, query, tec)
            evidence = investigator.investigate(query, tecnicas=tec)
            if not evidence.scored and tec and anchor:
                # Technique filter excluded everything (e.g. technique not in corpus):
                # fall back to an unfiltered, event-anchored search.
                anchored = f"{question} {anchor}".strip()
                logger.info("[%s]   no hits with filter; retrying anchored: %r", execution_id, anchored)
                evidence = investigator.investigate(anchored, tecnicas=None)
            logger.info(
                "[%s]   -> %d chunks, top score=%.3f%s",
                execution_id,
                len(evidence.scored),
                evidence.top_score,
                f", {len(evidence.flagged)} flagged" if evidence.flagged else "",
            )
            flagged_total += len(evidence.flagged)
            collected.extend(evidence.scored)
        best_score = max((item.score for item in collected), default=0.0)
        logger.info(
            "[%s] iteration %d: %d chunks collected, best score=%.3f",
            execution_id,
            iteration,
            len(collected),
            best_score,
        )
        if any(item.score >= cfg.evidence.min_rerank_score for item in collected):
            break
        logger.info("[%s] evidence below threshold; replanning with a broader query", execution_id)
        plan = planner.replan(alert)

    # Remediation pass: route to playbooks/runbooks so the response steps come from
    # operational guidance, not from generic MITRE prose.
    if remediation_queries:
        logger.info(
            "[%s] remediation retrieval: %d queries (filter fuentes=playbook,runbook)",
            execution_id,
            len(remediation_queries),
        )
    remediation_collected: list[ScoredChunk] = []
    for question in remediation_queries:
        query = f"{question} {anchor}".strip() if anchor else question
        logger.info("[%s]   remediation query: %r", execution_id, query)
        evidence = investigator.investigate(query, fuentes=["playbook", "runbook"])
        logger.info(
            "[%s]   -> %d chunks, top score=%.3f",
            execution_id,
            len(evidence.scored),
            evidence.top_score,
        )
        flagged_total += len(evidence.flagged)
        remediation_collected.extend(evidence.scored)

    # Guarantee a couple of slots for remediation evidence so playbook/runbook guidance
    # reaches the report even when MITRE chunks score higher.
    reserve = min(2, cfg.retrieval.top_final)
    best_remediation = _dedup_top(remediation_collected, reserve)
    reserved_ids = {item.chunk.id for item in best_remediation}
    best_investigation = [
        item for item in _dedup_top(collected, cfg.retrieval.top_final)
        if item.chunk.id not in reserved_ids
    ]
    slots_left = cfg.retrieval.top_final - len(best_remediation)
    best = sorted(
        best_remediation + best_investigation[:slots_left],
        key=lambda s: s.score,
        reverse=True,
    )
    context = build_context(best)
    citations = [format_citation(item.chunk) for item in best]
    logger.info(
        "[%s] writing report from %d evidence chunks (%d remediation) (LLM)...",
        execution_id,
        len(best),
        len(best_remediation),
    )

    report = _write_report(llm, alert, context)

    logger.info("[%s] checking grounding (LLM judge)...", execution_id)
    verdict = enforce_grounding(report, context, judge)
    if not verdict.grounded:
        logger.warning("[%s] grounding check failed: %s", execution_id, verdict.reason)
        audit.log(execution_id, "grounding_failed", reason=verdict.reason)

    # Present the report to the analyst BEFORE proposing/approving any action, so the
    # human decides with the report (and its grounding status) in hand.
    if on_report is not None:
        on_report(report, verdict.grounded, verdict.reason)

    actions = _remediate(alert, report, llm, tools, approver, audit, execution_id)

    closure = ""
    if tools is not None:
        logger.info("[%s] writing closure note (LLM)...", execution_id)
        closure = _write_closure(llm, alert, report, actions)

    logger.info("[%s] done: grounded=%s, %d citations", execution_id, verdict.grounded, len(citations))
    audit.log(
        execution_id,
        "completed",
        used_retrieval=True,
        grounded=verdict.grounded,
        flagged=flagged_total,
        citations=len(citations),
        actions=len(actions),
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
        actions=actions,
        closure=closure,
    )


def _remediate(
    alert: dict,
    report: str,
    llm: LocalLLM,
    tools: ToolRegistry | None,
    approver: Approver | None,
    audit: AuditLog,
    execution_id: str,
) -> list[ActionOutcome]:
    """Propose a response plan (Remediator) and run it through the approval guardrail."""
    if tools is None:
        return []
    logger.info("[%s] proposing response actions (Remediator, LLM)...", execution_id)
    proposed = Remediator(llm, tools).propose(alert, report)
    for action in proposed:
        logger.info(
            "[%s]   proposed: %s %s (destructive=%s)",
            execution_id,
            action.tool,
            action.args,
            action.destructive,
        )
    return run_with_approval(proposed, tools, audit, execution_id, approve=approver)
