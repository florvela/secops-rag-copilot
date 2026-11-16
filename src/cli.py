from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from src.agents.llm import build_llm
from src.agents.orchestrator import investigate_alert
from src.config import get_settings
from src.guardrails.human_approval import cli_approver
from src.guardrails.injection_guard import InjectionGuard
from src.guardrails.input_validation import validate_alert
from src.indexing import build_reranker, build_store
from src.logging_setup import configure_logging
from src.mcp_tools import build_default_registry
from src.security.audit import AuditLog

logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="Investigate a security alert fixture.")
    parser.add_argument("alert", help="path to an alert JSON file")
    parser.add_argument("-q", "--quiet", action="store_true", help="hide progress logs")
    parser.add_argument("-v", "--verbose", action="store_true", help="show debug logs")
    args = parser.parse_args()

    level = logging.WARNING if args.quiet else logging.DEBUG if args.verbose else logging.INFO
    configure_logging(level)

    settings = get_settings()
    alert = validate_alert(json.loads(Path(args.alert).read_text(encoding="utf-8"))).model_dump()

    logger.info("loading knowledge base (embeddings index)...")
    store = build_store(settings)
    logger.info("loading cross-encoder re-ranker...")
    reranker = build_reranker(settings)
    logger.info("connecting to LLM backend (%s)...", settings.llm.backend)
    llm = build_llm(settings)
    guard = InjectionGuard(threshold=settings.pipeline.injection_guard.threshold)
    audit = AuditLog(settings.log_dir)
    tools = build_default_registry()

    def show_report(report: str, grounded: bool, reason: str) -> None:
        # Printed before any approval prompt, so the analyst decides with the report in hand.
        print("\n" + "=" * 60)
        print("INVESTIGATION REPORT\n")
        print(report)
        status = "GROUNDED" if grounded else "NOT GROUNDED — review before approving actions"
        print(f"\n[grounding: {status}]")
        if not grounded and reason:
            print(f"  reason: {reason}")
        print("\n" + "-" * 60)
        print("Proposed response actions (approve destructive ones below):")

    result = investigate_alert(
        alert,
        store,
        reranker,
        llm,
        settings.pipeline,
        guard,
        audit,
        tools=tools,
        approver=cli_approver,
        on_report=show_report,
    )

    print("\nCitations:")
    for citation in result.citations:
        print(" -", citation)
    if result.actions:
        print("\nResponse actions taken:")
        for action in result.actions:
            print(f" - [{action.status}] {action.tool} {action.args}")
    if result.closure:
        print("\n" + "=" * 60)
        print("CLOSURE NOTE\n")
        print(result.closure)
    print(
        f"\ngrounded={result.grounded} iterations={result.iterations} "
        f"flagged_chunks={result.flagged_chunks} execution_id={result.execution_id}"
    )


if __name__ == "__main__":
    main()
