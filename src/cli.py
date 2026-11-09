from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.agents.llm import build_llm
from src.agents.orchestrator import investigate_alert
from src.config import get_settings
from src.guardrails.injection_guard import InjectionGuard
from src.guardrails.input_validation import validate_alert
from src.indexing import build_reranker, build_store
from src.security.audit import AuditLog


def main() -> None:
    parser = argparse.ArgumentParser(description="Investigate a security alert fixture.")
    parser.add_argument("alert", help="path to an alert JSON file")
    args = parser.parse_args()

    settings = get_settings()
    alert = validate_alert(json.loads(Path(args.alert).read_text(encoding="utf-8"))).model_dump()

    store = build_store(settings)
    reranker = build_reranker(settings)
    llm = build_llm(settings)
    guard = InjectionGuard(threshold=settings.pipeline.injection_guard.threshold)
    audit = AuditLog(settings.log_dir)

    result = investigate_alert(alert, store, reranker, llm, settings.pipeline, guard, audit)

    print("=" * 60)
    print("REPORT\n")
    print(result.report)
    print("\nCitations:")
    for citation in result.citations:
        print(" -", citation)
    print(
        f"\ngrounded={result.grounded} iterations={result.iterations} "
        f"flagged_chunks={result.flagged_chunks} execution_id={result.execution_id}"
    )


if __name__ == "__main__":
    main()
