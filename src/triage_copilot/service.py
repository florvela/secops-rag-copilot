"""Public entry point of the library: run a full alert investigation.

The app layer builds the concrete dependencies (retrieval store, LLM client, tool
registry, approver, audit sink) and calls :func:`investigate_alert`.
"""

from triage_copilot.investigation.orchestrator import InvestigationResult, investigate_alert

__all__ = ["InvestigationResult", "investigate_alert"]
