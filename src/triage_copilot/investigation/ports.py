from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from triage_copilot.agents.investigator import Evidence


@runtime_checkable
class AuditSink(Protocol):
    def log(self, execution_id: str, event: str, **fields: Any) -> dict: ...


@runtime_checkable
class DocRetriever(Protocol):
    def investigate(
        self,
        query: str,
        tecnicas: list[str] | None = None,
        fuentes: list[str] | None = None,
    ) -> "Evidence": ...


# Called with (report, grounded, grounded_reason) once the report is ready and before
# any response action runs, so a caller can present it to the analyst first.
ReportCallback = Callable[[str, bool, str], None]
