"""Colored, per-module logging setup.

Each agent/module logs in its own color so the trace is easy to follow, and the raw
model output (the "thinking") is logged at DEBUG level — run the CLI with `-v` to see it.
Colors are disabled automatically when stderr is not a TTY, or when NO_COLOR is set.
"""

from __future__ import annotations

import logging
import os
import sys

_RESET = "\033[0m"
_COLORS = {
    "triage_copilot.investigation.orchestrator": "\033[36m",       # cyan
    "triage_copilot.agents.planner": "\033[34m",            # blue
    "triage_copilot.agents.investigator": "\033[35m",       # magenta
    "triage_copilot.agents.judge": "\033[33m",              # yellow
    "triage_copilot.agents.remediator": "\033[32m",         # green
    "triage_copilot.investigation.approval": "\033[31m",  # red
    "app.cli": "\033[37m",                        # white
}
_DEFAULT = "\033[90m"  # grey for everything else (indexing, libraries)


def _short(name: str) -> str:
    return name.split(".")[-1]


class ColorFormatter(logging.Formatter):
    def __init__(self, use_color: bool) -> None:
        super().__init__()
        self._use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        ts = self.formatTime(record, "%H:%M:%S")
        line = f"{ts} {record.levelname:<7} {_short(record.name):<13} {record.getMessage()}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        if not self._use_color:
            return line
        color = _COLORS.get(record.name, _DEFAULT)
        return f"{color}{line}{_RESET}"


def configure_logging(level: int) -> None:
    use_color = sys.stderr.isatty() and os.environ.get("NO_COLOR") is None
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ColorFormatter(use_color))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Keep library chatter out of the way so the agent trace stands out.
    for noisy in ("sentence_transformers", "transformers", "httpx", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
