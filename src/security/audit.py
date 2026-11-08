from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, log_dir: str | Path) -> None:
        self._path = Path(log_dir) / "security.jsonl"
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, execution_id: str, event: str, **fields: Any) -> dict:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "execution_id": execution_id,
            "event": event,
            **fields,
        }
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        return record
