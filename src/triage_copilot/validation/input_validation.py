from __future__ import annotations

import functools
import json
import os
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

_MAX_EVENT_CHARS = 20000
# The map path is resolved by the app/env so the library carries no hardcoded layout.
_MITRE_MAP_PATH = Path(os.getenv("MITRE_MAP_PATH", "config/activity_mitre_map.json"))


@functools.lru_cache(maxsize=1)
def _activity_mitre_map() -> dict[str, list[str]]:
    """Lookup of event ``activity_name`` -> MITRE techniques.

    Built from the AiSOC detections by ``scripts/build_mitre_map.py``. Returns an
    empty map (no enrichment) if the file is missing or unreadable.
    """
    try:
        data = json.loads(_MITRE_MAP_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {
        key: value
        for key, value in data.items()
        if not key.startswith("_") and isinstance(value, list)
    }


class Trigger(BaseModel):
    query: str = Field(max_length=5000)
    source: str = Field(max_length=200)
    lookback_seconds: int = Field(default=0, ge=0, le=86400)
    iteration: int = Field(default=0, ge=0)


class Alert(BaseModel):
    severity: str = Field(max_length=20)
    description: str = Field(max_length=2000)
    resolution: str = Field(max_length=4000)
    mitre_techniques: list[str] = Field(max_length=20)
    matched_event: dict
    trigger: Trigger

    @field_validator("matched_event")
    @classmethod
    def _limit_event_size(cls, value: dict) -> dict:
        if len(json.dumps(value)) > _MAX_EVENT_CHARS:
            raise ValueError("matched_event exceeds the maximum allowed size")
        return value


def _is_nested(payload: dict) -> bool:
    """Heuristic: the nested SIEM alert carries these top-level containers."""
    return "security_detection" in payload or "events" in payload


def normalize_alert(payload: dict) -> dict:
    """Map the nested SIEM alert format to the flat internal `Alert` shape.

    The pipeline consumes a flat alert (``severity``, ``description``,
    ``mitre_techniques``, ``matched_event``, ``trigger``). Incoming alerts use a
    nested SIEM layout (``security_detection``, ``event``, ``events.records``);
    this adapter flattens them so the rest of the system stays unchanged. A
    payload that is already flat is returned untouched.
    """
    if not isinstance(payload, dict) or not _is_nested(payload):
        return payload

    detection = payload.get("security_detection") or {}
    event = payload.get("event") or {}
    records = (payload.get("events") or {}).get("records") or []

    # Some SIEM exports write an empty object `{}` instead of `[]` when there are
    # no techniques; coerce anything that is not a list to an empty list.
    techniques = payload.get("mitre_techniques")
    if not isinstance(techniques, list):
        techniques = []

    # The flat model carries a single event; use the first matched record.
    matched_event = records[0] if records else {}

    # Enrich: when the alert has no MITRE technique, infer it from the event's
    # activity_name using the AiSOC-derived lookup (leaves it empty if unknown).
    if not techniques:
        activity = matched_event.get("activity_name")
        if activity:
            techniques = list(_activity_mitre_map().get(activity, []))

    normalized: dict = {
        "mitre_techniques": techniques,
        "matched_event": matched_event,
        "trigger": {
            "query": event.get("query") or "",
            "source": event.get("source") or "",
            "iteration": event.get("iteration") or 0,
            "lookback_seconds": event.get("lookback_seconds") or 0,
        },
    }
    # Only forward fields that are present so a missing one still fails validation.
    for key in ("severity", "description", "resolution"):
        if key in detection:
            normalized[key] = detection[key]
    return normalized


def validate_alert(payload: dict) -> Alert:
    return Alert.model_validate(normalize_alert(payload))
