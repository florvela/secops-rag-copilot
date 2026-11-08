from __future__ import annotations

import json

from pydantic import BaseModel, Field, field_validator

_MAX_EVENT_CHARS = 20000


class Trigger(BaseModel):
    query: str = Field(max_length=5000)
    source: str = Field(max_length=200)
    lookback_seconds: int = Field(ge=0, le=86400)
    iteration: int = Field(ge=0)


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


def validate_alert(payload: dict) -> Alert:
    return Alert.model_validate(payload)
