import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.guardrails.input_validation import validate_alert

VALID = json.loads(Path("fixtures/alerts/mfa_console_signin.json").read_text(encoding="utf-8"))


def test_valid_alert():
    alert = validate_alert(VALID)
    assert alert.mitre_techniques == ["T1078.004"]


def test_missing_field_rejected():
    bad = dict(VALID)
    bad.pop("trigger")
    with pytest.raises(ValidationError):
        validate_alert(bad)


def test_oversized_description_rejected():
    bad = dict(VALID)
    bad["description"] = "x" * 5000
    with pytest.raises(ValidationError):
        validate_alert(bad)
