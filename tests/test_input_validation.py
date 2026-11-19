import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from triage_copilot.validation.input_validation import validate_alert

VALID = json.loads(Path("fixtures/alerts/mfa_console_signin.json").read_text(encoding="utf-8"))


def test_valid_alert():
    alert = validate_alert(VALID)
    assert alert.mitre_techniques == ["T1078.004"]


def test_missing_field_rejected():
    bad = dict(VALID)
    bad.pop("security_detection")
    with pytest.raises(ValidationError):
        validate_alert(bad)


def test_oversized_description_rejected():
    bad = dict(VALID)
    bad["security_detection"] = dict(bad["security_detection"], description="x" * 5000)
    with pytest.raises(ValidationError):
        validate_alert(bad)


def test_empty_mitre_enriched_from_activity_name():
    # cloudtrail_trail_deleted has mitre_techniques=[] and activity_name="DeleteTrail";
    # the AiSOC-derived map infers T1562.008.
    raw = json.loads(
        Path("fixtures/alerts/cloudtrail_trail_deleted.json").read_text(encoding="utf-8")
    )
    assert raw["mitre_techniques"] in ([], {})  # unset in the source alert
    alert = validate_alert(raw)
    assert "T1562.008" in alert.mitre_techniques
