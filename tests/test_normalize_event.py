import json
from pathlib import Path

import pytest

from greynoc_detections import DetectionEventError, normalize_security_event


def test_normalize_security_event_aliases():
    event = json.loads(Path("tests/sample_events.json").read_text())[0]
    normalized = normalize_security_event(event)

    assert normalized["timestamp"] == "2026-01-01T12:00:00+00:00"
    assert normalized["source_ip"] == "10.0.0.10"
    assert normalized["destination_ip"] == "10.0.0.20"
    assert normalized["destination_port"] == 443
    assert normalized["protocol"] == "TCP"
    assert normalized["hostname"] == "workstation"
    assert normalized["username"] == "analyst"
    assert normalized["event_type"] == "network"
    assert normalized["severity"] == "medium"
    assert normalized["raw_event"]["id"] == "evt-001"


def test_normalize_requires_object():
    with pytest.raises(DetectionEventError):
        normalize_security_event(["not", "an", "object"])


def test_normalize_rejects_missing_timestamp_by_default():
    with pytest.raises(DetectionEventError, match="Missing timestamp"):
        normalize_security_event({"message": "login failed"})


def test_normalize_can_default_timestamp_when_allowed():
    normalized = normalize_security_event({"message": "login failed"}, allow_now_timestamp=True)
    assert normalized["event_type"] == "authentication"
    assert normalized["timestamp"]

