import json
from pathlib import Path

import pytest

from greynoc_detections import normalize_security_event
from greynoc_detections.exceptions import DetectionEventError, RuleValidationError
from greynoc_detections.validate import load_detection_rules, main, validate_detection_rule


def _base_rule(**overrides):
    rule = {
        "id": "example.test.rule",
        "type": "brute_force",
        "title": "Repeated Failed Authentication",
        "severity": "high",
        "description": "Repeated authentication failures may indicate password guessing.",
        "recommended_action": "Review authentication context and source reputation.",
        "conditions": {
            "event_type": "authentication",
            "message_contains": ["failed", "password"],
            "min_count": 5,
            "time_window_seconds": 300,
            "source_fields": ["source_ip", "username"],
        },
    }
    rule.update(overrides)
    return rule


def test_validate_accepts_public_metadata_fields():
    rule = _base_rule(
        confidence=80,
        false_positives=["Password manager retries", "User typo burst"],
        mitre_attack=["T1110", "T1110.001"],
        references=["https://attack.mitre.org/techniques/T1110/"],
    )
    assert validate_detection_rule(rule)["id"] == "example.test.rule"


def test_validate_rejects_invalid_mitre_attack_id():
    rule = _base_rule(mitre_attack=["TA0006"])
    with pytest.raises(RuleValidationError, match="invalid MITRE"):
        validate_detection_rule(rule)


def test_validate_rejects_bad_field_contains_values():
    rule = _base_rule(conditions={"event_type": "http", "field_contains": {"path": ["/login", ""]}})
    with pytest.raises(RuleValidationError, match="field_contains.path"):
        validate_detection_rule(rule)


def test_validate_rejects_numeric_field_contains():
    rule = _base_rule(conditions={"event_type": "http", "field_contains": {"path": 123}})
    with pytest.raises(RuleValidationError, match="field_contains.path"):
        validate_detection_rule(rule)


def test_validate_allows_numeric_field_equals():
    rule = _base_rule(conditions={"event_type": "network", "field_equals": {"destination_port": 443}})
    assert validate_detection_rule(rule)["id"] == "example.test.rule"


def test_load_detection_rules_rejects_duplicate_ids(tmp_path: Path):
    first = _base_rule(id="example.duplicate.rule")
    second = _base_rule(id="example.duplicate.rule", title="Duplicate")
    (tmp_path / "a.json").write_text(json.dumps(first), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(second), encoding="utf-8")

    with pytest.raises(RuleValidationError, match="Duplicate rule id"):
        load_detection_rules(tmp_path)


def test_cli_json_output_reports_success(tmp_path: Path, capsys):
    (tmp_path / "rule.json").write_text(json.dumps(_base_rule()), encoding="utf-8")
    assert main(["--format", "json", str(tmp_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["rules_validated"] == 1


def test_cli_json_output_reports_duplicate_as_one_validated_rule(tmp_path: Path, capsys):
    first = _base_rule(id="example.duplicate.rule")
    second = _base_rule(id="example.duplicate.rule", title="Duplicate")
    (tmp_path / "a.json").write_text(json.dumps(first), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(second), encoding="utf-8")

    assert main(["--format", "json", str(tmp_path)]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["rules_validated"] == 1
    assert payload["file_failures"] == 1


def test_cli_json_output_reports_missing_path(capsys):
    assert main(["--format", "json", "missing-rules-dir"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert "Missing path" in payload["errors"][0]


def test_normalizer_bounds_raw_event_and_normalizes_ips():
    event = normalize_security_event(
        {
            "id": "evt-1",
            "timestamp": "2026-05-13T12:00:00Z",
            "src_ip": "010.000.000.001",
            "dst_ip": "2001:0db8:0000:0000:0000:0000:0000:0001",
            "destination_port": "443",
            "protocol": "tcp",
            "message": "connection allowed",
            "nested": {"value": "x" * 25_000},
        }
    )
    assert event["source_ip"] in {"10.0.0.1", "010.000.000.001"}
    assert event["destination_ip"] == "2001:db8::1"
    assert event["destination_port"] == 443
    assert event["protocol"] == "TCP"
    assert len(event["raw_event"]["nested"]["value"]) == 20_000


def test_normalizer_rejects_oversized_message():
    with pytest.raises(DetectionEventError, match="message"):
        normalize_security_event(
            {
                "timestamp": "2026-05-13T12:00:00Z",
                "message": "x" * 10_001,
            }
        )
