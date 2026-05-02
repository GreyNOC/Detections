from pathlib import Path

import pytest

from greynoc_detections import RuleValidationError, load_detection_rules, validate_detection_rule


def test_loads_example_rules():
    rules = load_detection_rules("rules/examples")
    ids = {rule["id"] for rule in rules}

    assert len(rules) == 6
    assert "example.port_scan.generic" in ids
    assert "example.ai_user_agent_abuse.basic" in ids


def test_validate_rule_accepts_minimal_public_rule():
    rule = {
        "id": "example.test_rule",
        "type": "port_scan",
        "title": "Test Rule",
        "severity": "low",
        "description": "A safe public test rule.",
        "recommended_action": "Review the event.",
        "conditions": {"event_type": "network"},
    }

    assert validate_detection_rule(rule) is rule


def test_validate_rule_rejects_private_correlation_type():
    rule = {
        "id": "example.private_type",
        "type": "attack_chain_progression",
        "title": "Private Type",
        "severity": "high",
        "description": "Should not be public.",
        "recommended_action": "Do not load.",
        "conditions": {"event_type": "network"},
    }

    with pytest.raises(RuleValidationError, match="unsupported type"):
        validate_detection_rule(rule)


def test_validate_rule_rejects_unsafe_regex():
    rule = {
        "id": "example.unsafe_regex",
        "type": "suspicious_powershell",
        "title": "Unsafe Regex",
        "severity": "medium",
        "description": "Unsafe regex should fail.",
        "recommended_action": "Fix the regex.",
        "conditions": {"regex": "(a+)+"},
    }

    with pytest.raises(RuleValidationError, match="unsafe"):
        validate_detection_rule(rule)


def test_load_detection_rules_accepts_rules_wrapper(tmp_path: Path):
    rule_file = tmp_path / "wrapped.json"
    rule_file.write_text(
        """
        {
          "rules": [
            {
              "id": "example.wrapper",
              "type": "scan_finding",
              "title": "Wrapped Rule",
              "severity": "info",
              "description": "Wrapped rule payload.",
              "recommended_action": "Review scanner output.",
              "conditions": {"event_type": "scan_finding"}
            }
          ]
        }
        """,
        encoding="utf-8",
    )

    rules = load_detection_rules(rule_file)
    assert [rule["id"] for rule in rules] == ["example.wrapper"]

