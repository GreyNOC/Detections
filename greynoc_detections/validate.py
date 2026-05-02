"""Rule validation and CLI for public GreyNOC detection rules."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

from .constants import CONDITION_FIELDS, REQUIRED_RULE_FIELDS, SEVERITY_ORDER, SUPPORTED_RULE_TYPES
from .exceptions import RuleValidationError

MAX_REGEX_LENGTH = 300
MAX_RULE_FILE_BYTES = 1_000_000

UNSAFE_REGEX_SIGNATURES = (
    re.compile(r"\([^)]*[+*][^)]*\)\s*[+*?]"),
    re.compile(r"(?:\.\*){2,}"),
    re.compile(r"(?:\.\+){2,}"),
    re.compile(r"\([^)]*\{\d+,?\d*\}[^)]*\)\s*[+*?{]"),
)


def _rule_id(rule: dict[str, Any]) -> str:
    return str(rule.get("id") or "<unknown>")


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuleValidationError(f"{label} must be an object")
    return value


def _require_text(rule: dict[str, Any], key: str) -> str:
    value = rule.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuleValidationError(f"Rule {_rule_id(rule)} requires non-empty string field '{key}'")
    return value.strip()


def _validate_regex(rule_id: str, pattern: str) -> None:
    if not isinstance(pattern, str) or not pattern:
        raise RuleValidationError(f"Rule {rule_id} includes an empty regex pattern")
    if len(pattern) > MAX_REGEX_LENGTH:
        raise RuleValidationError(f"Rule {rule_id} regex pattern is too long")
    for signature in UNSAFE_REGEX_SIGNATURES:
        if signature.search(pattern):
            raise RuleValidationError(f"Rule {rule_id} regex pattern may be unsafe")
    try:
        re.compile(pattern)
    except re.error as exc:
        raise RuleValidationError(f"Rule {rule_id} regex pattern is invalid: {exc}") from exc


def _validate_conditions(rule: dict[str, Any]) -> dict[str, Any]:
    rule_id = _rule_id(rule)
    conditions = _require_object(rule.get("conditions"), f"Rule {rule_id} conditions")
    if not conditions:
        raise RuleValidationError(f"Rule {rule_id} requires at least one condition")
    unknown = sorted(set(conditions) - CONDITION_FIELDS)
    if unknown:
        raise RuleValidationError(f"Rule {rule_id} has unsupported condition fields: {', '.join(unknown)}")

    if "regex" in conditions:
        regexes = conditions["regex"]
        if isinstance(regexes, str):
            regexes = [regexes]
        if not isinstance(regexes, list) or not regexes:
            raise RuleValidationError(f"Rule {rule_id} field 'regex' must be a string or non-empty list")
        for pattern in regexes:
            _validate_regex(rule_id, pattern)

    for integer_key in ("min_count", "time_window_seconds"):
        if integer_key in conditions:
            value = conditions[integer_key]
            if not isinstance(value, int) or value <= 0:
                raise RuleValidationError(f"Rule {rule_id} condition '{integer_key}' must be a positive integer")

    for object_key in ("field_equals", "field_contains"):
        if object_key in conditions and not isinstance(conditions[object_key], dict):
            raise RuleValidationError(f"Rule {rule_id} condition '{object_key}' must be an object")

    for list_key in ("message_contains", "event_type", "source_fields"):
        if list_key in conditions:
            value = conditions[list_key]
            if isinstance(value, str):
                continue
            if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
                raise RuleValidationError(f"Rule {rule_id} condition '{list_key}' must be a string or string list")

    return conditions


def validate_detection_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """Validate a public detection rule and return the original object."""

    rule = _require_object(rule, "Rule")
    for field in REQUIRED_RULE_FIELDS:
        if field not in rule:
            raise RuleValidationError(f"Rule {_rule_id(rule)} missing required field '{field}'")

    rule_id = _require_text(rule, "id")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,127}", rule_id):
        raise RuleValidationError(f"Rule {rule_id} has invalid id format")

    rule_type = _require_text(rule, "type")
    if rule_type not in SUPPORTED_RULE_TYPES:
        raise RuleValidationError(f"Rule {rule_id} has unsupported type '{rule_type}'")

    severity = _require_text(rule, "severity").lower()
    if severity not in SEVERITY_ORDER:
        raise RuleValidationError(f"Rule {rule_id} has unsupported severity '{severity}'")

    _require_text(rule, "title")
    _require_text(rule, "description")
    _require_text(rule, "recommended_action")
    _validate_conditions(rule)

    tags = rule.get("tags", [])
    if tags is not None and (not isinstance(tags, list) or not all(isinstance(item, str) for item in tags)):
        raise RuleValidationError(f"Rule {rule_id} field 'tags' must be a list of strings")

    references = rule.get("references", [])
    if references is not None and (
        not isinstance(references, list) or not all(isinstance(item, str) for item in references)
    ):
        raise RuleValidationError(f"Rule {rule_id} field 'references' must be a list of strings")

    return rule


def _json_files(paths: Iterable[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.rglob("*.json")))
        elif path.suffix.lower() == ".json":
            files.append(path)
    return sorted(dict.fromkeys(files))


def _rules_from_payload(payload: Any, source: Path) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("rules"), list):
        return payload["rules"]
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return [payload]
    raise RuleValidationError(f"{source} must contain a rule object, rule list, or {{'rules': [...]}}")


def load_detection_rules(path: str | Path) -> list[dict[str, Any]]:
    """Recursively load and validate detection rules from a file or directory."""

    root = Path(path)
    files = _json_files([root])
    if not files:
        raise RuleValidationError(f"No JSON rule files found at {root}")

    rules: list[dict[str, Any]] = []
    for file_path in files:
        if file_path.stat().st_size > MAX_RULE_FILE_BYTES:
            raise RuleValidationError(f"{file_path} is too large")
        try:
            payload = json.loads(file_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuleValidationError(f"{file_path} is not valid JSON: {exc}") from exc
        for rule in _rules_from_payload(payload, file_path):
            rules.append(validate_detection_rule(rule))
    return rules


def _validate_cli(paths: list[Path]) -> int:
    files = _json_files(paths)
    if not files:
        print("FAIL no JSON files found", file=sys.stderr)
        return 1

    failures = 0
    total = 0
    for file_path in files:
        try:
            payload = json.loads(file_path.read_text(encoding="utf-8"))
            rules = _rules_from_payload(payload, file_path)
            for rule in rules:
                total += 1
                validate_detection_rule(rule)
            print(f"PASS {file_path} ({len(rules)} rule{'s' if len(rules) != 1 else ''})")
        except (OSError, RuleValidationError, json.JSONDecodeError) as exc:
            failures += 1
            print(f"FAIL {file_path}: {exc}", file=sys.stderr)

    print(f"Validated {total} rule{'s' if total != 1 else ''}; {failures} file failure{'s' if failures != 1 else ''}.")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate GreyNOC detection rule JSON files.")
    parser.add_argument("paths", nargs="+", type=Path, help="Rule JSON files or directories to validate.")
    args = parser.parse_args(argv)
    return _validate_cli(args.paths)


if __name__ == "__main__":
    raise SystemExit(main())

