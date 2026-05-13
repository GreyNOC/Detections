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
MAX_TEXT_LENGTH = 2_000
MAX_CONDITION_ITEMS = 100
MAX_TAGS = 32
MAX_REFERENCES = 32

UNSAFE_REGEX_SIGNATURES = (
    re.compile(r"\([^)]*[+*][^)]*\)\s*[+*?]"),
    re.compile(r"(?:\.\*){2,}"),
    re.compile(r"(?:\.\+){2,}"),
    re.compile(r"\([^)]*\{\d+,?\d*\}[^)]*\)\s*[+*?{]"),
)

MITRE_ATTACK_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


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
    clean = value.strip()
    if len(clean) > MAX_TEXT_LENGTH:
        raise RuleValidationError(f"Rule {_rule_id(rule)} field '{key}' is too long")
    return clean


def _string_or_string_list(value: Any, *, label: str, allow_empty: bool = False) -> list[str]:
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list):
        raise RuleValidationError(f"{label} must be a string or string list")
    if not values and not allow_empty:
        raise RuleValidationError(f"{label} must not be empty")
    if len(values) > MAX_CONDITION_ITEMS:
        raise RuleValidationError(f"{label} has too many values")
    cleaned: list[str] = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise RuleValidationError(f"{label} must contain only non-empty strings")
        item_clean = item.strip()
        if len(item_clean) > MAX_TEXT_LENGTH:
            raise RuleValidationError(f"{label} contains a value that is too long")
        cleaned.append(item_clean)
    return cleaned


def _condition_scalar(value: Any, *, label: str) -> None:
    if isinstance(value, bool) or isinstance(value, int) or isinstance(value, float):
        return
    if isinstance(value, str) and value.strip() and len(value.strip()) <= MAX_TEXT_LENGTH:
        return
    raise RuleValidationError(f"{label} must be a non-empty string, number, boolean, or list of those values")


def _validate_field_equals(rule_id: str, conditions: dict[str, Any]) -> None:
    key = "field_equals"
    if key not in conditions:
        return
    value = conditions[key]
    if not isinstance(value, dict) or not value:
        raise RuleValidationError(f"Rule {rule_id} condition '{key}' must be a non-empty object")
    if len(value) > MAX_CONDITION_ITEMS:
        raise RuleValidationError(f"Rule {rule_id} condition '{key}' has too many fields")
    for field_name, expected in value.items():
        if not isinstance(field_name, str) or not field_name.strip():
            raise RuleValidationError(f"Rule {rule_id} condition '{key}' contains an invalid field name")
        label = f"Rule {rule_id} condition '{key}.{field_name}'"
        if isinstance(expected, list):
            if not expected:
                raise RuleValidationError(f"{label} must not be an empty list")
            if len(expected) > MAX_CONDITION_ITEMS:
                raise RuleValidationError(f"{label} has too many values")
            for item in expected:
                _condition_scalar(item, label=label)
        else:
            _condition_scalar(expected, label=label)


def _validate_field_contains(rule_id: str, conditions: dict[str, Any]) -> None:
    key = "field_contains"
    if key not in conditions:
        return
    value = conditions[key]
    if not isinstance(value, dict) or not value:
        raise RuleValidationError(f"Rule {rule_id} condition '{key}' must be a non-empty object")
    if len(value) > MAX_CONDITION_ITEMS:
        raise RuleValidationError(f"Rule {rule_id} condition '{key}' has too many fields")
    for field_name, expected in value.items():
        if not isinstance(field_name, str) or not field_name.strip():
            raise RuleValidationError(f"Rule {rule_id} condition '{key}' contains an invalid field name")
        _string_or_string_list(expected, label=f"Rule {rule_id} condition '{key}.{field_name}'")


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
        if len(regexes) > MAX_CONDITION_ITEMS:
            raise RuleValidationError(f"Rule {rule_id} field 'regex' has too many patterns")
        for pattern in regexes:
            _validate_regex(rule_id, pattern)

    for integer_key in ("min_count", "time_window_seconds"):
        if integer_key in conditions:
            value = conditions[integer_key]
            if not isinstance(value, int) or value <= 0:
                raise RuleValidationError(f"Rule {rule_id} condition '{integer_key}' must be a positive integer")

    _validate_field_equals(rule_id, conditions)
    _validate_field_contains(rule_id, conditions)

    for list_key in ("message_contains", "event_type", "source_fields"):
        if list_key in conditions:
            _string_or_string_list(conditions[list_key], label=f"Rule {rule_id} condition '{list_key}'")

    return conditions


def _validate_metadata(rule: dict[str, Any], rule_id: str) -> None:
    tags = rule.get("tags", [])
    if tags is not None:
        values = _string_or_string_list(tags, label=f"Rule {rule_id} field 'tags'", allow_empty=True)
        if len(values) > MAX_TAGS:
            raise RuleValidationError(f"Rule {rule_id} field 'tags' has too many values")

    references = rule.get("references", [])
    if references is not None:
        values = _string_or_string_list(references, label=f"Rule {rule_id} field 'references'", allow_empty=True)
        if len(values) > MAX_REFERENCES:
            raise RuleValidationError(f"Rule {rule_id} field 'references' has too many values")

    false_positives = rule.get("false_positives", [])
    if false_positives is not None:
        _string_or_string_list(false_positives, label=f"Rule {rule_id} field 'false_positives'", allow_empty=True)

    attack_ids = rule.get("mitre_attack", [])
    if attack_ids is not None:
        values = _string_or_string_list(attack_ids, label=f"Rule {rule_id} field 'mitre_attack'", allow_empty=True)
        for attack_id in values:
            if not MITRE_ATTACK_ID.fullmatch(attack_id):
                raise RuleValidationError(f"Rule {rule_id} has invalid MITRE ATT&CK id '{attack_id}'")

    confidence = rule.get("confidence")
    if confidence is not None and (
        not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or confidence < 0 or confidence > 100
    ):
        raise RuleValidationError(f"Rule {rule_id} field 'confidence' must be a number from 0 to 100")


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
    _validate_metadata(rule, rule_id)

    return rule


def _json_files(paths: Iterable[Path]) -> list[Path]:
    files: list[Path] = []
    missing: list[Path] = []
    unsupported: list[Path] = []
    for path in paths:
        if not path.exists():
            missing.append(path)
        elif path.is_dir():
            files.extend(sorted(path.rglob("*.json")))
        elif path.suffix.lower() == ".json":
            files.append(path)
        else:
            unsupported.append(path)
    if missing:
        raise RuleValidationError("Missing path(s): " + ", ".join(str(path) for path in missing))
    if unsupported:
        raise RuleValidationError("Unsupported non-JSON path(s): " + ", ".join(str(path) for path in unsupported))
    return sorted(dict.fromkeys(files))


def _rules_from_payload(payload: Any, source: Path) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("rules"), list):
        return payload["rules"]
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return [payload]
    raise RuleValidationError(f"{source} must contain a rule object, rule list, or {{'rules': [...]}}")


def _load_rule_file(file_path: Path) -> list[dict[str, Any]]:
    if file_path.stat().st_size > MAX_RULE_FILE_BYTES:
        raise RuleValidationError(f"{file_path} is too large")
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuleValidationError(f"{file_path} is not valid JSON: {exc}") from exc
    return _rules_from_payload(payload, file_path)


def load_detection_rules(path: str | Path) -> list[dict[str, Any]]:
    """Recursively load and validate detection rules from a file or directory."""

    files = _json_files([Path(path)])
    if not files:
        raise RuleValidationError(f"No JSON rule files found at {path}")

    rules: list[dict[str, Any]] = []
    seen_ids: dict[str, Path] = {}
    for file_path in files:
        for rule in _load_rule_file(file_path):
            validated = validate_detection_rule(rule)
            rule_id = str(validated["id"])
            if rule_id in seen_ids:
                raise RuleValidationError(f"Duplicate rule id '{rule_id}' in {file_path} and {seen_ids[rule_id]}")
            seen_ids[rule_id] = file_path
            rules.append(validated)
    return rules


def _validate_cli(paths: list[Path], *, output_format: str = "text") -> int:
    results: list[dict[str, Any]] = []
    try:
        files = _json_files(paths)
    except RuleValidationError as exc:
        if output_format == "json":
            print(json.dumps({"ok": False, "errors": [str(exc)], "files": [], "rules_validated": 0}, indent=2, sort_keys=True))
        else:
            print(f"FAIL {exc}", file=sys.stderr)
        return 1
    if not files:
        if output_format == "json":
            print(json.dumps({"ok": False, "errors": ["no JSON files found"], "files": [], "rules_validated": 0}, indent=2, sort_keys=True))
        else:
            print("FAIL no JSON files found", file=sys.stderr)
        return 1

    failures = 0
    total = 0
    seen_ids: dict[str, Path] = {}
    for file_path in files:
        file_result: dict[str, Any] = {"path": str(file_path), "ok": True, "rules": 0, "errors": []}
        try:
            rules = _load_rule_file(file_path)
            for rule in rules:
                validated = validate_detection_rule(rule)
                rule_id = str(validated["id"])
                if rule_id in seen_ids:
                    raise RuleValidationError(f"Duplicate rule id '{rule_id}' also found in {seen_ids[rule_id]}")
                seen_ids[rule_id] = file_path
                total += 1
            file_result["rules"] = len(rules)
            if output_format == "text":
                print(f"PASS {file_path} ({len(rules)} rule{'s' if len(rules) != 1 else ''})")
        except (OSError, RuleValidationError, json.JSONDecodeError) as exc:
            failures += 1
            file_result["ok"] = False
            file_result["errors"].append(str(exc))
            if output_format == "text":
                print(f"FAIL {file_path}: {exc}", file=sys.stderr)
        results.append(file_result)

    if output_format == "json":
        print(
            json.dumps(
                {
                    "ok": failures == 0,
                    "files": results,
                    "rules_validated": total,
                    "file_failures": failures,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(f"Validated {total} rule{'s' if total != 1 else ''}; {failures} file failure{'s' if failures != 1 else ''}.")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate GreyNOC detection rule JSON files.")
    parser.add_argument("paths", nargs="+", type=Path, help="Rule JSON files or directories to validate.")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Validation output format.")
    args = parser.parse_args(argv)
    return _validate_cli(args.paths, output_format=args.format)


if __name__ == "__main__":
    raise SystemExit(main())
