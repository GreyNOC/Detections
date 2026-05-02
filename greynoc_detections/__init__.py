"""Public-safe GreyNOC detection rule helpers."""

from .constants import REQUIRED_RULE_FIELDS, SEVERITY_ORDER, SUPPORTED_RULE_TYPES
from .exceptions import DetectionEventError, RuleValidationError
from .normalize import normalize_security_event

__all__ = [
    "DetectionEventError",
    "REQUIRED_RULE_FIELDS",
    "RuleValidationError",
    "SEVERITY_ORDER",
    "SUPPORTED_RULE_TYPES",
    "load_detection_rules",
    "normalize_security_event",
    "validate_detection_rule",
]


def __getattr__(name: str):
    if name in {"load_detection_rules", "validate_detection_rule"}:
        from .validate import load_detection_rules, validate_detection_rule

        return {
            "load_detection_rules": load_detection_rules,
            "validate_detection_rule": validate_detection_rule,
        }[name]
    raise AttributeError(f"module 'greynoc_detections' has no attribute {name!r}")
