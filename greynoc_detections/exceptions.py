"""Public exceptions raised by GreyNOC detection helpers."""


class DetectionEventError(ValueError):
    """Raised when a security event cannot be normalized safely."""


class RuleValidationError(ValueError):
    """Raised when a detection rule is incomplete, unsupported, or unsafe."""

