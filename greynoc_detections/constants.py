"""Constants for public GreyNOC detection rule validation."""

SUPPORTED_RULE_TYPES = frozenset(
    {
        "port_scan",
        "brute_force",
        "malware_beaconing",
        "suspicious_powershell",
        "scan_finding",
        "ai_user_agent_abuse",
    }
)

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

REQUIRED_RULE_FIELDS = (
    "id",
    "type",
    "title",
    "severity",
    "description",
    "recommended_action",
    "conditions",
)

CONDITION_FIELDS = frozenset(
    {
        "event_type",
        "message_contains",
        "field_equals",
        "field_contains",
        "regex",
        "min_count",
        "time_window_seconds",
        "source_fields",
    }
)

