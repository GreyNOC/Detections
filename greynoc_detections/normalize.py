"""Security event normalization helpers.

This module only performs public-safe shape normalization. It does not match
rules, score alerts, correlate entities, or build cases.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .constants import SEVERITY_ORDER
from .exceptions import DetectionEventError


def _first(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = payload.get(key)
        if value not in (None, ""):
            return value
    return None


def _safe_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise DetectionEventError(f"Invalid integer value: {value!r}") from exc
    if parsed < 0 or parsed > 65535:
        raise DetectionEventError(f"Port value out of range: {parsed}")
    return parsed


def _normalize_timestamp(value: Any, *, allow_now_timestamp: bool) -> str:
    if value in (None, ""):
        if allow_now_timestamp:
            return datetime.now(UTC).isoformat()
        raise DetectionEventError("Missing timestamp")
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value).strip()
        if raw.endswith("Z"):
            raw = f"{raw[:-1]}+00:00"
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError as exc:
            raise DetectionEventError(f"Invalid timestamp: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat()


def _severity(value: Any) -> str:
    clean = str(value or "info").strip().lower()
    return clean if clean in SEVERITY_ORDER else "info"


def _event_type(value: Any, message: str) -> str:
    clean = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    if clean:
        return clean
    lowered = message.lower()
    if "powershell" in lowered:
        return "process"
    if "login" in lowered or "password" in lowered:
        return "authentication"
    if "port" in lowered or "connection" in lowered:
        return "network"
    return "security_event"


def normalize_security_event(payload: dict[str, Any], *, allow_now_timestamp: bool = False) -> dict[str, Any]:
    """Normalize an untrusted security event into a stable public shape."""

    if not isinstance(payload, dict):
        raise DetectionEventError("Security event must be an object")

    event = dict(payload)
    message = str(_first(event, "message", "msg", "detail", "event", "command", "process", "action") or "")
    raw_type = _first(event, "event_type", "type", "category")

    return {
        "id": str(event.get("id") or ""),
        "timestamp": _normalize_timestamp(
            _first(event, "timestamp", "time", "created_at", "event_time"),
            allow_now_timestamp=allow_now_timestamp,
        ),
        "source_ip": str(_first(event, "source_ip", "src_ip", "client_ip", "remote_ip", "source") or ""),
        "destination_ip": str(
            _first(event, "destination_ip", "dest_ip", "dst_ip", "server_ip", "target_ip", "target") or ""
        ),
        "source_port": _safe_int(_first(event, "source_port", "src_port", "sport")),
        "destination_port": _safe_int(_first(event, "destination_port", "dest_port", "dst_port", "dport", "port")),
        "protocol": str(_first(event, "protocol", "proto") or "").upper(),
        "hostname": str(_first(event, "hostname", "host", "computer", "asset") or ""),
        "username": str(_first(event, "username", "user", "account", "principal") or ""),
        "event_type": _event_type(raw_type, message),
        "severity": _severity(_first(event, "severity", "level", "risk")),
        "message": message,
        "raw_event": event,
    }

