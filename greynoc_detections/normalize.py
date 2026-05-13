"""Security event normalization helpers.

This module only performs public-safe shape normalization. It does not match
rules, score alerts, correlate entities, or build cases.
"""

from __future__ import annotations

import copy
import ipaddress
from datetime import UTC, datetime
from typing import Any

from .constants import SEVERITY_ORDER
from .exceptions import DetectionEventError

MAX_MESSAGE_LENGTH = 10_000
MAX_PROTOCOL_LENGTH = 16
MAX_ID_LENGTH = 256
MAX_HOSTNAME_LENGTH = 255
MAX_USERNAME_LENGTH = 512
MAX_RAW_DEPTH = 8
MAX_RAW_ITEMS = 500
MAX_RAW_STRING_LENGTH = 20_000


def _first(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = payload.get(key)
        if value not in (None, ""):
            return value
    return None


def _clean_text(value: Any, *, max_length: int, field: str) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip()
    if len(text) > max_length:
        raise DetectionEventError(f"Field {field!r} is too long")
    return text


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


def _normalize_ip(value: Any, *, field: str) -> str:
    text = _clean_text(value, max_length=256, field=field)
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _normalize_timestamp(value: Any, *, allow_now_timestamp: bool) -> str:
    if value in (None, ""):
        if allow_now_timestamp:
            return datetime.now(UTC).replace(microsecond=0).isoformat()
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
    return dt.astimezone(UTC).replace(microsecond=0).isoformat()


def _severity(value: Any) -> str:
    clean = str(value or "info").strip().lower()
    return clean if clean in SEVERITY_ORDER else "info"


def _event_type(value: Any, message: str) -> str:
    clean = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    if clean:
        return clean[:128]
    lowered = message.lower()
    if "powershell" in lowered:
        return "process"
    if "login" in lowered or "password" in lowered:
        return "authentication"
    if "port" in lowered or "connection" in lowered:
        return "network"
    return "security_event"


def _bounded_copy(value: Any, *, depth: int = 0) -> Any:
    if depth > MAX_RAW_DEPTH:
        return "<max-depth>"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_RAW_ITEMS:
                result["<truncated>"] = True
                break
            result[str(key)[:MAX_RAW_STRING_LENGTH]] = _bounded_copy(item, depth=depth + 1)
        return result
    if isinstance(value, list):
        return [_bounded_copy(item, depth=depth + 1) for item in value[:MAX_RAW_ITEMS]]
    if isinstance(value, tuple):
        return [_bounded_copy(item, depth=depth + 1) for item in value[:MAX_RAW_ITEMS]]
    if isinstance(value, str):
        return value[:MAX_RAW_STRING_LENGTH]
    try:
        return copy.deepcopy(value)
    except Exception:
        return str(value)[:MAX_RAW_STRING_LENGTH]


def normalize_security_event(payload: dict[str, Any], *, allow_now_timestamp: bool = False) -> dict[str, Any]:
    """Normalize an untrusted security event into a stable public shape."""

    if not isinstance(payload, dict):
        raise DetectionEventError("Security event must be an object")

    event = _bounded_copy(payload)
    message = _clean_text(
        _first(event, "message", "msg", "detail", "event", "command", "process", "action"),
        max_length=MAX_MESSAGE_LENGTH,
        field="message",
    )
    raw_type = _first(event, "event_type", "type", "category")

    return {
        "id": _clean_text(event.get("id"), max_length=MAX_ID_LENGTH, field="id"),
        "timestamp": _normalize_timestamp(
            _first(event, "timestamp", "time", "created_at", "event_time"),
            allow_now_timestamp=allow_now_timestamp,
        ),
        "source_ip": _normalize_ip(_first(event, "source_ip", "src_ip", "client_ip", "remote_ip", "source"), field="source_ip"),
        "destination_ip": _normalize_ip(
            _first(event, "destination_ip", "dest_ip", "dst_ip", "server_ip", "target_ip", "target"),
            field="destination_ip",
        ),
        "source_port": _safe_int(_first(event, "source_port", "src_port", "sport")),
        "destination_port": _safe_int(_first(event, "destination_port", "dest_port", "dst_port", "dport", "port")),
        "protocol": _clean_text(_first(event, "protocol", "proto"), max_length=MAX_PROTOCOL_LENGTH, field="protocol").upper(),
        "hostname": _clean_text(_first(event, "hostname", "host", "computer", "asset"), max_length=MAX_HOSTNAME_LENGTH, field="hostname"),
        "username": _clean_text(_first(event, "username", "user", "account", "principal"), max_length=MAX_USERNAME_LENGTH, field="username"),
        "event_type": _event_type(raw_type, message),
        "severity": _severity(_first(event, "severity", "level", "risk")),
        "message": message,
        "raw_event": event,
    }

