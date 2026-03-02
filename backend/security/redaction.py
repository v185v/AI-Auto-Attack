from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import re
from typing import Any

from backend.core.config import get_settings


DEFAULT_SENSITIVE_KEYS = {
    "authorization",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "password",
    "passwd",
    "secret",
    "client_secret",
    "private_key",
    "signing_key",
}

_BEARER_RE = re.compile(r"(?i)(bearer\s+)([a-z0-9._\-+/=]+)")
_KV_SECRET_RE = re.compile(r"(?i)\b(token|api[-_]?key|password|secret)\b\s*[:=]\s*([^\s,;]+)")
_URL_CRED_RE = re.compile(r"(?i)(https?://)([^:/\s]+):([^@/\s]+)@")


@dataclass(frozen=True)
class RedactionSettings:
    enabled: bool
    mask: str
    sensitive_keys: set[str]


def redact_payload(payload: Any, settings: RedactionSettings | None = None) -> Any:
    active = settings or get_redaction_settings()
    if not active.enabled:
        return payload
    return _redact_value(payload, active)


def redact_text(value: str, settings: RedactionSettings | None = None) -> str:
    active = settings or get_redaction_settings()
    if not active.enabled:
        return value
    text = str(value)
    text = _URL_CRED_RE.sub(lambda m: f"{m.group(1)}{active.mask}:{active.mask}@", text)
    text = _BEARER_RE.sub(lambda m: f"{m.group(1)}{active.mask}", text)
    text = _KV_SECRET_RE.sub(lambda m: f"{m.group(1)}={active.mask}", text)
    return text


def _redact_value(value: Any, settings: RedactionSettings) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, raw in value.items():
            key_str = str(key)
            if _is_sensitive_key(key_str, settings):
                result[key_str] = settings.mask
            else:
                result[key_str] = _redact_value(raw, settings)
        return result
    if isinstance(value, list):
        return [_redact_value(item, settings) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item, settings) for item in value)
    if isinstance(value, str):
        return redact_text(value, settings)
    return value


def _is_sensitive_key(key: str, settings: RedactionSettings) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    if normalized in settings.sensitive_keys:
        return True
    for marker in ("token", "secret", "password", "apikey", "api_key"):
        if marker in normalized:
            return True
    return False


@lru_cache(maxsize=1)
def get_redaction_settings() -> RedactionSettings:
    settings = get_settings()
    security = settings.get("security", {})
    redaction = security.get("redaction", {})
    configured = redaction.get("sensitive_keys", [])
    keys = {str(item).strip().lower().replace("-", "_") for item in configured if str(item).strip()}
    keys.update(DEFAULT_SENSITIVE_KEYS)
    return RedactionSettings(
        enabled=bool(redaction.get("enabled", True)),
        mask=str(redaction.get("mask", "***REDACTED***")),
        sensitive_keys=keys,
    )


def clear_redaction_cache() -> None:
    get_redaction_settings.cache_clear()
