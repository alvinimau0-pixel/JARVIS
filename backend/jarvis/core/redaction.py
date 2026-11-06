"""Secret redaction for logs, audit records and error messages."""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "[REDACTED]"

_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"xox[abprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}"),
    re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)(--(?:password|passwd|token|secret|api-key)[ =])\S+"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-~+/]{16,}=*"),
    re.compile(r"(?i)((?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*)[^\s,;'\"]+"),
    re.compile(r"([a-z][a-z0-9+.\-]*://[^:/\s@]+:)[^@\s]+(@)"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
]

_SENSITIVE_KEYS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key)"
)

_known: set[str] = set()
_lock = threading.Lock()


def register_secret(value: str | None) -> None:
    """Register an exact secret value (e.g. the session token) so it is always redacted."""
    if value and len(value) >= 8:
        with _lock:
            _known.add(value)


def redact_text(text: str) -> str:
    with _lock:
        known = sorted(_known, key=len, reverse=True)
    for secret in known:
        text = text.replace(secret, REDACTED)
    for pattern in _PATTERNS:
        if pattern.groups >= 1:
            text = pattern.sub(lambda m: _keep_prefix(m), text)
        else:
            text = pattern.sub(REDACTED, text)
    return text


def _keep_prefix(match: re.Match[str]) -> str:
    groups = match.groups()
    prefix = groups[0] or ""
    suffix = groups[1] if len(groups) > 1 and groups[1] else ""
    return f"{prefix}{REDACTED}{suffix}"


def redact(value: Any) -> Any:
    """Recursively redact strings and values under sensitive keys."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and _SENSITIVE_KEYS.search(key):
                out[key] = REDACTED
            else:
                out[key] = redact(item)
        return out
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [redact(item) for item in value]
    return value


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - never let logging crash the app
            return True
        record.msg = redact_text(message)
        record.args = None
        if record.exc_info:
            # Tracebacks can carry secrets in exception messages or local reprs.
            record.exc_text = redact_text(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        return True
