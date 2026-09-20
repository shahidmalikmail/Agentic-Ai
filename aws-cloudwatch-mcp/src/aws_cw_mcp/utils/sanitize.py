"""Best-effort redaction of secrets in text returned to the model.

This is a safety net, not a guarantee: logs are free-form text. Everything that
originates from AWS log messages, alarm reasons or error strings passes through
here before leaving the process.
"""
from __future__ import annotations

import re
from typing import Any, Optional

REDACTED = "[REDACTED]"

_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.DOTALL)
_AWS_KEY_ID = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_COOKIE = re.compile(r"(?i)\b(set-cookie|cookie)\s*:\s*[^\r\n]+")
_URL_CREDS = re.compile(r"(://[^/\s:@]+:)([^@\s/]+)(@)")
_KV = re.compile(
    r"(?i)\b([\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|credential|authorization)[\w.-]*)([\"']?\s*[:=]\s*[\"']?)([^\s\"'&,;}]+)")


def sanitize_text(text: Any, max_chars: Optional[int] = None) -> str:
    s = text if isinstance(text, str) else str(text)
    s = _PRIVATE_KEY.sub(f"[{REDACTED} PRIVATE KEY]", s)
    s = _AWS_KEY_ID.sub(f"[{REDACTED} AWS KEY ID]", s)
    s = _JWT.sub(f"[{REDACTED} JWT]", s)
    s = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", s)
    s = _COOKIE.sub(lambda m: f"{m.group(1)}: {REDACTED}", s)
    s = _URL_CREDS.sub(lambda m: f"{m.group(1)}{REDACTED}{m.group(3)}", s)
    s = _KV.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", s)
    if max_chars is not None and len(s) > max_chars:
        s = s[:max_chars] + f"...[truncated {len(s) - max_chars} chars]"
    return s


def sanitize_obj(obj: Any, max_chars: Optional[int] = None) -> Any:
    """Recursively sanitize every string inside dicts/lists/tuples."""
    if isinstance(obj, str):
        return sanitize_text(obj, max_chars)
    if isinstance(obj, dict):
        return {k: sanitize_obj(v, max_chars) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize_obj(v, max_chars) for v in obj]
    return obj
