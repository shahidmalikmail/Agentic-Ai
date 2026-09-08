"""P12B: pure, deterministic, fail-closed credential sanitizer for PROD
Commerce log evidence candidates (short strings only - a normalized
message or a would-be excerpt - never a full log body).

No I/O, no SSH, no Kubernetes access, no filesystem, no network, no
environment access, no dependency on ssh_client.py/kube_core.py/
config.py/commerce_tools.py/commerce_log_analyzer.py. Never logs or
persists a candidate value - callers must not print/log a value that was
withheld, and this module never does so itself.

This is deliberately NOT commerce_log_analyzer.redact_secrets(): that
function substitutes "<redacted>" in place and always returns text (a
partial result). This module's contract is the opposite - WHOLE-CANDIDATE
withholding (returns None) the moment ANY forbidden pattern or
high-entropy heuristic fires, never a partially-sanitized string. "Never
partially return a suspicious candidate" (P12B instruction) is the
entire reason this is a separate module rather than an extension of
redact_secrets().

Covers the existing DEV/UAT patterns (password/api_key/secret-or-token/
Bearer/AWS-AKIA/JDBC-password) PLUS the P12B-identified gaps: AWS
secret-access-key/session-token key=value forms, Vault token shapes,
Authorization: Basic, credential-bearing connection-string URIs, PEM
private-key blocks, and a generic high-entropy-token heuristic. This is
NOT an unsafe "detects everything" promise - it is a defense-in-depth
allow-by-exception gate: a candidate is retained only when NONE of these
checks fire, and any uncertainty is resolved by withholding, not by
guessing safe.
"""
from __future__ import annotations

import re
from typing import Optional

# Existing DEV/UAT patterns (see commerce_log_analyzer._SECRET_PATTERNS) -
# reproduced here rather than imported, so this module has zero dependency
# on commerce_log_analyzer.py and can never be affected by a future change
# there (or vice versa). Whole-candidate withholding makes the exact
# substitution text irrelevant anyway - only "did it match" matters here.
_EXISTING_SECRET_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b(api[_-]?key|apikey)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b(secret|token|access[_-]?key|client[_-]?secret)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)authorization:\s*bearer\s+\S+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)jdbc:\S*password=\S+"),
)

# P12B new patterns - the gaps identified in the P12B design report.
_NEW_SECRET_PATTERNS: tuple[re.Pattern, ...] = (
    # AWS secret access key / session token (key=value form; the bare
    # ~40-char secret value itself has no fixed prefix, so it is only
    # reliably caught via its key name - the generic high-entropy
    # heuristic below is the backstop for the bare-value case).
    re.compile(r"(?i)\b(aws[_-]?secret[_-]?access[_-]?key)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b(aws[_-]?session[_-]?token)\b\s*[:=]\s*\S+"),
    # Vault token shapes: legacy "s."/"b." and current "hvs." prefixes,
    # each followed by a long token body - matched directly as a value
    # shape (not requiring a "token=" key name), since these tokens are
    # often logged bare.
    re.compile(r"\bhvs\.[A-Za-z0-9]{20,}\b"),
    re.compile(r"\b[sb]\.[A-Za-z0-9]{24,}\b"),
    # Authorization: Basic <base64> (the existing pattern only covers Bearer).
    re.compile(r"(?i)authorization:\s*basic\s+\S+"),
    # Credential-bearing connection-string URIs: scheme://[user]:pass@host.
    # The username is OPTIONAL (e.g. Redis's common "redis://:pass@host"
    # form has none) - only a password before "@" is required.
    re.compile(r"(?i)\b(postgres|postgresql|redis|amqp|mongodb|mysql)://[^\s:@/]*:[^\s@]+@\S+"),
    # PEM private-key block (multi-line - "." in a character class already
    # matches newlines via [\s\S], no re.DOTALL needed).
    re.compile(r"-----BEGIN(?:\s+\S+)?\s+PRIVATE KEY-----[\s\S]*?-----END(?:\s+\S+)?\s+PRIVATE KEY-----"),
)

_ALL_SECRET_PATTERNS: tuple[re.Pattern, ...] = _EXISTING_SECRET_PATTERNS + _NEW_SECRET_PATTERNS

# Generic high-entropy token heuristic: a long run of base64/hex-alphabet
# characters with no whitespace. This is intentionally coarse and will
# over-trigger on some benign values (e.g. a long pod UID) - that is the
# correct failure direction for a fail-closed sanitizer: a false positive
# only ever withholds a candidate, it never leaks one.
_HIGH_ENTROPY_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9+/_=-]{32,}")
_MIN_CHAR_CLASSES_FOR_ENTROPY = 3  # of {lower, upper, digit, symbol}


def _char_class_count(token: str) -> int:
    classes = 0
    if any(c.islower() for c in token):
        classes += 1
    if any(c.isupper() for c in token):
        classes += 1
    if any(c.isdigit() for c in token):
        classes += 1
    if any(not c.isalnum() for c in token):
        classes += 1
    return classes


def looks_high_entropy(candidate: str) -> bool:
    """True if `candidate` contains a long token-shaped run of characters
    with enough class diversity to plausibly be a credential/secret,
    regardless of whether it sits next to a recognizable key name. A
    coarse heuristic, deliberately biased toward over-triggering (see
    module docstring) rather than under-triggering."""
    for match in _HIGH_ENTROPY_TOKEN_PATTERN.finditer(candidate):
        if _char_class_count(match.group(0)) >= _MIN_CHAR_CLASSES_FOR_ENTROPY:
            return True
    return False


def contains_forbidden_pattern(text: str) -> bool:
    """True if `text` matches any known credential/secret pattern (existing
    DEV/UAT set plus the P12B additions). Never returns the offending
    match - callers must never log/print it either."""
    return any(pattern.search(text) for pattern in _ALL_SECRET_PATTERNS)


def sanitize_candidate(candidate: Optional[str]) -> Optional[str]:
    """The single gate for any short text candidate (a normalized message,
    or a would-be excerpt) considered for retention in PROD Commerce log
    evidence output.

    Returns the candidate UNCHANGED only if it is clean: no known secret
    pattern matches, and no high-entropy token-shaped substring is
    present. Returns None (withhold the ENTIRE candidate, never a
    partially-redacted version of it) if anything is uncertain. None in
    is None out - there is nothing to sanitize.

    This function never logs, prints, or otherwise persists the candidate
    it is given, whether it is retained or withheld."""
    if candidate is None:
        return None
    if contains_forbidden_pattern(candidate):
        return None
    if looks_high_entropy(candidate):
        return None
    return candidate
