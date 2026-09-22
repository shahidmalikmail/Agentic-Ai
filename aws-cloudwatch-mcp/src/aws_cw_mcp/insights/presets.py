"""Server-owned, reviewed match presets and bin table.

Claude only ever names a preset id. The regexes live here, use a deliberately tiny character set
(no '/', no quotes, no newlines) and are the only regexes that reach a query, so a caller can never
inject one. Regexes are matched against @message and are case-insensitive where useful.
"""
from __future__ import annotations

import re

# Character classes shared with the validator (single source of truth).
LITERAL_CHARS = r"A-Za-z0-9 _.:=@\-"          # user 'contains'/'exclude' literals (rendered as "quoted strings")
REGEX_CHARS = r"A-Za-z0-9_ ().|?\\\-"          # preset regex bodies
LITERAL_RE = re.compile(rf"[{LITERAL_CHARS}]{{1,64}}")
REGEX_BODY_RE = re.compile(rf"[{REGEX_CHARS}]{{1,300}}")

PRESETS: dict = {
    "errors": r"(?i)(error|exception|fatal|severe)",
    "exceptions": r"(?i)(exception|stack ?trace|traceback|caused by)",
    "timeouts": r"(?i)(timeout|timed out|deadline exceeded)",
    "connection_problems": r"(?i)(connection refused|connection reset|broken pipe|unable to connect|no route to host)",
    "http_4xx": r"\b(400|401|403|404|405|408|409|410|413|414|429)\b",
    "http_5xx": r"\b(500|501|502|503|504)\b",
    "oom": r"(?i)(out ?of ?memory|oomkilled|oom-killed|java heap space|cannot allocate memory)",
    "auth_failures": r"(?i)(unauthorized|forbidden|authentication failed|access denied|invalid credentials|login failed)",
    "tls_errors": r"(?i)(handshake failure|certificate (expired|verify failed)|ssl error|tls error)",
    "dns_errors": r"(?i)(unknownhost|unknown host|name or service not known|nxdomain|dns resolution)",
}
PRESET_IDS = tuple(PRESETS)

BIN_LABELS = {60: "1m", 300: "5m", 900: "15m", 1800: "30m", 3600: "1h"}
ALLOWED_BINS = tuple(BIN_LABELS)


def default_bin_seconds(range_seconds: int) -> int:
    """<=1h -> 1m, <=6h -> 5m, <=24h -> 15m, else 1h (series stays under ~170 buckets)."""
    if range_seconds <= 3600:
        return 60
    if range_seconds <= 6 * 3600:
        return 300
    if range_seconds <= 24 * 3600:
        return 900
    return 3600


def bucket_count(start_s: int, end_s: int, bin_seconds: int) -> int:
    """Number of aligned bins that overlap [start_s, end_s)."""
    first = start_s // bin_seconds
    last = (end_s - 1) // bin_seconds
    return last - first + 1


def expected_bin_count(start_s: int, end_s: int, bin_seconds: int) -> int:
    """Aligned bins that can hold events for a Logs Insights query over [start_s, end_s] INCLUSIVE.

    CloudWatch Logs Insights treats BOTH startTime and endTime as inclusive (StartQuery docs; confirmed by real
    validation: a bin stamped exactly at endTime was returned). So an event at exactly end_s is counted, and when
    end_s lies exactly on a bin boundary that boundary bin exists. For windows that end mid-bin this equals
    bucket_count(); it is one larger only when end_s is exactly on a bin boundary.

    Single source of truth for: the count_over_time row cap and API `limit` (validator) and the expected-bin
    statistics (analysis.insights_stats). bucket_count() above (half-open) is intentionally left unchanged."""
    return end_s // bin_seconds - start_s // bin_seconds + 1
