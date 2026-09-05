"""Pure log-text classification for HCL Commerce components.

No SSH/I-O here - operates only on log text already fetched via the
existing read-only `get_pod_logs` path. This module produces EVIDENCE
(category + count + sample lines), never a root-cause claim - that
synthesis happens in commerce_tools.diagnose_commerce_issue, using
commerce_knowledge for any general guidance.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
from typing import Optional

_MAX_EVIDENCE_LINES_PER_CATEGORY = 8
_MAX_EVIDENCE_LINE_CHARS = 500

# Evaluated in order per line; the FIRST matching category wins, so more
# specific/high-signal categories are listed before generic catch-alls
# (e.g. a Redis connection exception should land in "redis_error", not the
# generic "exception"/"generic_error" buckets).
_RULES: tuple[tuple[str, re.Pattern], ...] = (
    ("oom_killed", re.compile(r"\bOOMKilled\b", re.IGNORECASE)),
    ("crash_loop", re.compile(r"\bCrashLoopBackOff\b", re.IGNORECASE)),
    ("readiness_liveness_failure", re.compile(
        r"\b(readiness|liveness)\s+probe\s+(failed|error)\b", re.IGNORECASE)),
    ("scheduling_failure", re.compile(
        r"\b(FailedScheduling|Insufficient\s+(cpu|memory)|no\s+nodes\s+available)\b",
        re.IGNORECASE)),
    ("redis_error", re.compile(
        r"\bredis\b.*\b(error|exception|timeout|refused)\b|\bNOAUTH\b|\bWRONGTYPE\b",
        re.IGNORECASE)),
    # No trailing \b after the product name: Java exception class names
    # glue it directly to the rest of the word (e.g. "SolrServerException").
    ("search_error", re.compile(
        r"\b(solr|elasticsearch|elastic\s*search).*\b(error|exception|failed|timeout)\b",
        re.IGNORECASE)),
    ("database_error", re.compile(
        r"\b(sqlexception|sql\s+error|deadlock\s+detected|ora-\d{4,5}|db2\s?\d{4,5}|"
        r"connection\s+pool\s+exhausted|jdbc\S*\s*(error|exception))\b", re.IGNORECASE)),
    ("authentication_failure", re.compile(
        r"\b(authentication\s+failed|unauthorized|401|invalid\s+credentials|"
        r"access\s+denied|login\s+failed)\b", re.IGNORECASE)),
    ("connection_failure", re.compile(
        r"\b(connection\s+refused|connection\s+reset|connection\s+closed|"
        r"unable\s+to\s+connect|no\s+route\s+to\s+host|could\s+not\s+connect)\b",
        re.IGNORECASE)),
    ("timeout", re.compile(r"\b(timeout|timed\s+out)\b", re.IGNORECASE)),
    ("upstream_downstream_failure", re.compile(
        r"\b(upstream|downstream|backend)\b.*\b(error|unavailable|failed|refused)\b",
        re.IGNORECASE)),
    ("http_5xx", re.compile(r'"\s*5\d{2}\b|status(?:Code)?[=:\s]+5\d{2}\b')),
    ("http_4xx", re.compile(r'"\s*4\d{2}\b|status(?:Code)?[=:\s]+4\d{2}\b')),
    ("stack_trace", re.compile(r"^\s*at\s+[\w.$]+\(.*\)\s*$")),
    ("jvm_application_error", re.compile(
        r"\b(OutOfMemoryError|StackOverflowError|NoClassDefFoundError|FATAL|SEVERE)\b")),
    ("exception", re.compile(r"\b[\w.$]*Exception\b")),
    ("generic_error", re.compile(r"\bERROR\b")),
)

# Secret-like values redacted before any log text or evidence line leaves
# this layer. Whole-match redaction (not partial) to avoid leaking a
# trailing fragment of the secret through clever regex overlap.
_SECRET_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b(api[_-]?key|apikey)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)\b(secret|token|access[_-]?key|client[_-]?secret)\b\s*[:=]\s*\S+"),
    re.compile(r"(?i)authorization:\s*bearer\s+\S+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)jdbc:\S*password=\S+"),
)


def redact_secrets(text: str) -> str:
    """Replace secret-like substrings (passwords/tokens/API keys/AWS access
    key IDs/Bearer headers/JDBC passwords) with a fixed placeholder."""
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("<redacted>", redacted)
    return redacted


# Dedup normalization: two log lines that differ only by a timestamp, a
# UUID, or a long numeric ID are treated as the "same" message. Numeric
# normalization requires 4+ consecutive digits specifically so it never
# swallows a 3-digit HTTP status code (404/500), which is meaningful
# signal, not noise.
_TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\[\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\]"
)
_UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_LONG_NUMBER_PATTERN = re.compile(r"\b\d{4,}\b")


def _normalize_for_dedup(line: str) -> str:
    """Collapse variable tokens (timestamp/UUID/long numeric id) to fixed
    placeholders so structurally-identical messages compare equal. This key
    is used only for grouping - the original (redacted) line is what's
    kept as the sample."""
    normalized = _TIMESTAMP_PATTERN.sub("<TS>", line)
    normalized = _UUID_PATTERN.sub("<UUID>", normalized)
    normalized = _LONG_NUMBER_PATTERN.sub("<NUM>", normalized)
    return normalized


# --------------------------------------------------------------------------
# Timestamp parsing (Phase 4A). Built on the SAME shape as the dedup-only
# _TIMESTAMP_PATTERN above, but with capture groups, kept as a separate
# compiled pattern so dedup behavior (which only needs a match span, not
# parsed values) is never touched by this addition.
# --------------------------------------------------------------------------

_ABSOLUTE_TS_PATTERN = re.compile(
    r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})"
    r"[T ]"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:[.,](?P<frac>\d+))?"
    r"(?:(?P<tz>Z|[+-]\d{2}:?\d{2})|\s(?P<tz_abbrev>[A-Z]{2,5}))?"
)
_TIME_ONLY_TS_PATTERN = re.compile(
    r"\[(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:[.,](?P<frac>\d+))?\]"
)

# --------------------------------------------------------------------------
# Additional real-world absolute formats (live DEV/UAT validation, see
# project notes). Each is its own dedicated pattern/builder - deliberately
# NOT folded into _ABSOLUTE_TS_PATTERN above, since their date grammars
# (slash order, month NAME vs number, bracket conventions) are mutually
# incompatible with the ISO shape and with each other. Tried in order by
# parse_timestamp() after the ISO pattern; a syntactic match that fails to
# form a valid date/time (e.g. month=13) returns None immediately, same
# fail-fast contract as the original ISO pattern - it does not fall
# through to try a different format on the same text.
#
# Deliberately NOT handled here (see parse_timestamp() docstring): the
# nginx ingress controller's klog format, e.g. "W0905 08:43:54.365747" -
# it carries no year at all, and inventing one would violate the "never
# fabricate a year" rule. parse_timestamp() returns None for it.
# --------------------------------------------------------------------------

_MONTH_ABBR: dict[str, int] = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# Small, explicit, hand-verified map of timezone ABBREVIATIONS this code
# knows a real fixed UTC offset for - deliberately not a general tz
# database. An abbreviation not in this map is left unresolved (never
# guessed) - see _build_tzinfo_from_abbrev.
_TZ_ABBREVIATIONS: dict[str, timedelta] = {
    "AEST": timedelta(hours=10),
    "AEDT": timedelta(hours=11),
}

# WebSphere Liberty bracketed log format, e.g.
# "[9/5/26 18:42:57:144 AEST]" - M/D/YY (NOT ISO year-month-day order),
# a COLON (not a dot) before milliseconds, optional trailing tz
# abbreviation. Two-digit year is resolved via datetime.strptime's own
# "%y" rule (see _parse_liberty_absolute) - never today's date.
_LIBERTY_TS_PATTERN = re.compile(
    r"\[(?P<month>\d{1,2})/(?P<day>\d{1,2})/(?P<year2>\d{2})\s"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}):(?P<frac>\d+)"
    r"(?:\s(?P<tz_abbrev>[A-Z]{2,5}))?\]"
)

# nginx error log, e.g. "2026/09/05 08:43:08 [notice] ..." - slash-
# separated YYYY/MM/DD, unbracketed, no fractional seconds, no timezone
# ever observed live.
_NGINX_ERROR_TS_PATTERN = re.compile(
    r"(?P<year>\d{4})/(?P<month>\d{2})/(?P<day>\d{2})\s"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
)

# nginx access/combined log, e.g. "[05/Sep/2026:08:49:51 +0000]" -
# month NAME (not number), colon date/time separator, numeric offset.
_NGINX_COMBINED_TS_PATTERN = re.compile(
    r"\[(?P<day>\d{2})/(?P<monname>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"\s(?P<tz>[+-]\d{2}:?\d{2})\]"
)

# Redis, e.g. "1:M 05 Sep 2026 08:42:42.657 # ..." - "DD Mon YYYY
# HH:MM:SS[.frac]", no timezone ever observed live.
_REDIS_TS_PATTERN = re.compile(
    r"\b(?P<day>\d{2})\s(?P<monname>[A-Za-z]{3})\s(?P<year>\d{4})\s"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<frac>\d+))?"
)


@dataclass(frozen=True)
class ParsedTimestamp:
    """Result of parse_timestamp() - never fabricated, never guessed.

    kind="absolute": a full date+time was present. `value` is a real
    datetime - timezone-AWARE (UTC for "Z", or the parsed +/-HH:MM
    offset) when the source text included a timezone marker, or
    timezone-NAIVE (tzinfo=None) when it did not. `timezone_known`
    records which case applied - a naive `value` must never be silently
    treated as UTC or local time by a caller.

    kind="time_only": a bracketed [HH:MM:SS] time-of-day was present with
    NO date. `partial_time` holds it as a `datetime.time`; `value` is
    always None for this kind - no date is ever invented to make it
    absolute."""

    raw: str
    kind: str  # "absolute" | "time_only"
    value: Optional[datetime] = None
    timezone_known: bool = False
    partial_time: Optional[time] = None


def _build_microsecond(frac: Optional[str]) -> int:
    if not frac:
        return 0
    return int(frac.ljust(6, "0")[:6])


def _build_tzinfo(tz_raw: Optional[str]) -> tuple[Optional[timezone], bool]:
    """Returns (tzinfo, timezone_known). tzinfo is None (naive) when the
    source text had no timezone marker at all - this is NOT the same as
    "assume UTC"/"assume local"; timezone_known=False tells the caller
    the offset is genuinely unknown."""
    if not tz_raw:
        return None, False
    if tz_raw == "Z":
        return timezone.utc, True
    sign = 1 if tz_raw[0] == "+" else -1
    digits = tz_raw[1:].replace(":", "")
    off_hours = int(digits[:2])
    off_minutes = int(digits[2:4]) if len(digits) >= 4 else 0
    return timezone(sign * timedelta(hours=off_hours, minutes=off_minutes)), True


def _build_tzinfo_from_abbrev(abbrev: Optional[str]) -> tuple[Optional[timezone], bool]:
    """Resolve a timezone ABBREVIATION (e.g. "AEST") against the small,
    explicit _TZ_ABBREVIATIONS map - never a guess. No abbreviation, or
    one this code has no verified offset for, returns (None, False) -
    identical to "no timezone in the source text at all": the safe
    behavior is to leave the datetime naive rather than invent an
    offset for a zone name this code doesn't actually know."""
    if not abbrev:
        return None, False
    offset = _TZ_ABBREVIATIONS.get(abbrev.upper())
    if offset is None:
        return None, False
    return timezone(offset), True


def _build_month_from_name(name: Optional[str]) -> Optional[int]:
    """Resolve a 3-letter month name (e.g. "Sep") via the small, explicit
    _MONTH_ABBR map. Returns None (never raises, never guesses) for
    anything not in it."""
    if not name:
        return None
    return _MONTH_ABBR.get(name.lower())


def _parse_iso_absolute(line: str) -> Optional[ParsedTimestamp]:
    """Original ISO-family absolute pattern: YYYY-MM-DD[T/space]HH:MM:SS,
    with an optional numeric offset/Z OR (new) a trailing timezone
    ABBREVIATION (e.g. the "AEST" HCL Commerce/tooling-web logs carry) -
    see _ABSOLUTE_TS_PATTERN. Exactly the original behavior when no tz
    marker of either kind is present or recognized."""
    match = _ABSOLUTE_TS_PATTERN.search(line)
    if not match:
        return None
    try:
        if match.group("tz"):
            tzinfo, timezone_known = _build_tzinfo(match.group("tz"))
        else:
            tzinfo, timezone_known = _build_tzinfo_from_abbrev(match.group("tz_abbrev"))
        value = datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            _build_microsecond(match.group("frac")),
            tzinfo=tzinfo,
        )
    except ValueError:
        return None
    return ParsedTimestamp(
        raw=match.group(0), kind="absolute", value=value, timezone_known=timezone_known
    )


def _parse_liberty_absolute(line: str) -> Optional[ParsedTimestamp]:
    """WebSphere Liberty bracketed format - see _LIBERTY_TS_PATTERN. The
    two-digit year is resolved via datetime.strptime's own "%y" rule
    (Python/POSIX convention: 00-68 -> 2000-2068, 69-99 -> 1969-1999) -
    a fixed, deterministic, standard-library interpretation, never
    today's date and never custom rolling-year logic."""
    match = _LIBERTY_TS_PATTERN.search(line)
    if not match:
        return None
    try:
        base = datetime.strptime(
            f"{match.group('month')}/{match.group('day')}/{match.group('year2')}", "%m/%d/%y"
        )
        tzinfo, timezone_known = _build_tzinfo_from_abbrev(match.group("tz_abbrev"))
        value = base.replace(
            hour=int(match.group("hour")),
            minute=int(match.group("minute")),
            second=int(match.group("second")),
            microsecond=_build_microsecond(match.group("frac")),
            tzinfo=tzinfo,
        )
    except ValueError:
        return None
    return ParsedTimestamp(
        raw=match.group(0), kind="absolute", value=value, timezone_known=timezone_known
    )


def _parse_nginx_combined_absolute(line: str) -> Optional[ParsedTimestamp]:
    """nginx access/combined log format - see _NGINX_COMBINED_TS_PATTERN."""
    match = _NGINX_COMBINED_TS_PATTERN.search(line)
    if not match:
        return None
    month = _build_month_from_name(match.group("monname"))
    if month is None:
        return None
    try:
        tzinfo, timezone_known = _build_tzinfo(match.group("tz"))
        value = datetime(
            int(match.group("year")),
            month,
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            tzinfo=tzinfo,
        )
    except ValueError:
        return None
    return ParsedTimestamp(
        raw=match.group(0), kind="absolute", value=value, timezone_known=timezone_known
    )


def _parse_nginx_error_absolute(line: str) -> Optional[ParsedTimestamp]:
    """nginx error log format - see _NGINX_ERROR_TS_PATTERN. No timezone
    ever observed live, so timezone_known is always False for this
    format - never fabricated."""
    match = _NGINX_ERROR_TS_PATTERN.search(line)
    if not match:
        return None
    try:
        value = datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
        )
    except ValueError:
        return None
    return ParsedTimestamp(raw=match.group(0), kind="absolute", value=value, timezone_known=False)


def _parse_redis_absolute(line: str) -> Optional[ParsedTimestamp]:
    """Redis log format - see _REDIS_TS_PATTERN. No timezone ever
    observed live, so timezone_known is always False for this format -
    never fabricated."""
    match = _REDIS_TS_PATTERN.search(line)
    if not match:
        return None
    month = _build_month_from_name(match.group("monname"))
    if month is None:
        return None
    try:
        value = datetime(
            int(match.group("year")),
            month,
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            _build_microsecond(match.group("frac")),
        )
    except ValueError:
        return None
    return ParsedTimestamp(raw=match.group(0), kind="absolute", value=value, timezone_known=False)


# Tried in this order by parse_timestamp() - see the module note above
# _MONTH_ABBR for why these are separate, non-overlapping parsers rather
# than one mega-pattern.
_ABSOLUTE_PARSERS = (
    _parse_iso_absolute,
    _parse_liberty_absolute,
    _parse_nginx_combined_absolute,
    _parse_nginx_error_absolute,
    _parse_redis_absolute,
)


def parse_timestamp(line: str) -> Optional[ParsedTimestamp]:
    """Extract a timestamp from one line of text (a log line, or a single
    Kubernetes event timestamp field), if present. Pure - no I/O, no
    guessing:

    - An absolute (dated) timestamp is returned only when a full date+time
      matching one of the KNOWN real-world formats is actually present in
      the text: the original ISO family (YYYY-MM-DD[T/space]HH:MM:SS,
      optional Z/numeric-offset/timezone-abbreviation), WebSphere Liberty's
      bracketed "[M/D/YY H:MM:SS:mmm [TZ]]", nginx's error-log
      "YYYY/MM/DD HH:MM:SS", nginx's access/combined-log
      "[DD/Mon/YYYY:HH:MM:SS +ZZZZ]", or Redis's "DD Mon YYYY
      HH:MM:SS[.frac]" - see _ABSOLUTE_PARSERS. Each is tried in order;
      the first one whose pattern matches decides the outcome for that
      line (fail-fast: a syntactic match that fails to form a valid
      date/time returns None immediately, it does not fall through to a
      different format).
    - A timezone ABBREVIATION (e.g. "AEST"/"AEDT") is resolved only
      against the small, explicit _TZ_ABBREVIATIONS map - an unrecognized
      abbreviation is never guessed into an offset; timezone_known stays
      False exactly as if no timezone text were present at all.
    - Deliberately NOT handled: the nginx ingress controller's klog format
      (e.g. "W0905 08:43:54.365747") carries no year at all - inventing
      one would fabricate information this function must never fabricate,
      so it is left unparsed (returns None) rather than given a new kind.
    - A bracketed [HH:MM:SS] time-only prefix is returned as an
      explicitly non-absolute partial time (kind="time_only") - it is
      NEVER promoted to a fake absolute timestamp by assuming today's
      date or any other date.
    - Returns None (never raises) when nothing timestamp-shaped is found,
      or when what looks like one doesn't form a valid date/time (e.g.
      month=13, hour=99) - a malformed timestamp is treated the same as
      a missing one, not as an error."""
    for parser in _ABSOLUTE_PARSERS:
        result = parser(line)
        if result is not None:
            return result

    match = _TIME_ONLY_TS_PATTERN.search(line)
    if match:
        try:
            partial = time(
                int(match.group("hour")),
                int(match.group("minute")),
                int(match.group("second")),
                _build_microsecond(match.group("frac")),
            )
        except ValueError:
            return None
        return ParsedTimestamp(raw=match.group(0), kind="time_only", partial_time=partial)

    return None


@dataclass(frozen=True)
class EvidenceSample:
    """The structured counterpart to one string in CategoryFinding.evidence
    - same (redacted, capped) text, plus its parsed timestamp if any. Kept
    separate from CategoryFinding.evidence (which stays list[str] for
    backward compatibility) so existing consumers are unaffected; a
    caller building a timeline reads this instead. Never serialize this
    dataclass directly into JSON - convert it to a plain dict first."""

    text: str
    timestamp: Optional[ParsedTimestamp] = None


# Fixed severity tiers, independent of how often a category fires - a
# single oom_killed/crash_loop signal outranks 300 generic_error lines.
# Count is used only to break ties within the same tier.
_SEVERITY_HIGH = frozenset(
    {
        "oom_killed",
        "crash_loop",
        "scheduling_failure",
        "readiness_liveness_failure",
        "connection_failure",
        "database_error",
        "redis_error",
        "search_error",
    }
)
_SEVERITY_MEDIUM = frozenset(
    {
        "timeout",
        "authentication_failure",
        "upstream_downstream_failure",
        "http_5xx",
        "exception",
        "stack_trace",
    }
)
_SEVERITY_LOW = frozenset({"generic_error", "http_4xx"})

_SEVERITY_RANK: dict[str, int] = {
    **{c: 0 for c in _SEVERITY_HIGH},
    **{c: 1 for c in _SEVERITY_MEDIUM},
    **{c: 2 for c in _SEVERITY_LOW},
}
_SEVERITY_NAME_BY_RANK = ("high", "medium", "low")


def severity_rank(category: str) -> int:
    """Lower = more severe (0=high, 1=medium, 2=low). Public so callers can
    sort a mix of log- and event-derived findings by the same tiers this
    module uses internally. Unknown/future category names default to 1
    (medium) - never silently the lowest tier."""
    return _SEVERITY_RANK.get(category, 1)


def severity_of(category: str) -> str:
    """Public so commerce_tools can tag event-derived findings (which are
    classified via classify_log_text too) with the same vocabulary as
    log-derived ones. Unknown/future category names default to "medium" -
    never silently "low", so an unrecognized category isn't buried."""
    return _SEVERITY_NAME_BY_RANK[severity_rank(category)]


@dataclass
class CategoryFinding:
    category: str
    count: int
    """Total matching lines - kept for backward compatibility; identical to
    total_occurrences."""
    total_occurrences: int
    distinct_messages: int
    """Number of distinct normalized messages within this category (see
    _normalize_for_dedup) - the whole point of deduplication: a category
    with count=500 but distinct_messages=2 is one repeating problem, not
    500 different ones."""
    evidence: list[str] = field(default_factory=list)
    """Up to _MAX_EVIDENCE_LINES_PER_CATEGORY samples, one per DISTINCT
    normalized message (not just the first N raw lines), redacted and
    length-capped. UNCHANGED shape/content from before Phase 4A - kept
    for backward compatibility with every existing caller."""

    evidence_detail: list[EvidenceSample] = field(default_factory=list)
    """Phase 4A addition: the SAME samples as `evidence`, in the same
    order, but paired with each sample's parsed timestamp (if any) - see
    EvidenceSample/parse_timestamp. Purely additive; nothing reads or
    writes this except commerce_tools.assemble_timeline(). Not JSON-safe
    on its own - never serialize it directly."""


@dataclass
class AnalysisResult:
    total_lines: int
    findings: list[CategoryFinding]

    @property
    def total_matches(self) -> int:
        return sum(f.count for f in self.findings)


def classify_log_text(text: str) -> AnalysisResult:
    """Classify each non-blank line of `text` into at most one evidence
    category (first matching rule wins). Within a category, equivalent
    messages (differing only by timestamp/UUID/long numeric id) are
    deduplicated: `count`/`total_occurrences` still reflect every matching
    line, but `evidence` holds only distinct samples, up to
    _MAX_EVIDENCE_LINES_PER_CATEGORY. Findings are sorted by fixed severity
    tier first, matching-line count only as a tiebreaker."""
    counts: dict[str, int] = {}
    # category -> {normalized_key: first-seen EvidenceSample}
    distinct_by_category: dict[str, dict[str, EvidenceSample]] = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        for category, pattern in _RULES:
            if pattern.search(line):
                counts[category] = counts.get(category, 0) + 1
                bucket = distinct_by_category.setdefault(category, {})
                key = _normalize_for_dedup(line)
                if key not in bucket:
                    bucket[key] = EvidenceSample(
                        text=redact_secrets(line)[:_MAX_EVIDENCE_LINE_CHARS],
                        timestamp=parse_timestamp(line),
                    )
                break

    findings = []
    for cat, count in counts.items():
        samples = list(distinct_by_category.get(cat, {}).values())[:_MAX_EVIDENCE_LINES_PER_CATEGORY]
        findings.append(
            CategoryFinding(
                category=cat,
                count=count,
                total_occurrences=count,
                distinct_messages=len(distinct_by_category.get(cat, {})),
                evidence=[s.text for s in samples],
                evidence_detail=samples,
            )
        )
    findings.sort(key=lambda f: (severity_rank(f.category), -f.count))
    return AnalysisResult(total_lines=len(text.splitlines()), findings=findings)
