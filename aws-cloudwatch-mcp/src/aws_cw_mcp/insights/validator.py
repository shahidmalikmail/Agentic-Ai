"""Query validation: an allow-list, fail-closed gate between the planner and AWS.

Stage A (validate_plan): structured checks - groups, allowlist, range, vocabulary, limits.
Stage B (validate_query_text): the rendered string must be built ONLY from approved stage shapes.
Rather than a permissive tokenizer, every pipeline stage must FULL-MATCH one of a handful of anchored
shapes the templates emit; anything else - including any command the language may add in future -
is rejected. Blocked commands are named for clearer errors, but the shape whitelist is the real defence.
The validator is also the only component that registers requests in the ApprovedQueryRegistry.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Optional

from aws_cw_mcp.config import Config, INSIGHTS_HARD_RANGE_HOURS
from aws_cw_mcp.insights import templates
from aws_cw_mcp.insights.plans import (DIM_STATUS_CODE, DIMENSIONS, KIND_COUNT_BY, KIND_COUNT_OVER_TIME,
                                       KIND_SAMPLE_EVENTS, KINDS, QUERY_LANGUAGE, QueryPlan,
                                       plan_cache_key, request_fingerprint)
from aws_cw_mcp.insights.presets import (ALLOWED_BINS, LITERAL_CHARS, LITERAL_RE, PRESETS, REGEX_CHARS,
                                         expected_bin_count)
from aws_cw_mcp.insights.registry import ApprovedQueryRegistry
from aws_cw_mcp.utils.errors import QueryRejected

_GROUP_RE = re.compile(r"^[\.\-_/#A-Za-z0-9]{1,512}$")   # AWS pattern for logGroupNames [V]
MAX_CONTAINS = 3
MAX_EXCLUDE = 3
MAX_STATUS_CODES = 8
MAX_SAMPLE_LIMIT = 20
MAX_TOP_N = 20
EXTENDED_MAX_GROUPS = 3

ALLOWED_COMMANDS = frozenset({"fields", "filter", "parse", "stats", "sort", "limit", "estimate"})
BLOCKED_COMMANDS = frozenset({
    "source", "join", "lookup", "subqueries", "subquery", "appendcols", "cidrlookup", "unmask",
    "pattern", "diff", "logcompare", "anomaly", "filterindex", "unnest", "expand", "relevantfields",
    "countfrequent", "outlier", "fillmissing", "filldown", "accum", "autoregress", "addtotals",
    "sessionize", "dedup", "display", "where", "select", "from", "source_logs",
})

# --- anchored stage shapes (full match) -------------------------------------------------------
_RX = rf"[{REGEX_CHARS}]{{1,300}}"
_LIT = rf"[{LITERAL_CHARS}]{{1,64}}"
_TERM = rf'@message like (?:/{_RX}/|"{_LIT}")'
_GROUP = rf"\({_TERM}(?: or {_TERM})*\)"
_BOOL = rf"{_GROUP}(?: and not {_GROUP})?"
_SHAPES = {
    "fields": re.compile(r"fields @timestamp, @log, @message"),
    "filter": re.compile(rf"filter {_BOOL}"),
    "parse": re.compile(r"parse @message /\\b\(\?<status>\d{3}(?:\|\d{3})*\)\\b/"),
    "stats": re.compile(r"stats count\(\*\) as matches by (?:bin\((?:1m|5m|15m|30m|1h)\)|@log|@logStream|status)"),
    "sort": re.compile(r"sort (?:matches|@timestamp) desc"),
    "limit": re.compile(r"limit (\d{1,4})"),
}


def split_stages(query: str) -> list:
    """Split on top-level '|' while honouring "quoted" strings and /regex/ literals.
    Unbalanced quotes/regex -> rejection. (Our charsets exclude '/' and '"' inside literals, so
    the delimiters are unambiguous.)"""
    stages, buf = [], []
    in_str = in_rx = False
    for ch in query:
        if ch == '"' and not in_rx:
            in_str = not in_str
        elif ch == "/" and not in_str:
            in_rx = not in_rx
        if ch == "|" and not in_str and not in_rx:
            stages.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if in_str or in_rx:
        raise QueryRejected("unbalanced quote or regex delimiter in the rendered query")
    stages.append("".join(buf).strip())
    return stages


def validate_query_text(query: str, cfg: Config, *, estimate: bool = False) -> list:
    """Stage B. Returns the core stages (without the trailing `estimate`) or raises QueryRejected."""
    if not isinstance(query, str) or not query.strip():
        raise QueryRejected("the rendered query is empty")
    if len(query) > cfg.insights_max_query_chars:
        raise QueryRejected(f"the rendered query exceeds {cfg.insights_max_query_chars} characters")
    if any(not (0x20 <= ord(c) <= 0x7E) for c in query):
        raise QueryRejected("the rendered query contains non-printable or non-ASCII characters (newlines/tabs included)")
    if "#" in query:
        raise QueryRejected("comments are not allowed in queries")

    stages = split_stages(query)
    if any(not s for s in stages):
        raise QueryRejected("the rendered query contains an empty pipeline stage")
    names = [s.split(None, 1)[0].lower() for s in stages]

    if "estimate" in names:
        if not estimate or names[-1] != "estimate" or names.count("estimate") != 1 or stages[-1] != "estimate":
            raise QueryRejected("'estimate' is only allowed as the final, system-appended stage")
        core = stages[:-1]
    else:
        if estimate:
            raise QueryRejected("the estimate variant must end with the estimate stage")
        core = stages
    if not core:
        raise QueryRejected("the query has no stages")
    if len(core) > cfg.insights_max_stages:
        raise QueryRejected(f"the query has more than {cfg.insights_max_stages} pipeline stages")

    for stage in core:
        cmd = stage.split(None, 1)[0].lower()
        if cmd in BLOCKED_COMMANDS or cmd not in ALLOWED_COMMANDS:
            reason = "blocked" if cmd in BLOCKED_COMMANDS else "not allow-listed"
            raise QueryRejected(f"command '{cmd[:20]}' is {reason}")
        shape = _SHAPES.get(cmd)
        m = shape.fullmatch(stage) if shape else None
        if not m:
            raise QueryRejected(f"a '{cmd}' stage does not match an approved shape")
        if cmd == "limit":
            n = int(m.group(1))
            if not 1 <= n <= cfg.insights_max_rows:
                raise QueryRejected(f"limit must be between 1 and {cfg.insights_max_rows}")

    last_cmd = core[-1].split(None, 1)[0].lower()
    if last_cmd not in ("stats", "limit"):
        raise QueryRejected("the query must end in a bounded stage (stats or limit)")
    return core


def check_group_name(name: str, cfg: Config) -> str:
    if not isinstance(name, str) or not _GROUP_RE.match(name) or ".." in name:
        raise QueryRejected("a log group name has an invalid format")
    allow = cfg.log_group_allowlist
    if allow and not any(fnmatch.fnmatchcase(name, pat) for pat in allow):
        raise QueryRejected("a log group is outside LOG_GROUP_ALLOWLIST")
    return name


@dataclass(frozen=True)
class ValidatedPlan:
    plan: QueryPlan
    query: str
    estimate_query: str
    group_names: tuple
    start_s: int
    end_s: int
    api_limit: int
    fingerprint: str
    estimate_fingerprint: str
    cache_key: str
    extended_range: bool
    bucket_count: Optional[int] = None


def validate_plan(plan: QueryPlan, cfg: Config) -> ValidatedPlan:
    """Stage A + Stage B. Pure: does not register approvals."""
    if plan.kind not in KINDS:
        raise QueryRejected("unknown query kind")
    groups = tuple(check_group_name(g, cfg) for g in plan.log_groups)
    if not groups:
        raise QueryRejected("at least one log group is required")
    if len(set(groups)) != len(groups):
        raise QueryRejected("duplicate log groups")
    if len(groups) > cfg.insights_max_log_groups:
        raise QueryRejected(f"at most {cfg.insights_max_log_groups} log groups per query")

    # time range
    if plan.end_s <= plan.start_s:
        raise QueryRejected("the time range is empty or inverted")
    seconds = plan.seconds
    if seconds > INSIGHTS_HARD_RANGE_HOURS * 3600:
        raise QueryRejected(f"the range exceeds the hard ceiling of {INSIGHTS_HARD_RANGE_HOURS} hours")
    extended = seconds > cfg.insights_max_range_hours * 3600
    if extended and len(groups) > EXTENDED_MAX_GROUPS:
        raise QueryRejected(f"ranges over {cfg.insights_max_range_hours}h allow at most "
                            f"{EXTENDED_MAX_GROUPS} log groups")

    # match vocabulary
    m = plan.match
    if m.is_empty():
        raise QueryRejected("at least one match criterion (preset, contains or status_codes) is required")
    if any(p not in PRESETS for p in m.presets):
        raise QueryRejected("unknown preset")
    if len(set(m.presets)) != len(m.presets):
        raise QueryRejected("duplicate presets")
    if len(m.contains) > MAX_CONTAINS or len(m.exclude) > MAX_EXCLUDE:
        raise QueryRejected(f"at most {MAX_CONTAINS} 'contains' and {MAX_EXCLUDE} 'exclude' terms")
    for lit in (*m.contains, *m.exclude):
        if not isinstance(lit, str) or not LITERAL_RE.fullmatch(lit):
            raise QueryRejected("a literal term is empty, longer than 64 characters or uses characters "
                                "outside [A-Za-z0-9 _.:=@-]")
    if len(m.status_codes) > MAX_STATUS_CODES or len(set(m.status_codes)) != len(m.status_codes):
        raise QueryRejected(f"at most {MAX_STATUS_CODES} distinct status codes")
    if any(isinstance(c, bool) or not isinstance(c, int) or not 100 <= c <= 599 for c in m.status_codes):
        raise QueryRejected("status codes must be integers from 100 to 599")

    # kind-specific
    buckets: Optional[int] = None
    if plan.kind == KIND_COUNT_OVER_TIME:
        if plan.dimension is not None:
            raise QueryRejected("count_over_time takes no dimension")
        if plan.bin_seconds not in ALLOWED_BINS:
            raise QueryRejected("bin must be one of 1m, 5m, 15m, 30m, 1h")
        # Logs Insights treats endTime as inclusive, so a window ending exactly on a bin boundary can return one
        # more bin than the half-open count. The row cap and the API limit must both allow it (never truncate it).
        buckets = expected_bin_count(plan.start_s, plan.end_s, plan.bin_seconds)
        if buckets > cfg.insights_max_rows:
            raise QueryRejected(f"this range and bin would return {buckets} buckets, above the row cap of "
                                f"{cfg.insights_max_rows}; use a larger bin or a shorter range")
        api_limit = buckets
    elif plan.kind == KIND_COUNT_BY:
        if plan.dimension not in DIMENSIONS:
            raise QueryRejected("dimension must be log_group, log_stream or status_code")
        if plan.dimension == DIM_STATUS_CODE and not m.status_codes:
            raise QueryRejected("dimension status_code requires status_codes")
        if not 1 <= plan.limit <= min(MAX_TOP_N, cfg.insights_max_rows):
            raise QueryRejected(f"top_n must be between 1 and {min(MAX_TOP_N, cfg.insights_max_rows)}")
        api_limit = plan.limit
    else:  # sample_events
        if plan.dimension is not None:
            raise QueryRejected("sample_events takes no dimension")
        if not 1 <= plan.limit <= min(MAX_SAMPLE_LIMIT, cfg.insights_max_rows):
            raise QueryRejected(f"limit must be between 1 and {min(MAX_SAMPLE_LIMIT, cfg.insights_max_rows)}")
        api_limit = plan.limit

    query = templates.render(plan)
    estimate_query = templates.render(plan, estimate=True)
    validate_query_text(query, cfg)                       # Stage B on both variants
    validate_query_text(estimate_query, cfg, estimate=True)
    return ValidatedPlan(
        plan=plan, query=query, estimate_query=estimate_query, group_names=groups,
        start_s=plan.start_s, end_s=plan.end_s, api_limit=api_limit,
        fingerprint=request_fingerprint(query, groups, plan.start_s, plan.end_s, api_limit),
        estimate_fingerprint=request_fingerprint(estimate_query, groups, plan.start_s, plan.end_s, None),
        cache_key=plan_cache_key(plan), extended_range=extended, bucket_count=buckets)


class Validator:
    """Validates plans and is the ONLY component allowed to approve requests for StartQuery."""

    def __init__(self, cfg: Config, approved: ApprovedQueryRegistry):
        self._cfg = cfg
        self._approved = approved

    def validate(self, plan: QueryPlan) -> ValidatedPlan:
        return validate_plan(plan, self._cfg)

    def approve(self, vp: ValidatedPlan, *, estimate: bool) -> str:
        """Re-validate the exact text about to be sent, then register its fingerprint (single use)."""
        query = vp.estimate_query if estimate else vp.query
        validate_query_text(query, self._cfg, estimate=estimate)
        # An estimate is approved WITHOUT an API limit (None); a real query with its bounded limit.
        fp = request_fingerprint(query, vp.group_names, vp.start_s, vp.end_s, None if estimate else vp.api_limit)
        expected = vp.estimate_fingerprint if estimate else vp.fingerprint
        if fp != expected:
            raise QueryRejected("the validated request changed after validation")
        self._approved.approve(fp)
        return fp

    @property
    def language(self) -> str:
        return QUERY_LANGUAGE
