"""Query templates. The ONLY place Logs Insights query text is produced.

Rendering is done from a structured QueryPlan; raw input is never concatenated: every literal is
re-checked against the literal charset here (defence in depth, the planner/validator check first).
The rendered text is a single line, stages joined by " | ".

NOTE: exact Logs Insights syntax is confirmed against AWS in the real validation step; golden tests
pin the rendered form once it is confirmed.
"""
from __future__ import annotations

from aws_cw_mcp.insights.plans import (DIM_LOG_GROUP, DIM_LOG_STREAM, DIM_STATUS_CODE, KIND_COUNT_BY,
                                       KIND_COUNT_OVER_TIME, KIND_SAMPLE_EVENTS, MatchSpec, QueryPlan)
from aws_cw_mcp.insights.presets import BIN_LABELS, LITERAL_RE, PRESETS
from aws_cw_mcp.utils.errors import QueryRejected

STAGE_SEP = " | "
_DIM_FIELD = {DIM_LOG_GROUP: "@log", DIM_LOG_STREAM: "@logStream", DIM_STATUS_CODE: "status"}


def _literal(value: str) -> str:
    if not isinstance(value, str) or not LITERAL_RE.fullmatch(value):
        raise QueryRejected("a literal term contains characters outside the allowed set")
    return f'@message like "{value}"'


def _status_regex(codes: tuple) -> str:
    return r"\b(" + "|".join(str(int(c)) for c in codes) + r")\b"


def render_match(spec: MatchSpec) -> str:
    parts = [f"@message like /{PRESETS[p]}/" for p in spec.presets]
    parts += [_literal(c) for c in spec.contains]
    if spec.status_codes:
        parts.append(f"@message like /{_status_regex(spec.status_codes)}/")
    if not parts:
        raise QueryRejected("at least one match criterion (preset, contains or status_codes) is required")
    expr = "(" + " or ".join(parts) + ")"
    if spec.exclude:
        expr += " and not (" + " or ".join(_literal(x) for x in spec.exclude) + ")"
    return expr


def render_stages(plan: QueryPlan) -> list:
    match = render_match(plan.match)
    if plan.kind == KIND_COUNT_OVER_TIME:
        return [f"filter {match}",
                f"stats count(*) as matches by bin({BIN_LABELS[plan.bin_seconds]})"]
    if plan.kind == KIND_COUNT_BY:
        if plan.dimension == DIM_STATUS_CODE:
            names = "|".join(str(int(c)) for c in plan.match.status_codes)
            return [f"filter {match}",
                    rf"parse @message /\b(?<status>{names})\b/",
                    "stats count(*) as matches by status",
                    "sort matches desc",
                    f"limit {plan.limit}"]
        field = _DIM_FIELD[plan.dimension]
        return [f"filter {match}",
                f"stats count(*) as matches by {field}",
                "sort matches desc",
                f"limit {plan.limit}"]
    if plan.kind == KIND_SAMPLE_EVENTS:
        return ["fields @timestamp, @log, @message",
                f"filter {match}",
                "sort @timestamp desc",
                f"limit {plan.limit}"]
    raise QueryRejected("unknown query kind")


def render(plan: QueryPlan, *, estimate: bool = False) -> str:
    stages = render_stages(plan)
    if estimate:
        stages = stages + ["estimate"]
    return STAGE_SEP.join(stages)
