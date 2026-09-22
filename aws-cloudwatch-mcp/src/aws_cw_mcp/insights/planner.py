"""Turn structured tool arguments into a QueryPlan (normalisation only; validation is in validator.py).

The MCP server never parses natural language: Claude maps the user's words to these arguments.
Relative ranges are floored to the minute so identical requests within a minute share a fingerprint
(result cache and in-flight de-duplication rely on this).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from aws_cw_mcp.config import INSIGHTS_HARD_RANGE_HOURS, Config
from aws_cw_mcp.insights.plans import (KIND_COUNT_BY, KIND_COUNT_OVER_TIME, KIND_SAMPLE_EVENTS, KINDS,
                                       MatchSpec, QueryPlan)
from aws_cw_mcp.insights.presets import default_bin_seconds
from aws_cw_mcp.utils.errors import QueryRejected
from aws_cw_mcp.utils.timerange import resolve_range


def _as_tuple(value: Any, what: str) -> tuple:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(value)
    raise QueryRejected(f"{what} must be a string or a list")


def _codes(value: Any) -> tuple:
    if value is None:
        return ()
    if isinstance(value, (int, str)) and not isinstance(value, bool):
        value = [value]
    if not isinstance(value, (list, tuple)):
        raise QueryRejected("status_codes must be a list of integers")
    out = []
    for c in value:
        if isinstance(c, bool):
            raise QueryRejected("status_codes must be integers")
        try:
            out.append(int(c))
        except (TypeError, ValueError):
            raise QueryRejected("status_codes must be integers") from None
    return tuple(out)


def build_plan(cfg: Config, *, kind: str, log_groups: Any, lookback: Optional[str] = None,
               start: Optional[str] = None, end: Optional[str] = None, preset: Any = None,
               contains: Any = None, exclude: Any = None, status_codes: Any = None,
               dimension: Optional[str] = None, bin_seconds: Optional[int] = None,
               limit: Optional[int] = None, now: Optional[datetime] = None) -> QueryPlan:
    if kind not in KINDS:
        raise QueryRejected("unknown query kind")
    groups = _as_tuple(log_groups, "log_groups")

    # Resolve the range against the HARD ceiling; the validator applies the standard/extended rules.
    tr = resolve_range(lookback=lookback if not start else None, start=start, end=end,
                       default_minutes=60, max_hours=INSIGHTS_HARD_RANGE_HOURS, now=now)
    s, e = tr.start, tr.end
    if not start:  # relative range: align to whole minutes for stable fingerprints
        delta = e - s
        e = e.replace(second=0, microsecond=0)
        s = e - delta
    s = s.astimezone(timezone.utc).replace(microsecond=0)
    e = e.astimezone(timezone.utc).replace(microsecond=0)
    if e - s < timedelta(seconds=1):
        raise QueryRejected("the time range is too short")

    match = MatchSpec(presets=_as_tuple(preset, "preset"), contains=_as_tuple(contains, "contains"),
                      exclude=_as_tuple(exclude, "exclude"), status_codes=_codes(status_codes))
    seconds = int((e - s).total_seconds())

    if kind == KIND_COUNT_OVER_TIME:
        if limit is not None:
            raise QueryRejected("count_over_time takes no limit")
        return QueryPlan(kind=kind, log_groups=groups, start=s, end=e, match=match,
                         bin_seconds=bin_seconds or default_bin_seconds(seconds), limit=1)
    if kind == KIND_COUNT_BY:
        return QueryPlan(kind=kind, log_groups=groups, start=s, end=e, match=match,
                         dimension=dimension, limit=10 if limit is None else _int(limit, "top_n"))
    return QueryPlan(kind=KIND_SAMPLE_EVENTS, log_groups=groups, start=s, end=e, match=match,
                     limit=10 if limit is None else _int(limit, "limit"))


def _int(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise QueryRejected(f"{what} must be an integer")
    try:
        return int(value)
    except ValueError:
        raise QueryRejected(f"{what} must be an integer") from None
