"""Time-range parsing with a hard maximum span (cost/throttling control)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from aws_cw_mcp.utils.errors import InputError

_LOOKBACK = re.compile(
    r"^(?:last[\s_-]*)?(\d+)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days)$", re.I)


@dataclass(frozen=True)
class TimeRange:
    start: datetime
    end: datetime

    @property
    def seconds(self) -> int:
        return int((self.end - self.start).total_seconds())

    @property
    def start_ms(self) -> int:
        return int(self.start.timestamp() * 1000)

    @property
    def end_ms(self) -> int:
        return int(self.end.timestamp() * 1000)

    def as_dict(self) -> dict:
        return {"start": self.start.isoformat(), "end": self.end.isoformat(), "seconds": self.seconds}


def parse_lookback(text: str) -> timedelta:
    m = _LOOKBACK.match(text.strip())
    if not m:
        raise InputError(f"Unrecognised lookback {text!r}; use forms like '15m', '1h', '6h', '24h', '7d'.")
    n, unit = int(m.group(1)), m.group(2).lower()
    if n <= 0:
        raise InputError("lookback must be positive")
    if unit.startswith("m"):
        return timedelta(minutes=n)
    if unit.startswith("h"):
        return timedelta(hours=n)
    return timedelta(days=n)


def parse_timestamp(text: str) -> datetime:
    s = text.strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        raise InputError(f"Invalid timestamp {text!r}; use ISO-8601, e.g. 2026-09-20T10:00:00Z") from None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def resolve_range(*, lookback: Optional[str], start: Optional[str], end: Optional[str],
                  default_minutes: int, max_hours: int,
                  now: Optional[datetime] = None) -> TimeRange:
    now = now or datetime.now(timezone.utc)
    if start:
        s = parse_timestamp(start)
        e = parse_timestamp(end) if end else now
    else:
        if end:
            raise InputError("'end' requires 'start' (or use 'lookback' alone).")
        e = now
        s = e - (parse_lookback(lookback) if lookback else timedelta(minutes=default_minutes))
    if e > now:
        e = now
    if s >= e:
        raise InputError("Time range is empty or start is not before end.")
    if e - s > timedelta(hours=max_hours):
        raise InputError(
            f"Requested range {e - s} exceeds the configured maximum of {max_hours}h. "
            "Narrow the range (this limit protects CloudWatch cost and throttling).")
    return TimeRange(s, e)
