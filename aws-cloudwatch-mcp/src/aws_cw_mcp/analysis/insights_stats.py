"""Deterministic statistics over normalized Insights rows. Pure functions: no AWS, no I/O.

2A deliberately does arithmetic only: totals, shares, first/last non-empty bin, peak and median of the
same series. No baselines, no spike verdicts, no causes.
"""
from __future__ import annotations

from datetime import datetime, timezone
from statistics import median
from typing import Optional

# Single shared inclusive [startTime, endTime] bin calculation (also used by the validator for api_limit).
from aws_cw_mcp.insights.presets import expected_bin_count  # noqa: F401  (re-exported: st.expected_bin_count)


def parse_bin_timestamp(value) -> Optional[datetime]:
    """Insights returns bin timestamps like '2026-09-20 14:05:00.000' (UTC). None if unparseable."""
    if not isinstance(value, str):
        return None
    text = value.strip().replace(" ", "T", 1)
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _to_int(value) -> Optional[int]:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def series_from_rows(rows: list, bin_seconds: int) -> tuple:
    """Return (points, unparsed). points = sorted [(epoch_bin_start, count)] with count > 0 as returned."""
    points, unparsed = {}, 0
    for row in rows:
        key = next((k for k in row if str(k).startswith("bin(")), None)
        ts = parse_bin_timestamp(row.get(key)) if key else None
        n = _to_int(row.get("matches"))
        if ts is None or n is None:
            unparsed += 1
            continue
        epoch = int(ts.timestamp()) // bin_seconds * bin_seconds
        points[epoch] = points.get(epoch, 0) + n
    return sorted(points.items()), unparsed


def series_stats(points: list, start_s: int, end_s: int, bin_seconds: int) -> dict:
    """Calculated facts about a bin series. Missing bins are counted as zero for the median and reported."""
    expected = expected_bin_count(start_s, end_s, bin_seconds)
    first_bin = start_s // bin_seconds * bin_seconds
    counts = dict(points)
    full = [counts.get(first_bin + i * bin_seconds, 0) for i in range(expected)]
    total = sum(full)
    nonzero = [(t, c) for t, c in points if c > 0]
    out = {"total": total, "expected_bins": expected, "returned_bins": len(points),
           "empty_bins": expected - len(nonzero), "median_bin": median(full) if full else 0}
    if nonzero:
        peak_t, peak_c = max(nonzero, key=lambda p: (p[1], -p[0]))
        out.update(peak_bin_start=peak_t, peak_count=peak_c,
                   first_nonempty_bin=nonzero[0][0], last_nonempty_bin=nonzero[-1][0])
    return out


def shares(rows: list, label_field: str, count_field: str = "matches") -> list:
    """Per-label counts with percentage share of the total across the returned rows."""
    items = []
    for row in rows:
        n = _to_int(row.get(count_field))
        if n is None:
            continue
        items.append((str(row.get(label_field, "")), n))
    total = sum(n for _, n in items)
    return [{"label": label, "count": n, "share_pct": round(100.0 * n / total, 1) if total else 0.0}
            for label, n in items], total


def iso_epoch(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
