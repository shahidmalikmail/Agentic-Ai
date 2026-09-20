"""Small statistics helpers (calculated values, always labelled as such)."""
from __future__ import annotations

from typing import Sequence


def percentile(values: Sequence[float], pct: float) -> float:
    """Linear-interpolated percentile of a non-empty sequence."""
    if not values:
        raise ValueError("percentile of empty sequence")
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = (pct / 100.0) * (len(ordered) - 1)
    lo = int(rank)
    hi = min(lo + 1, len(ordered) - 1)
    return float(ordered[lo] + (ordered[hi] - ordered[lo]) * (rank - lo))


def summarize(values: Sequence[float]) -> dict:
    if not values:
        return {"count": 0}
    return {
        "count": len(values),
        "min": min(values),
        "max": max(values),
        "avg": sum(values) / len(values),
        "p50": percentile(values, 50),
        "p90": percentile(values, 90),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
    }
