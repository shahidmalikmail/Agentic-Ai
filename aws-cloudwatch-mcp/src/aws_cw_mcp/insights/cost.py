"""Scan-size estimation, per-query cap and the per-process byte budget.

The estimate comes from running the same query with a trailing `| estimate` (AWS: approximate,
no Insights charges, must be the last command [V]). Its API result shape is NOT verified [U], so the
parser is tolerant but FAILS CLOSED: if the number cannot be identified unambiguously, no query runs.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional

from aws_cw_mcp.config import Config
from aws_cw_mcp.insights.validator import ValidatedPlan
from aws_cw_mcp.utils.errors import CostGuardError

_GIB = 1 << 30

# The field CloudWatch Logs Insights returns for a `| estimate` query (observed in real-AWS validation V2 as
# {"@estimatedBytesScanned": "0"}). It is the ONLY @-prefixed field the parser accepts.
ESTIMATE_FIELD = "@estimatedBytesScanned"


def fmt_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TiB"


def _to_number(value) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def parse_estimate_bytes(rows: list) -> int:
    """Extract the estimated byte count from the estimate query's result rows, or fail closed."""
    if not rows:
        raise CostGuardError("The scan estimate returned no rows; refusing to run the query (fail closed).")
    numeric: list = []
    byte_named: list = []
    explicit: list = []          # values of the documented estimate field, when AWS returns it
    explicit_seen = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key, val in row.items():
            if key == ESTIMATE_FIELD:
                explicit_seen += 1
                num = _to_number(val)
                if num is not None:
                    explicit.append(num)
                continue
            if str(key).startswith("@"):     # @ptr and every other @-field stay ignored
                continue
            num = _to_number(val)
            if num is None:
                continue
            numeric.append(num)
            if "byte" in str(key).lower():
                byte_named.append(num)
    if explicit_seen:
        # The documented field is authoritative: use it exclusively. Any malformed or repeated occurrence
        # leaves the pool with != 1 usable value, so we fail closed instead of falling back to other fields.
        pool = explicit if len(explicit) == explicit_seen else []
    else:
        pool = byte_named if byte_named else numeric
    if len(pool) != 1 or pool[0] < 0 or pool[0] != pool[0] or pool[0] == float("inf"):
        raise CostGuardError("The scan estimate could not be interpreted unambiguously; "
                             "refusing to run the query (fail closed).")
    return int(pool[0])


class ByteBudget:
    """Per-process budget. reserve() before a query, commit() with actual bytes after, release() on abort."""

    def __init__(self, total_bytes: int):
        self.total = int(total_bytes)
        self._used = 0
        self._reserved = 0
        self._lock = threading.Lock()

    def reserve(self, estimate: int) -> "Reservation":
        with self._lock:
            remaining = self.total - self._used - self._reserved
            if estimate > remaining:
                raise CostGuardError(
                    f"The session scan budget would be exceeded: estimated {fmt_bytes(estimate)}, remaining "
                    f"{fmt_bytes(max(remaining, 0))} of {fmt_bytes(self.total)}. Narrow the scope or restart the "
                    "server to reset the per-process budget.")
            self._reserved += estimate
            return Reservation(self, int(estimate))

    def _settle(self, reservation: "Reservation", actual: int) -> None:
        with self._lock:
            self._reserved -= reservation.amount
            self._used += max(0, int(actual))

    def _drop(self, reservation: "Reservation") -> None:
        with self._lock:
            self._reserved -= reservation.amount

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    @property
    def reserved(self) -> int:
        with self._lock:
            return self._reserved

    @property
    def remaining(self) -> int:
        with self._lock:
            return max(0, self.total - self._used - self._reserved)


class Reservation:
    def __init__(self, budget: ByteBudget, amount: int):
        self._budget, self.amount, self._done = budget, amount, False
        self._lock = threading.Lock()

    def commit(self, actual_bytes: int) -> None:
        with self._lock:
            if self._done:
                return
            self._done = True
        self._budget._settle(self, actual_bytes)

    def release(self) -> None:
        with self._lock:
            if self._done:
                return
            self._done = True
        self._budget._drop(self)


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reasons: tuple
    estimated_bytes: int
    per_query_cap: int
    budget_remaining: int

    def as_dict(self) -> dict:
        return {"allowed": self.allowed, "reasons": list(self.reasons), "estimated_bytes": self.estimated_bytes,
                "per_query_cap_bytes": self.per_query_cap, "session_budget_remaining_bytes": self.budget_remaining}


class CostGuard:
    def __init__(self, cfg: Config):
        self._cfg = cfg

    def evaluate(self, estimated: int, vp: ValidatedPlan, budget_remaining: int) -> Verdict:
        reasons = []
        cap = self._cfg.insights_max_estimated_bytes
        if estimated > cap:
            reasons.append(f"estimated scan {fmt_bytes(estimated)} exceeds the per-query cap {fmt_bytes(cap)}")
        if estimated > budget_remaining:
            reasons.append(f"estimated scan {fmt_bytes(estimated)} exceeds the remaining session budget "
                           f"{fmt_bytes(budget_remaining)}")
        return Verdict(not reasons, tuple(reasons), int(estimated), cap, int(budget_remaining))

    def enforce(self, estimated: int, vp: ValidatedPlan, budget_remaining: int) -> Verdict:
        v = self.evaluate(estimated, vp, budget_remaining)
        if not v.allowed:
            raise CostGuardError("; ".join(v.reasons) + ". Narrow the log groups, time range or match, "
                                 "or run aws_insights_estimate_scan to explore scope first.")
        return v

    def price_usd(self, nbytes: int) -> Optional[float]:
        p = self._cfg.insights_price_per_gb
        return None if p is None else round(nbytes / 1e9 * p, 6)
