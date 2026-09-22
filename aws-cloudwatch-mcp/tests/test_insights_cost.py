"""Estimate parsing (fail closed), per-query cap, session byte budget, price formatting."""
import threading

import pytest

from aws_cw_mcp.insights.cost import ByteBudget, CostGuard, fmt_bytes, parse_estimate_bytes
from aws_cw_mcp.insights.validator import validate_plan
from aws_cw_mcp.utils.errors import CostGuardError
from conftest import make_insights_config, plan_for

GIB = 1 << 30
CFG = make_insights_config()
VP = validate_plan(plan_for(CFG), CFG)


# ------------------------------------------------------------------ estimate parsing
@pytest.mark.parametrize("rows,expected", [
    ([{"estimatedBytes": "1234"}], 1234),
    ([{"bytes": 1.5e6}], 1_500_000),
    ([{"estimated_bytes_scanned": "2048.0"}], 2048),
    ([{"@ptr": "abc", "value": "42"}], 42),                          # sole numeric field, @-fields ignored
    ([{"label": "estimate", "count": "7"}], 7),
    ([{"scanBytes": "100", "recordsMatched": "9"}], 100),            # byte-named field wins over other numerics
    ([{"x": "1E6"}], 1_000_000),
    ([{"bytes": " 55 "}], 55),
])
def test_estimate_parsing_accepts_unambiguous_shapes(rows, expected):
    assert parse_estimate_bytes(rows) == expected


@pytest.mark.parametrize("rows", [
    [], [{}], [{"note": "no numbers here"}], [{"a": "1", "b": "2"}],                # ambiguous
    [{"bytes": "1", "estimatedBytes": "2"}],                                          # two byte fields
    [{"bytes": "-5"}], [{"bytes": "nan"}], [{"bytes": "inf"}], [{"bytes": True}],
    [{"bytes": "1"}, {"bytes": "2"}],                                                 # multiple rows -> ambiguous
    ["not a dict"], [None],
])
def test_estimate_parsing_fails_closed(rows):
    with pytest.raises(CostGuardError, match="fail closed"):
        parse_estimate_bytes(rows)


def test_fmt_bytes():
    assert fmt_bytes(0) == "0 B" and fmt_bytes(1536) == "1.50 KiB" and fmt_bytes(2 * GIB) == "2.00 GiB"
    assert fmt_bytes(5 * 1024 ** 4) == "5.00 TiB"


# ------------------------------------------------------------------ byte budget
def test_reserve_commit_and_refund_of_the_difference():
    b = ByteBudget(1000)
    r = b.reserve(600)
    assert b.reserved == 600 and b.remaining == 400 and b.used == 0
    r.commit(250)
    assert (b.used, b.reserved, b.remaining) == (250, 0, 750)
    r.commit(999)                                            # idempotent: cannot double-charge
    assert b.used == 250


def test_release_returns_the_reservation_without_charging():
    b = ByteBudget(1000)
    r = b.reserve(400)
    r.release()
    r.release()
    assert (b.used, b.reserved, b.remaining) == (0, 0, 1000)
    r.commit(500)                                            # after release, commit is a no-op
    assert b.used == 0


def test_actual_can_exceed_estimate_and_is_still_counted():
    b = ByteBudget(1000)
    b.reserve(100).commit(900)
    assert b.used == 900 and b.remaining == 100


def test_reservation_over_remaining_budget_is_refused_with_numbers():
    b = ByteBudget(1000)
    b.reserve(700)
    with pytest.raises(CostGuardError, match="session scan budget") as exc:
        b.reserve(400)
    assert "remaining" in str(exc.value) and b.reserved == 700


def test_budget_is_thread_safe_and_never_overcommits():
    b = ByteBudget(1000)
    granted = []
    lock = threading.Lock()

    def worker():
        try:
            r = b.reserve(100)
        except CostGuardError:
            return
        with lock:
            granted.append(r)

    ts = [threading.Thread(target=worker) for _ in range(40)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(granted) == 10 and b.reserved == 1000 and b.remaining == 0


# ------------------------------------------------------------------ cost guard
def test_within_limits_is_allowed():
    v = CostGuard(CFG).evaluate(1 * GIB, VP, 20 * GIB)
    assert v.allowed and v.reasons == () and v.per_query_cap == 2 * GIB


def test_over_per_query_cap_and_over_budget_are_reported_together():
    g = CostGuard(CFG)
    v = g.evaluate(3 * GIB, VP, 1 * GIB)
    assert not v.allowed and len(v.reasons) == 2
    assert any("per-query cap" in r for r in v.reasons) and any("session budget" in r for r in v.reasons)
    d = v.as_dict()
    assert d["allowed"] is False and d["estimated_bytes"] == 3 * GIB


def test_enforce_raises_with_guidance_and_boundary_is_inclusive():
    g = CostGuard(CFG)
    g.enforce(2 * GIB, VP, 20 * GIB)                         # exactly the cap is allowed
    with pytest.raises(CostGuardError, match="Narrow"):
        g.enforce(2 * GIB + 1, VP, 20 * GIB)


def test_price_is_only_reported_when_configured():
    assert CostGuard(CFG).price_usd(10 ** 9) is None
    priced = make_insights_config(insights_price_per_gb=0.005)
    assert CostGuard(priced).price_usd(2 * 10 ** 9) == pytest.approx(0.01)
    assert CostGuard(priced).price_usd(0) == 0.0
