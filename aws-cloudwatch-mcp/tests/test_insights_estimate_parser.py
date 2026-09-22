"""Estimate parser: the documented `@estimatedBytesScanned` field (observed in real-AWS validation V2 as
{"@estimatedBytesScanned": "0"}) is accepted; `@ptr` and every other @-field stay ignored; everything malformed,
missing or ambiguous still fails closed."""
import pytest

from aws_cw_mcp.insights.cost import ESTIMATE_FIELD, parse_estimate_bytes
from aws_cw_mcp.runtime import Runtime
from aws_cw_mcp.server import build_tools
from aws_cw_mcp.utils.errors import CostGuardError
from conftest import GROUP, FakeClients, Harness, cells, parse, plan_for


def refuses(rows):
    with pytest.raises(CostGuardError, match="fail closed"):
        parse_estimate_bytes(rows)


def test_the_field_name_constant_is_exact():
    assert ESTIMATE_FIELD == "@estimatedBytesScanned"


# ------------------------------------------------------------------ 1 & 2: accepted
def test_zero_bytes_from_the_real_aws_shape_is_parsed_as_zero():
    assert parse_estimate_bytes([{"@estimatedBytesScanned": "0"}]) == 0            # exactly what AWS returned in V2


@pytest.mark.parametrize("value,expected", [
    ("1", 1), ("123456789", 123456789), ("2147483648", 2147483648), ("1.5E6", 1_500_000), (" 42 ", 42),
    (1048576, 1048576), (2048.0, 2048), ("0.0", 0),
])
def test_positive_values_are_parsed_correctly(value, expected):
    assert parse_estimate_bytes([{"@estimatedBytesScanned": value}]) == expected


# ------------------------------------------------------------------ 3: @ptr (and other @-fields) ignored
def test_ptr_is_ignored_next_to_the_estimate_field():
    assert parse_estimate_bytes([{"@ptr": "CmoKJQoh999999", "@estimatedBytesScanned": "77"}]) == 77
    assert parse_estimate_bytes([{"@ptr": "987654321", "@estimatedBytesScanned": "5"}]) == 5    # numeric-looking @ptr too


@pytest.mark.parametrize("rows", [
    [{"@ptr": "123"}],                                    # a numeric-looking @ptr is NOT an estimate
    [{"@ptr": "123", "note": "abc"}],
    [{"@other": "5"}], [{"@timestamp": "1789925520"}], [{"@message": "7"}], [{"@bytes": "9"}],   # no other @-field accepted
    [{"@estimatedbytesscanned": "5"}], [{"@EstimatedBytesScanned": "5"}], [{"estimatedBytesScanned": "5x"}],   # exact name only
])
def test_only_the_documented_at_field_is_accepted(rows):
    refuses(rows)


def test_plain_fields_behave_exactly_as_before():
    assert parse_estimate_bytes([{"estimatedBytes": "1234"}]) == 1234
    assert parse_estimate_bytes([{"@ptr": "abc", "value": "42"}]) == 42
    assert parse_estimate_bytes([{"scanBytes": "100", "recordsMatched": "9"}]) == 100


# ------------------------------------------------------------------ 4: missing -> fail closed
@pytest.mark.parametrize("rows", [[], [{}], [{"x": "no number"}], [{"@ptr": "p"}], [None], ["x"], [[]]])
def test_missing_estimate_still_fails_closed(rows):
    refuses(rows)


# ------------------------------------------------------------------ 5: malformed / non-numeric -> fail closed
@pytest.mark.parametrize("value", ["abc", "", " ", "12abc", "0x10", "-1", "-0.5", "nan", "NaN", "inf", "-inf", "1e999",
                                   None, True, False, [], {}, "1,000"])
def test_malformed_or_non_numeric_estimate_still_fails_closed(value):
    refuses([{"@estimatedBytesScanned": value}])


@pytest.mark.parametrize("extra", [{"bytes": "5"}, {"estimatedBytes": "5"}, {"count": "7"}, {"scanBytes": "9"}])
def test_a_malformed_documented_field_never_falls_back_to_another_field(extra):
    refuses([{"@estimatedBytesScanned": "abc", **extra}])


# ------------------------------------------------------------------ 6: ambiguous -> fail closed
def test_repeated_estimate_fields_are_ambiguous():
    refuses([{"@estimatedBytesScanned": "1"}, {"@estimatedBytesScanned": "2"}])
    refuses([{"@estimatedBytesScanned": "1"}, {"@estimatedBytesScanned": "1"}])          # even identical values
    refuses([{"@estimatedBytesScanned": "1"}, {"@estimatedBytesScanned": "abc"}])        # one valid, one malformed
    refuses([{"@estimatedBytesScanned": "1"}, {}, {"@estimatedBytesScanned": None}])


def test_existing_ambiguity_rules_are_unchanged_without_the_documented_field():
    refuses([{"a": "1", "b": "2"}])
    refuses([{"bytes": "1", "estimatedBytes": "2"}])
    refuses([{"bytes": "1"}, {"bytes": "2"}])


def test_the_documented_field_is_authoritative_over_other_numeric_fields():
    """AWS's own field wins; unrelated numeric fields in the same row cannot make it ambiguous or change it."""
    assert parse_estimate_bytes([{"@estimatedBytesScanned": "10", "bytes": "99", "count": "3"}]) == 10


# ------------------------------------------------------------------ end to end through the real executor / tool
def _estimate_with_field(h, value):
    h.start_ok("est-1")
    h.read_stub.add_response("get_query_results", {"status": "Complete", "results": [cells(**{"@estimatedBytesScanned": value})],
                                                   "statistics": {"bytesScanned": 0.0, "recordsMatched": 0.0,
                                                                  "recordsScanned": 0.0}})


def test_the_executor_accepts_the_real_aws_zero_estimate_and_allows_the_query():
    h = Harness()
    _estimate_with_field(h, 0)
    est = h.executor.estimate(plan_for(h.cfg))
    assert est.estimated_bytes == 0 and est.verdict.allowed
    h.done()


def test_the_estimate_tool_reports_zero_bytes_instead_of_failing_closed():
    h = Harness()
    _estimate_with_field(h, 0)
    tools = build_tools(Runtime(h.cfg, FakeClients(), insights_clients=h.clients, insights_executor=h.executor))
    d = parse(tools["aws_insights_estimate_scan"](log_groups=[GROUP], preset="errors", lookback="15m"))
    assert d["status"] == "ok" and d["FACT"]["estimated_bytes"] == 0 and d["FACT"]["verdict"]["allowed"] is True
    assert d["FACT"]["query_preview"].endswith("by bin(1m)")
    h.done()


def test_a_full_run_proceeds_with_the_real_aws_estimate_shape_and_still_enforces_the_cap():
    h = Harness()
    _estimate_with_field(h, 12345)
    h.start_ok("q-1")
    h.results("Complete", bytes_scanned=20000)
    h.results("Complete", [{"bin(1m)": "2026-09-20 11:10:00.000", "matches": 3}], bytes_scanned=20000)
    out = h.executor.run(plan_for(h.cfg))
    assert out.state == "complete" and out.estimated_bytes == 12345 and out.actual_bytes == 20000
    h.done()
    over = Harness()
    _estimate_with_field(over, over.cfg.insights_max_estimated_bytes + 1)
    with pytest.raises(CostGuardError, match="per-query cap"):
        over.executor.run(plan_for(over.cfg))                                 # cost-guard behaviour is unchanged
    over.done()


def test_an_unusable_estimate_from_aws_still_blocks_the_real_query():
    h = Harness()
    _estimate_with_field(h, "not-a-number")
    with pytest.raises(CostGuardError, match="fail closed"):
        h.executor.run(plan_for(h.cfg))
    assert len(h.start_stub._queue) == 0 and h.executor.slots.in_use == 0    # no real StartQuery was queued or sent
    h.done()
