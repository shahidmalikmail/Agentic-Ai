"""Full lifecycle through the REAL gate/API/executor over Stubber-backed clients and a fake clock."""
import pytest
from botocore.exceptions import ClientError, ReadTimeoutError

from aws_cw_mcp.insights.plans import KIND_COUNT_BY, KIND_COUNT_OVER_TIME, KIND_SAMPLE_EVENTS
from aws_cw_mcp.insights.results import outcome_to_result
from aws_cw_mcp.utils.errors import (ConcurrencyLimit, CostGuardError, NotFoundError, QueryFailed,
                                     QueryRejected, ReadOnlyViolation)
from conftest import GROUP, Harness, cells, make_insights_config, plan_for

BIN_ROWS = [{"bin(1m)": "2026-09-20 11:10:00.000", "matches": 3},
            {"bin(1m)": "2026-09-20 11:20:00.000", "matches": 12}]


def test_full_run_estimate_start_poll_finish(harness):
    h = harness
    h.run_flow(BIN_ROWS, actual=2_000_000, running_polls=2)
    out = h.executor.run(plan_for(h.cfg))
    assert out.state == "complete" and out.estimated_bytes == 1_000_000 and out.actual_bytes == 2_000_000
    assert [r["matches"] for r in out.rows] == ["3", "12"]
    assert h.executor.budget.used == 2_000_000 and h.executor.budget.reserved == 0
    assert h.executor.slots.in_use == 0 and h.owned.snapshot() == []
    h.done()


def test_start_parameters_are_exactly_the_approved_request(harness):
    """Estimate: NO API limit (it would be applied after `| estimate`). Real query: the bounded limit."""
    h = harness
    plan = plan_for(h.cfg)
    vp = h.validator.validate(plan)
    base = {"logGroupNames": [GROUP], "startTime": vp.start_s, "endTime": vp.end_s, "queryLanguage": "CWLI"}
    h.start_ok("est-1", expected={**base, "queryString": vp.estimate_query})          # note: no "limit" key
    h.results("Complete", [{"estimatedBytes": 5}])
    h.start_ok("q-1", expected={**base, "queryString": vp.query, "limit": vp.api_limit})
    h.results("Complete", bytes_scanned=1)
    h.results("Complete", BIN_ROWS, bytes_scanned=1)
    h.executor.run(plan)
    h.done()


def test_estimate_query_is_run_first_and_ends_with_estimate(harness):
    h = harness
    h.estimate_flow(123)
    est = h.executor.estimate(plan_for(h.cfg))
    assert est.estimated_bytes == 123 and est.verdict.allowed
    assert est.validated.estimate_query.endswith(" | estimate")
    h.done()


def test_estimate_cached_second_call_makes_no_aws_call(harness):
    h = harness
    h.estimate_flow(777)
    plan = plan_for(h.cfg)
    assert h.executor.estimate(plan).cached is False
    assert h.executor.estimate(plan).cached is True     # Stubber would raise on any extra call
    h.done()


def test_result_cache_hit_consumes_no_budget_or_calls(harness):
    h = harness
    h.run_flow(BIN_ROWS)
    plan = plan_for(h.cfg)
    first = h.executor.run(plan)
    used = h.executor.budget.used
    second = h.executor.run(plan)
    assert second.cached and second.rows == first.rows and h.executor.budget.used == used
    h.clock.advance(h.cfg.insights_cache_ttl + 1)
    h.run_flow(BIN_ROWS, query_id="q-2")
    h.executor.estimates._data.clear()
    assert h.executor.run(plan).cached is False
    h.done()


def test_fails_closed_when_estimate_cannot_be_interpreted(harness):
    h = harness
    h.start_ok("est-1")
    h.results("Complete", [{"foo": "bar"}])
    with pytest.raises(CostGuardError, match="fail closed"):
        h.executor.run(plan_for(h.cfg))
    assert len(h.start_stub._queue) == 0            # no second StartQuery was attempted
    h.done()


def test_fails_closed_when_estimate_query_errors(harness):
    h = harness
    h.start_error("MalformedQueryException", "bad query")
    with pytest.raises(CostGuardError, match="estimate could not be obtained"):
        h.executor.run(plan_for(h.cfg))
    h.done()


def test_estimate_terminal_failure_status_fails_closed(harness):
    h = harness
    h.start_ok("est-1")
    h.results("Failed")
    with pytest.raises(CostGuardError, match="ended with status Failed"):
        h.executor.run(plan_for(h.cfg))
    h.done()


def test_over_per_query_cap_refused_before_any_real_query(harness):
    h = harness
    h.estimate_flow(h.cfg.insights_max_estimated_bytes + 1)
    with pytest.raises(CostGuardError, match="per-query cap"):
        h.executor.run(plan_for(h.cfg))
    assert h.executor.budget.reserved == 0 and h.executor.slots.in_use == 0
    h.done()


def test_session_budget_exhaustion_refuses_and_reserve_released():
    h = Harness(make_insights_config(insights_session_budget_bytes=1_500_000))
    h.run_flow(BIN_ROWS, actual=1_400_000)
    h.executor.run(plan_for(h.cfg))
    h.estimate_flow(1_000_000, query_id="est-2")
    with pytest.raises(CostGuardError, match="session"):
        h.executor.run(plan_for(h.cfg, preset="timeouts"))
    assert h.executor.budget.reserved == 0
    h.done()


def test_unknown_log_group_is_not_found_and_no_aws_call(harness):
    with pytest.raises(NotFoundError):
        harness.executor.run(plan_for(harness.cfg, groups=("/aws/app/missing",)))
    harness.done()


def test_invalid_plan_rejected_before_aws(harness):
    plan = plan_for(harness.cfg)
    bad = plan.__class__(**{**plan.__dict__, "log_groups": ("/aws/x;drop",)})
    with pytest.raises(QueryRejected):
        harness.executor.run(bad)
    harness.done()


# ---- AWS errors ----------------------------------------------------------------------------
@pytest.mark.parametrize("api", ["start", "results"])
def test_access_denied_surfaces_as_client_error(harness, api):
    h = harness
    if api == "start":
        h.start_error("AccessDeniedException", "not authorized to perform: logs:StartQuery")
    else:
        h.start_ok("est-1")
        h.read_stub.add_client_error("get_query_results", "AccessDeniedException", "denied")
    with pytest.raises(ClientError) as exc:
        h.executor.run(plan_for(h.cfg))
    assert exc.value.response["Error"]["Code"] == "AccessDeniedException"
    assert h.executor.slots.in_use == 0 and h.executor.budget.reserved == 0
    h.done()


def test_malformed_query_on_real_start_is_reported_and_state_released(harness):
    h = harness
    h.estimate_flow(10)
    h.start_error("MalformedQueryException", "syntax")
    with pytest.raises(ClientError) as exc:
        h.executor.run(plan_for(h.cfg))
    assert exc.value.response["Error"]["Code"] == "MalformedQueryException"
    assert h.executor.slots.in_use == 0 and h.executor.budget.reserved == 0
    h.done()


def test_limit_exceeded_retried_once_then_succeeds(harness):
    h = harness
    h.start_error("LimitExceededException", "too many")
    h.start_ok("est-1")
    h.results("Complete", [{"estimatedBytes": 5}])
    h.start_ok("q-1")
    h.results("Complete", bytes_scanned=1)
    h.results("Complete", BIN_ROWS, bytes_scanned=1)
    out = h.executor.run(plan_for(h.cfg))
    assert out.state == "complete"
    h.done()


def test_limit_exceeded_twice_gives_concurrency_limit_and_breaker_counts(harness):
    h = harness
    h.start_error("LimitExceededException")
    h.start_error("LimitExceededException")
    with pytest.raises(ConcurrencyLimit):
        h.executor.run(plan_for(h.cfg))
    assert h.executor.breaker._failures == 2
    h.done()


def test_start_timeout_is_never_retried_and_reports_unknown_outcome(harness):
    h = harness
    h.estimate_flow(10)
    # A timeout during the REAL StartQuery (Stubber cannot raise transport errors, so wrap the api call)
    calls = {"n": 0}
    real = h.api.begin_query

    def flaky(**kw):
        calls["n"] += 1
        if kw["query"].endswith("estimate"):
            return real(**kw)
        raise ReadTimeoutError(endpoint_url="https://logs.us-east-1.amazonaws.com")

    h.api.begin_query = flaky
    with pytest.raises(QueryFailed, match="NOT retried"):
        h.executor.run(plan_for(h.cfg))
    assert calls["n"] == 2                       # one estimate + exactly ONE real attempt
    assert h.executor.slots.in_use == 0 and h.executor.budget.reserved == 0
    h.done()


@pytest.mark.parametrize("status", ["Failed", "Cancelled", "Timeout", "Unknown"])
def test_aws_terminal_failure_statuses_reported_verbatim(harness, status):
    h = harness
    h.estimate_flow(10)
    h.start_ok("q-1")
    h.results(status, bytes_scanned=500)
    with pytest.raises(QueryFailed, match=status):
        h.executor.run(plan_for(h.cfg))
    assert h.executor.budget.used == 500 and h.executor.slots.in_use == 0   # pessimistic settle
    h.done()


def test_throttling_during_poll_stops_query_and_releases(harness):
    h = harness
    h.estimate_flow(10)
    h.start_ok("q-1")
    h.read_stub.add_client_error("get_query_results", "ThrottlingException", "slow down")
    h.stop_ok()
    with pytest.raises(ClientError):
        h.executor.run(plan_for(h.cfg))
    assert h.executor.slots.in_use == 0
    h.done()


# ---- results / normalization through the executor ------------------------------------------------
def test_pagination_next_token_followed_up_to_cap():
    h = Harness(make_insights_config(insights_max_rows=3))
    h.estimate_flow(10)
    h.start_ok("q-1")
    h.results("Complete", bytes_scanned=1)
    h.results("Complete", [{"@log": "a", "matches": 5}, {"@log": "b", "matches": 4}], bytes_scanned=1,
              next_token="tok")
    h.results("Complete", [{"@log": "c", "matches": 3}, {"@log": "d", "matches": 2}], bytes_scanned=1)
    out = h.executor.run(plan_for(h.cfg, kind=KIND_COUNT_BY, dimension="log_group", limit=3))
    assert len(out.rows) == 3
    h.done()


def test_empty_result_message_and_no_health_claim(harness):
    h = harness
    h.run_flow([], actual=100)
    res = outcome_to_result("t", h.executor.run(plan_for(h.cfg)), h.cfg).to_dict()
    assert res["status"] == "empty"
    assert res["summary"] == "No matching log data was found for the selected time range and log groups."
    assert "does not establish that the system is healthy" in " ".join(map(str, res["ANALYSIS"]))
    h.done()


def test_ptr_field_is_dropped_and_secrets_in_rows_redacted():
    h = Harness()
    h.estimate_flow(10)
    h.start_ok("q-1")
    h.results("Complete", bytes_scanned=1)
    h.read_stub.add_response("get_query_results", {"status": "Complete", "statistics": {"bytesScanned": 1.0},
                                                   "results": [[{"field": "@timestamp", "value": "2026-09-20 11:00:00.000"},
                                                                {"field": "@message", "value": "login failed password=hunter2 for bob"},
                                                                {"field": "@ptr", "value": "SECRETPTRVALUE"}]]})
    out = h.executor.run(plan_for(h.cfg, kind=KIND_SAMPLE_EVENTS, limit=5))
    text = outcome_to_result("aws_insights_sample_events", out, h.cfg).to_json()
    assert "SECRETPTRVALUE" not in text and "@ptr" not in text and "hunter2" not in text
    assert '"untrusted_log_content": true' in text
    h.done()


def test_estimate_only_never_starts_a_real_query(harness):
    h = harness
    h.estimate_flow(50)
    harness.executor.estimate(plan_for(h.cfg, kind=KIND_SAMPLE_EVENTS, limit=5))
    assert len(h.start_stub._queue) == 0 and h.executor.status()["running_jobs"] == []
    h.done()


def test_gate_blocks_running_without_validator_approval(harness):
    """Even if executor code were bypassed, the boto gate refuses an unapproved StartQuery - even with a
    response queued and ready (Stubber would have answered it), so it is the gate that says no."""
    harness.start_ok("would-have-worked")
    with pytest.raises(ReadOnlyViolation, match="not approved"):
        harness.api.begin_query(query='filter (@message like "x") | limit 5', group_names=[GROUP],
                                start_s=1, end_s=2, limit=5)
    assert len(harness.start_stub._queue) == 1          # the queued response was never consumed
    assert harness.owned.snapshot() == []
