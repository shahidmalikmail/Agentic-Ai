"""Regression tests for the V2 finding.

Real AWS rejected the estimate query with `MalformedQueryException: unexpected symbol found limit` because the
API `limit` parameter (sent alongside `... | estimate`) is applied AFTER the query, which stops `estimate` being
the final command. Invariant enforced here: an estimate request carries NO API limit, `| estimate` is always the
final command, and real queries still carry their bounded limit.
"""
import re

import pytest
from botocore.stub import Stubber

from aws_cw_mcp.insights.plans import (KIND_COUNT_BY, KIND_COUNT_OVER_TIME, KIND_SAMPLE_EVENTS, request_fingerprint)
from aws_cw_mcp.insights.registry import ApprovedQueryRegistry
from aws_cw_mcp.insights.validator import Validator, validate_plan
from aws_cw_mcp.aws.insights_client import InsightsApi
from aws_cw_mcp.utils.errors import ReadOnlyViolation
from conftest import GROUP, Harness, make_insights_config, plan_for

CFG = make_insights_config()

# Every plan shape the tools can produce
PLANS = [
    dict(kind=KIND_COUNT_OVER_TIME, preset="errors"),
    dict(kind=KIND_COUNT_OVER_TIME, preset="http_5xx", lookback="6h"),
    dict(kind=KIND_COUNT_OVER_TIME, preset=None, contains=["timeout"], exclude=["healthcheck"], lookback="24h"),
    dict(kind=KIND_COUNT_BY, preset="errors", dimension="log_group", limit=10),
    dict(kind=KIND_COUNT_BY, preset="errors", dimension="log_stream", limit=3),
    dict(kind=KIND_COUNT_BY, preset=None, dimension="status_code", status_codes=[403, 404, 503]),
    dict(kind=KIND_SAMPLE_EVENTS, preset="timeouts", limit=20),
    dict(kind=KIND_SAMPLE_EVENTS, preset=None, contains=["db2"], limit=1),
]


def aws_compiles(query, api_limit):
    """Model of the observed AWS behaviour: the API `limit` is applied as a trailing `| limit N` stage."""
    return query + (f" | limit {api_limit}" if api_limit is not None else "")


def final_stage(query):
    return query.rsplit("|", 1)[-1].strip()


# --------------------------------------------------------------------- the invariant, on every plan shape
@pytest.mark.parametrize("kw", PLANS)
def test_estimate_query_ends_with_estimate_and_nothing_can_follow_it(kw):
    vp = validate_plan(plan_for(CFG, **kw), CFG)
    assert vp.estimate_query.endswith(" | estimate") and final_stage(vp.estimate_query) == "estimate"
    assert len(re.findall(r"\bestimate\b", vp.estimate_query)) == 1
    assert not re.search(r"estimate\s*\|", vp.estimate_query)
    # the estimate variant is fingerprinted WITHOUT a limit; the real query WITH its bounded limit
    assert vp.estimate_fingerprint == request_fingerprint(vp.estimate_query, vp.group_names, vp.start_s, vp.end_s, None)
    assert vp.estimate_fingerprint != request_fingerprint(vp.estimate_query, vp.group_names, vp.start_s, vp.end_s, vp.api_limit)
    assert vp.fingerprint == request_fingerprint(vp.query, vp.group_names, vp.start_s, vp.end_s, vp.api_limit)


@pytest.mark.parametrize("kw", PLANS)
def test_through_the_real_executor_no_estimate_request_can_compile_to_a_limit_after_estimate(kw):
    """Run the real executor + gate + API for every plan shape and model AWS's limit handling on what was sent."""
    h = Harness()
    sent = []
    real = h.api.begin_query

    def spy(**k):
        sent.append({"query": k["query"], "limit": k.get("limit")})
        return real(**k)

    h.api.begin_query = spy
    h.run_flow([], actual=1)
    h.executor.run(plan_for(h.cfg, **kw))
    est, real_q = sent
    assert est["query"].endswith(" | estimate") and est["limit"] is None                  # NO API limit on an estimate
    assert final_stage(aws_compiles(est["query"], est["limit"])) == "estimate"            # estimate is still final
    assert real_q["limit"] is not None and 1 <= real_q["limit"] <= h.cfg.insights_max_rows    # real: bounded limit
    assert "estimate" not in real_q["query"]
    h.done()


def test_the_old_behaviour_would_have_failed_the_invariant():
    """Documents V2: sending the API limit with the estimate query makes `limit` the final stage."""
    vp = validate_plan(plan_for(CFG), CFG)
    assert final_stage(aws_compiles(vp.estimate_query, vp.api_limit)) != "estimate"        # what V2 did (rejected)
    assert final_stage(aws_compiles(vp.estimate_query, None)) == "estimate"                # what we do now


# --------------------------------------------------------------------- exact wire format (Stubber expected_params)
def test_estimate_wire_request_has_no_limit_key_and_real_request_has_it():
    h = Harness()
    plan = plan_for(h.cfg)
    vp = h.validator.validate(plan)
    est = {"queryString": vp.estimate_query, "logGroupNames": [GROUP], "startTime": vp.start_s,
           "endTime": vp.end_s, "queryLanguage": "CWLI"}
    h.start_ok("est-1", expected=est)                                    # Stubber fails the test if "limit" is present
    h.results("Complete", [{"estimatedBytes": 7}])
    h.start_ok("q-1", expected={**est, "queryString": vp.query, "limit": vp.api_limit})
    h.results("Complete", bytes_scanned=1)
    h.results("Complete", [], bytes_scanned=1)
    h.executor.run(plan)
    h.done()


def test_estimate_only_flow_sends_no_limit():
    h = Harness()
    vp = h.validator.validate(plan_for(h.cfg))
    h.start_ok("est-1", expected={"queryString": vp.estimate_query, "logGroupNames": [GROUP], "startTime": vp.start_s,
                                  "endTime": vp.end_s, "queryLanguage": "CWLI"})
    h.results("Complete", [{"estimatedBytes": 99}])
    assert h.executor.estimate(plan_for(h.cfg)).estimated_bytes == 99
    h.done()


def test_api_wrapper_omits_the_limit_key_when_none_and_includes_it_otherwise():
    h = Harness()
    h.approved.approve(request_fingerprint("filter (@message like \"x\") | limit 5 | estimate", [GROUP], 1, 2, None))
    h.start_ok("e", expected={"queryString": 'filter (@message like "x") | limit 5 | estimate', "logGroupNames": [GROUP],
                              "startTime": 1, "endTime": 2, "queryLanguage": "CWLI"})
    InsightsApi(h.clients).begin_query(query='filter (@message like "x") | limit 5 | estimate', group_names=[GROUP],
                                       start_s=1, end_s=2, limit=None)
    h.approved.approve(request_fingerprint('filter (@message like "x") | limit 5', [GROUP], 1, 2, 5))
    h.start_ok("r", expected={"queryString": 'filter (@message like "x") | limit 5', "logGroupNames": [GROUP],
                              "startTime": 1, "endTime": 2, "queryLanguage": "CWLI", "limit": 5})
    InsightsApi(h.clients).begin_query(query='filter (@message like "x") | limit 5', group_names=[GROUP],
                                       start_s=1, end_s=2, limit=5)
    h.done()


# --------------------------------------------------------------------- the boto gate enforces it independently
EST_Q = 'filter (@message like "x") | limit 5 | estimate'
REAL_Q = 'filter (@message like "x") | limit 5'


def _gated():
    h = Harness()
    return h, h.start_client


def test_gate_blocks_an_estimate_request_that_carries_an_api_limit_even_if_approved():
    h, client = _gated()
    h.approved.approve(request_fingerprint(EST_Q, [GROUP], 1, 2, 15))       # someone approved the WRONG shape
    h.start_ok("would-have-worked")
    with pytest.raises(ReadOnlyViolation, match="must not carry an API limit"):
        client.start_query(queryString=EST_Q, logGroupNames=[GROUP], startTime=1, endTime=2, limit=15,
                           queryLanguage="CWLI")
    assert len(h.start_stub._queue) == 1                                     # nothing was sent


def test_gate_blocks_a_real_query_without_a_limit():
    h, client = _gated()
    h.approved.approve(request_fingerprint(REAL_Q, [GROUP], 1, 2, None))
    h.start_ok("would-have-worked")
    with pytest.raises(ReadOnlyViolation, match="explicit limit"):
        client.start_query(queryString=REAL_Q, logGroupNames=[GROUP], startTime=1, endTime=2, queryLanguage="CWLI")


@pytest.mark.parametrize("query", [
    'filter (@message like "x") | estimate | limit 5',                       # estimate not last
    'estimate | filter (@message like "x") | limit 5',
    'filter (@message like "x") | limit 5 | estimate | estimate',           # twice
    'filter (@message like "x") | estimate | stats count(*) as matches by @log',
])
def test_gate_blocks_estimate_anywhere_but_as_the_single_final_command(query):
    h, client = _gated()
    for lim in (None, 5):
        h.approved.approve(request_fingerprint(query, [GROUP], 1, 2, lim))
    h.start_ok("would-have-worked")
    kw = dict(queryString=query, logGroupNames=[GROUP], startTime=1, endTime=2, queryLanguage="CWLI")
    for extra in ({}, {"limit": 5}):
        with pytest.raises(ReadOnlyViolation, match="single, final|must not carry|explicit limit"):
            client.start_query(**kw, **extra)


def test_gate_allows_the_two_correct_shapes_and_only_once_each():
    h, client = _gated()
    h.approved.approve(request_fingerprint(EST_Q, [GROUP], 1, 2, None))
    h.approved.approve(request_fingerprint(REAL_Q, [GROUP], 1, 2, 5))
    h.start_ok("est")
    h.start_ok("real")
    kw = dict(logGroupNames=[GROUP], startTime=1, endTime=2, queryLanguage="CWLI")
    assert client.start_query(queryString=EST_Q, **kw)["queryId"] == "est"
    assert client.start_query(queryString=REAL_Q, limit=5, **kw)["queryId"] == "real"
    h.start_ok("replay")
    with pytest.raises(ReadOnlyViolation, match="not approved"):
        client.start_query(queryString=EST_Q, **kw)


# --------------------------------------------------------------------- validator approval + normal result limits
def test_validator_approves_estimate_without_limit_and_real_query_with_limit():
    reg = ApprovedQueryRegistry()
    v = Validator(CFG, reg)
    vp = v.validate(plan_for(CFG))
    v.approve(vp, estimate=True)
    assert reg.is_approved(request_fingerprint(vp.estimate_query, vp.group_names, vp.start_s, vp.end_s, None))
    assert not reg.is_approved(request_fingerprint(vp.estimate_query, vp.group_names, vp.start_s, vp.end_s, vp.api_limit))
    v.approve(vp, estimate=False)
    assert reg.is_approved(vp.fingerprint)


@pytest.mark.parametrize("kw", PLANS)
def test_real_queries_still_enforce_the_result_limit(kw):
    vp = validate_plan(plan_for(CFG, **kw), CFG)
    assert 1 <= vp.api_limit <= CFG.insights_max_rows
    assert re.search(r"(limit \d+|stats count\(\*\) as matches by [^|]+)$", vp.query)      # bounded final stage
    small = make_insights_config(insights_max_rows=3)
    if kw["kind"] != KIND_COUNT_OVER_TIME:
        with pytest.raises(Exception):
            validate_plan(plan_for(small, **{**kw, "limit": 10}), small)                  # cannot exceed the row cap


def test_executor_still_caps_rows_at_the_configured_limit_for_real_queries():
    h = Harness(make_insights_config(insights_max_rows=3))
    h.estimate_flow(10)
    h.start_ok("q-1")
    h.results("Complete", bytes_scanned=1)
    h.results("Complete", [{"@log": f"{i}:/g", "matches": 1} for i in range(10)], bytes_scanned=1)
    out = h.executor.run(plan_for(h.cfg, kind=KIND_COUNT_BY, dimension="log_group", limit=3))
    assert len(out.rows) == 3
