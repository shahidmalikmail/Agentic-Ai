"""count_over_time API limit = INCLUSIVE expected bin count (Variant B).

CloudWatch Logs Insights treats endTime as inclusive, so a window ending exactly on a bin boundary can return one more
bin than the half-open count (e.g. 16 bins for a 15-minute window with 1-minute bins). The API `limit` and the row cap
must allow that bin instead of truncating it. Estimates still carry NO limit; real queries still carry an explicit one.
No AWS access: pure functions, Stubber-backed executor, and the result builder."""
import inspect
import re
from datetime import datetime, timedelta, timezone

import pytest

from aws_cw_mcp.analysis import insights_stats as st
from aws_cw_mcp.insights import presets, validator
from aws_cw_mcp.insights.planner import build_plan
from aws_cw_mcp.insights.plans import KIND_COUNT_BY, KIND_COUNT_OVER_TIME, KIND_SAMPLE_EVENTS, request_fingerprint
from aws_cw_mcp.insights.presets import bucket_count, expected_bin_count
from aws_cw_mcp.insights.results import InsightsOutcome, outcome_to_result
from aws_cw_mcp.insights.validator import validate_plan
from aws_cw_mcp.utils.errors import QueryRejected, ReadOnlyViolation
from conftest import GROUP, Harness, make_insights_config, plan_for

CFG = make_insights_config()
LATER = datetime(2026, 9, 21, 0, 0, tzinfo=timezone.utc)          # "now" for explicit historical windows
FMT = "%Y-%m-%d %H:%M:%S.000"


def plan(start, end, *, bin_seconds=60, cfg=CFG, contains=("availability",)):
    return build_plan(cfg, kind=KIND_COUNT_OVER_TIME, log_groups=[GROUP], start=start, end=end,
                      contains=list(contains), bin_seconds=bin_seconds, now=LATER)


def limit_for(start, end, **kw):
    return validate_plan(plan(start, end, **kw), kw.get("cfg", CFG)).api_limit


# ---------------------------------------------------------------- one shared inclusive helper
def test_a_single_shared_inclusive_helper_is_used_everywhere():
    assert st.expected_bin_count is presets.expected_bin_count is validator.expected_bin_count
    assert inspect.getsourcefile(st.expected_bin_count).endswith("presets.py")       # not duplicated in insights_stats
    assert not hasattr(validator, "bucket_count")                                     # validator no longer uses the half-open one


def test_bucket_count_itself_is_unchanged():
    assert bucket_count(0, 3600, 60) == 60 and bucket_count(30, 3630, 60) == 61 and bucket_count(0, 1, 3600) == 1
    assert bucket_count(0, 900, 60) == 15                                              # half-open: 15 for a boundary window
    assert "(end_s - 1) // bin_seconds" in inspect.getsource(bucket_count)
    assert "Number of aligned bins that overlap [start_s, end_s)." in inspect.getsource(bucket_count)


def test_helper_definition_is_inclusive_and_equals_the_half_open_count_except_on_a_boundary():
    for bin_s in (60, 300, 900, 3600):
        for start in (0, 1, 59, 60, 61, 3599, 3600, 1_789_923_300):
            for span in (1, 59, 60, 61, 899, 900, 901, 3599, 3600, 3601):
                end = start + span
                assert expected_bin_count(start, end, bin_s) == bucket_count(start, end, bin_s) + (1 if end % bin_s == 0 else 0)


# ---------------------------------------------------------------- 1. 15-minute / 1-minute boundary window -> 16
def test_a_fifteen_minute_one_minute_boundary_window_produces_api_limit_16():
    vp = validate_plan(plan("2026-09-20T16:55:00Z", "2026-09-20T17:10:00Z"), CFG)
    assert vp.api_limit == 16 and vp.bucket_count == 16
    assert bucket_count(vp.start_s, vp.end_s, 60) == 15                                # what it used to be
    assert vp.query.endswith("stats count(*) as matches by bin(1m)")                   # query text unchanged (no limit stage)


def test_default_relative_windows_with_one_minute_bins_always_get_the_boundary_bin():
    for minute in range(60):
        now = datetime(2026, 9, 20, 12, minute, 37, tzinfo=timezone.utc)
        p = build_plan(CFG, kind=KIND_COUNT_OVER_TIME, log_groups=[GROUP], lookback="15m", preset="errors", now=now)
        assert validate_plan(p, CFG).api_limit == 16                                   # relative ends are floored to the minute
        p1h = build_plan(CFG, kind=KIND_COUNT_OVER_TIME, log_groups=[GROUP], lookback="1h", preset="errors", now=now)
        assert validate_plan(p1h, CFG).api_limit == 61


# ---------------------------------------------------------------- 2. non-boundary window keeps the previous limit
@pytest.mark.parametrize("start,end", [
    ("2026-09-20T16:55:00Z", "2026-09-20T17:09:30Z"),      # ends mid-bin: 16:55 ... 17:09 = 15 bins
    ("2026-09-20T16:55:00Z", "2026-09-20T17:09:59Z"),
    ("2026-09-20T16:55:30Z", "2026-09-20T17:10:30Z"),      # both mid-bin: 16:55 ... 17:10 = 16 bins
])
def test_a_non_boundary_window_retains_the_previous_expected_limit(start, end):
    p = plan(start, end)
    assert validate_plan(p, CFG).api_limit == bucket_count(p.start_s, p.end_s, 60)


def test_the_specific_non_boundary_values():
    assert limit_for("2026-09-20T16:55:00Z", "2026-09-20T17:09:30Z") == 15
    assert limit_for("2026-09-20T16:55:30Z", "2026-09-20T17:10:30Z") == 16


# ---------------------------------------------------------------- 3. 5-minute bins
def test_five_minute_bins_handle_the_inclusive_boundary():
    assert limit_for("2026-09-20T16:55:00Z", "2026-09-20T17:10:00Z", bin_seconds=300) == 4    # 16:55, 17:00, 17:05, 17:10
    assert limit_for("2026-09-20T16:55:00Z", "2026-09-20T17:12:00Z", bin_seconds=300) == 4    # end mid-bin: unchanged
    assert limit_for("2026-09-20T16:55:00Z", "2026-09-20T17:09:00Z", bin_seconds=300) == 3    # 16:55, 17:00, 17:05
    for minute in range(60):                                                                    # 6h/5m default windows
        now = datetime(2026, 9, 20, 12, minute, 37, tzinfo=timezone.utc)
        p = build_plan(CFG, kind=KIND_COUNT_OVER_TIME, log_groups=[GROUP], lookback="6h", preset="errors", now=now)
        assert validate_plan(p, CFG).api_limit == bucket_count(p.start_s, p.end_s, 300) + (1 if p.end_s % 300 == 0 else 0)


# ---------------------------------------------------------------- 4. the 200-row safety cap is still enforced
def test_the_row_cap_of_200_is_still_enforced_with_inclusive_counting():
    start = datetime(2026, 9, 20, 0, 0, tzinfo=timezone.utc)

    def iso(minutes, seconds=0):
        return (start + timedelta(minutes=minutes, seconds=seconds)).isoformat()

    assert CFG.insights_max_rows == 200
    assert limit_for(iso(0), iso(199)) == 200                       # 200 inclusive bins: exactly at the cap -> allowed
    with pytest.raises(QueryRejected, match="above the row cap of 200"):
        validate_plan(plan(iso(0), iso(200)), CFG)                  # 201 inclusive bins -> rejected (was 200 half-open)
    assert limit_for(iso(0), iso(200, -30)) == 200                  # ends mid-bin: 200 bins -> allowed
    with pytest.raises(QueryRejected, match="above the row cap"):
        validate_plan(plan(iso(0), iso(400)), CFG)                  # far above


def test_the_cap_follows_configuration_and_the_api_limit_never_exceeds_it():
    small = make_insights_config(insights_max_rows=50)
    start = datetime(2026, 9, 20, 0, 0, tzinfo=timezone.utc)
    assert validate_plan(plan(start.isoformat(), (start + timedelta(minutes=49)).isoformat(), cfg=small), small).api_limit == 50
    with pytest.raises(QueryRejected):
        validate_plan(plan(start.isoformat(), (start + timedelta(minutes=50)).isoformat(), cfg=small), small)


def test_default_window_and_bin_combinations_stay_within_the_cap():
    for lb, secs in (("15m", 900), ("1h", 3600), ("6h", 21600), ("24h", 86400), ("7d", 604800)):
        for minute in range(60):
            now = datetime(2026, 9, 20, 12, minute, 37, tzinfo=timezone.utc)
            p = build_plan(CFG, kind=KIND_COUNT_OVER_TIME, log_groups=[GROUP], lookback=lb, preset="errors", now=now)
            vp = validate_plan(p, CFG)
            assert 1 <= vp.api_limit <= CFG.insights_max_rows            # 7d/1h is 169 at most


def test_other_kinds_are_unaffected():
    assert validate_plan(plan_for(CFG, kind=KIND_COUNT_BY, dimension="log_group", limit=7), CFG).api_limit == 7
    assert validate_plan(plan_for(CFG, kind=KIND_SAMPLE_EVENTS, limit=5), CFG).api_limit == 5


# ---------------------------------------------------------------- 5/6. estimate: NO limit; real query: explicit limit
def _window_plan(h):
    return plan_for(h.cfg, lookback="15m")                 # 15m/1m relative window ending on a minute -> api_limit 16


def test_estimate_requests_still_contain_no_limit_and_real_queries_carry_the_new_limit():
    h = Harness()
    p = _window_plan(h)
    vp = h.validator.validate(p)
    assert vp.api_limit == 16
    base = {"logGroupNames": [GROUP], "startTime": vp.start_s, "endTime": vp.end_s, "queryLanguage": "CWLI"}
    h.start_ok("est-1", expected={**base, "queryString": vp.estimate_query})                # no "limit" key at all
    h.results("Complete", [{"@estimatedBytesScanned": 1234}])
    h.start_ok("q-1", expected={**base, "queryString": vp.query, "limit": 16})
    h.results("Complete", bytes_scanned=1)
    h.results("Complete", [], bytes_scanned=1)
    h.executor.run(p)
    h.done()


def test_real_queries_still_require_an_explicit_limit_at_the_gate():
    h = Harness()
    vp = h.validator.validate(_window_plan(h))
    h.approved.approve(request_fingerprint(vp.query, vp.group_names, vp.start_s, vp.end_s, None))
    h.start_ok("would-have-worked")
    with pytest.raises(ReadOnlyViolation, match="explicit limit"):
        h.start_client.start_query(queryString=vp.query, logGroupNames=list(vp.group_names), startTime=vp.start_s,
                                   endTime=vp.end_s, queryLanguage="CWLI")


def test_estimate_with_a_limit_is_still_blocked_at_the_gate():
    h = Harness()
    vp = h.validator.validate(_window_plan(h))
    h.approved.approve(request_fingerprint(vp.estimate_query, vp.group_names, vp.start_s, vp.end_s, 16))
    h.start_ok("would-have-worked")
    with pytest.raises(ReadOnlyViolation, match="must not carry an API limit"):
        h.start_client.start_query(queryString=vp.estimate_query, logGroupNames=list(vp.group_names),
                                   startTime=vp.start_s, endTime=vp.end_s, limit=16, queryLanguage="CWLI")


def test_a_final_estimate_stage_is_never_followed_by_a_limit_for_the_new_limit_values():
    vp = validate_plan(_plan_16(), CFG)
    assert vp.estimate_query.endswith(" | estimate") and not re.search(r"estimate\s*\|", vp.estimate_query)


def _plan_16():
    return plan("2026-09-20T16:55:00Z", "2026-09-20T17:10:00Z")


# ---------------------------------------------------------------- 7. fingerprint uses the actual calculated limit everywhere
def test_the_fingerprint_uses_the_calculated_api_limit_consistently():
    vp = validate_plan(_plan_16(), CFG)
    assert vp.fingerprint == request_fingerprint(vp.query, vp.group_names, vp.start_s, vp.end_s, 16)
    assert vp.fingerprint != request_fingerprint(vp.query, vp.group_names, vp.start_s, vp.end_s, 15)
    assert vp.estimate_fingerprint == request_fingerprint(vp.estimate_query, vp.group_names, vp.start_s, vp.end_s, None)


def test_the_executor_sends_and_approves_exactly_the_validated_limit():
    """Wire limit == vp.api_limit == the limit in the approved fingerprint == the result builder's cap."""
    h = Harness()
    p = _window_plan(h)
    sent = []
    real = h.api.begin_query

    def spy(**k):
        sent.append(k.get("limit"))
        return real(**k)

    h.api.begin_query = spy
    h.run_flow([], actual=1)                    # would raise UnStubbedResponse/gate error if the approved fp did not match
    h.executor.run(p)
    assert sent == [None, 16]                   # estimate: no limit; real: 16
    h.done()


# ---------------------------------------------------------------- 8/9. the result builder accepts 16 and never truncates them
def _rows16(vp, per_bin=100):
    return [{"bin(1m)": datetime.fromtimestamp(vp.start_s + i * 60, timezone.utc).strftime(FMT), "matches": str(per_bin)}
            for i in range(16)]


def test_the_result_builder_accepts_api_limit_16_and_does_not_truncate_16_bins():
    vp = validate_plan(plan_for(CFG, lookback="15m"), CFG)
    assert vp.api_limit == 16
    o = InsightsOutcome(state="complete", validated=vp, rows=_rows16(vp), statistics={"recordsMatched": 1600.0},
                        estimated_bytes=1, actual_bytes=1)
    d = outcome_to_result("aws_insights_count_over_time", o, CFG).to_dict()
    f = d["FACT"]
    assert d["status"] == "ok" and f["truncated"] is False and f["row_count"] == 16      # NOT cut to 15, not 'partial'
    assert len(f["series"]) == 16 and f["series"][-1][0] == "2026-09-20T12:00:00Z"        # boundary bin kept
    assert f["series_stats"]["total"] == 1600 == f["aws"]["statistics"]["recordsMatched"]
    assert f["series_stats"]["expected_bins"] == 16 and f["series_stats"]["empty_bins"] == 0


def test_sixteen_bins_survive_the_whole_executor_path_untruncated():
    h = Harness()
    p = _window_plan(h)
    vp = h.validator.validate(p)
    h.run_flow(_rows16(vp), actual=5000)
    out = h.executor.run(p)
    assert len(out.rows) == 16
    d = outcome_to_result("aws_insights_count_over_time", out, h.cfg).to_dict()
    assert d["status"] == "ok" and d["FACT"]["row_count"] == 16 and d["FACT"]["truncated"] is False
    assert d["FACT"]["series_stats"]["total"] == 1600
    h.done()


def test_a_seventeenth_row_is_still_capped_as_a_safety_net():
    """The result builder still bounds rows to the validated limit: extra rows beyond api_limit are flagged, not shown."""
    vp = validate_plan(plan_for(CFG, lookback="15m"), CFG)
    rows = _rows16(vp) + [{"bin(1m)": "2026-09-20 12:01:00.000", "matches": "5"}]
    o = InsightsOutcome(state="complete", validated=vp, rows=rows, estimated_bytes=1, actual_bytes=1)
    f = outcome_to_result("t", o, CFG).to_dict()["FACT"]
    assert f["row_count"] == 16 and f["truncated"] is True


# ---------------------------------------------------------------- 10. series_stats boundary behaviour still correct
def test_series_stats_boundary_behaviour_is_unchanged():
    start, end = 1_789_923_300, 1_789_924_200                                   # 16:55:00Z-17:10:00Z from real validation
    pts = [(start, 500), (start + 300, 500), (start + 600, 500), (start + 900, 500)]
    s = st.series_stats(pts, start, end, 60)
    assert s["total"] == 2000 and s["expected_bins"] == 16 and s["returned_bins"] == 4 and s["last_nonempty_bin"] == end
    assert st.series_stats(pts, start, end, 300)["expected_bins"] == 4
