"""Normalization, deterministic statistics and the FACT/ANALYSIS/RECOMMENDATION envelope."""
import json
from datetime import datetime, timezone

import pytest

from aws_cw_mcp.analysis import insights_stats as st
from aws_cw_mcp.insights.plans import KIND_COUNT_BY, KIND_COUNT_OVER_TIME, KIND_SAMPLE_EVENTS
from aws_cw_mcp.insights.results import (EMPTY_SUMMARY, InsightsOutcome, RUNNING, normalize_rows,
                                         outcome_to_result)
from aws_cw_mcp.insights.validator import validate_plan
from conftest import GROUP, NOW, make_insights_config, plan_for

CFG = make_insights_config()


def outcome(plan, rows, **kw):
    vp = validate_plan(plan, CFG)
    base = dict(state="complete", validated=vp, rows=rows, statistics={"bytesScanned": 5000.0},
                estimated_bytes=4000, actual_bytes=5000, retention={GROUP: 30}, budget_remaining=100)
    base.update(kw)
    return InsightsOutcome(**base)


def epoch(h, m=0):
    return int(datetime(2026, 9, 20, h, m, tzinfo=timezone.utc).timestamp())


# ------------------------------------------------------------------ normalize_rows
def test_rows_are_sanitized_truncated_and_capped():
    rows = [{"@message": "login failed password=hunter2 " + "x" * 5000, "matches": 3}] * 5
    out, truncated = normalize_rows(rows, make_insights_config(insights_max_rows=3))
    assert len(out) == 3 and truncated
    assert "hunter2" not in json.dumps(out) and len(out[0]["@message"]) < CFG.max_message_chars + 60
    assert out[0]["matches"] == 3                                     # non-strings untouched


def test_response_size_budget_is_enforced():
    rows = [{"@message": "y" * 500}] * 50
    out, truncated = normalize_rows(rows, make_insights_config(max_response_chars=2000))
    assert truncated and 0 < len(out) < 50


def test_limit_argument_lowers_but_never_raises_the_cap():
    rows = [{"a": i} for i in range(300)]
    assert len(normalize_rows(rows, CFG, limit=5)[0]) == 5
    assert len(normalize_rows(rows, CFG, limit=10_000)[0]) == CFG.insights_max_rows


# ------------------------------------------------------------------ statistics
@pytest.mark.parametrize("text,ok", [("2026-09-20 14:05:00.000", True), ("2026-09-20T14:05:00Z", True),
                                     ("2026-09-20 14:05:00", True), ("garbage", False), (None, False), (5, False)])
def test_bin_timestamp_parsing(text, ok):
    assert (st.parse_bin_timestamp(text) is not None) == ok


def test_series_from_rows_aligns_merges_and_counts_unparsed():
    rows = [{"bin(5m)": "2026-09-20 11:05:00.000", "matches": "4"}, {"bin(5m)": "2026-09-20 11:07:00.000", "matches": 1},
            {"bin(5m)": "bad", "matches": 1}, {"matches": 2}, {"bin(5m)": "2026-09-20 11:20:00.000", "matches": "x"}]
    points, unparsed = st.series_from_rows(rows, 300)
    assert points == [(epoch(11, 5), 5)] and unparsed == 3


def test_series_stats_treats_missing_bins_as_zero_and_finds_peak_first_last():
    points = [(epoch(11, 10), 3), (epoch(11, 30), 12), (epoch(11, 40), 12)]
    # window 11:00-12:00 with 5-minute bins ENDS EXACTLY ON A BIN BOUNDARY: endTime is inclusive, so the 12:00 bin exists
    s = st.series_stats(points, epoch(11, 0), epoch(12, 0), 300)
    assert s["total"] == 27 and s["expected_bins"] == 13 and s["returned_bins"] == 3 and s["empty_bins"] == 10
    assert s["peak_count"] == 12 and s["peak_bin_start"] == epoch(11, 30)       # ties resolve to the earliest
    assert s["first_nonempty_bin"] == epoch(11, 10) and s["last_nonempty_bin"] == epoch(11, 40)
    assert s["median_bin"] == 0                                                   # 10 of 13 bins are empty


def test_series_stats_empty_series():
    s = st.series_stats([], epoch(11), epoch(12), 300)                            # inclusive end: 13 bins, all empty
    assert s["total"] == 0 and s["expected_bins"] == 13 and s["empty_bins"] == 13 and "peak_count" not in s


def test_shares_percentages_and_skipping_bad_counts():
    ranked, total = st.shares([{"@log": "a", "matches": "30"}, {"@log": "b", "matches": 10}, {"@log": "c", "matches": "x"}],
                              "@log")
    assert total == 40 and ranked[0] == {"label": "a", "count": 30, "share_pct": 75.0}
    assert st.shares([], "@log") == ([], 0)


# ------------------------------------------------------------------ outcome_to_result
def test_count_over_time_facts_analysis_and_evidence():
    p = plan_for(CFG, lookback="1h")
    rows = [{"bin(1m)": "2026-09-20 11:10:00.000", "matches": 3}, {"bin(1m)": "2026-09-20 11:20:00.000", "matches": 12}]
    d = outcome_to_result("aws_insights_count_over_time", outcome(p, rows), CFG).to_dict()
    assert d["status"] == "ok" and d["read_only"] is True
    f = d["FACT"]
    assert f["aws"]["status"] == "Complete" and f["aws"]["statistics"]["bytesScanned"] == 5000.0
    assert f["scope"]["log_groups"] == [GROUP] and f["scope"]["retention_days_by_group"] == {GROUP: 30}
    assert f["series"] == [["2026-09-20T11:10:00Z", 3], ["2026-09-20T11:20:00Z", 12]]
    assert f["series_stats"]["total"] == 15 and f["cost"]["estimated_bytes"] == 4000
    assert all(a["method"] == "calculated" and a["evidence"] for a in d["ANALYSIS"])
    assert any("Peak 12" in a["statement"] for a in d["ANALYSIS"])
    assert d["RECOMMENDATION"] == []                                              # never invented in 2A
    assert any("ingestion delay" in w for w in d["warnings"]) and any("approximate" in w for w in d["warnings"])
    assert f["untrusted_log_content"] is False


def test_count_by_ranks_with_shares():
    p = plan_for(CFG, kind=KIND_COUNT_BY, dimension="log_group")
    d = outcome_to_result("t", outcome(p, [{"@log": "111:/a", "matches": 9}, {"@log": "111:/b", "matches": 1}]), CFG).to_dict()
    assert d["FACT"]["ranked"][0]["label"] == "111:/a" and d["FACT"]["ranked"][0]["share_pct"] == 90.0
    assert "largest is '111:/a'" in d["ANALYSIS"][0]["statement"]


def test_status_code_dimension_uses_status_field():
    p = plan_for(CFG, kind=KIND_COUNT_BY, dimension="status_code", preset=None, status_codes=[503, 404])
    d = outcome_to_result("t", outcome(p, [{"status": "503", "matches": 8}, {"status": "404", "matches": 2}]), CFG).to_dict()
    assert [r["label"] for r in d["FACT"]["ranked"]] == ["503", "404"]


def test_sample_events_are_marked_untrusted_and_sanitized_and_ptr_free():
    p = plan_for(CFG, kind=KIND_SAMPLE_EVENTS, limit=5)
    rows = [{"@timestamp": "2026-09-20 11:00:00.000", "@log": "1:/x",
             "@message": "Authorization: Bearer abcdef1234567890 failed"}]
    text = outcome_to_result("t", outcome(p, rows), CFG).to_json()
    d = json.loads(text)
    assert d["FACT"]["untrusted_log_content"] is True and "abcdef1234567890" not in text
    assert any("untrusted" in w.lower() for w in d["warnings"]) and any("sample" in w for w in d["warnings"])


def test_empty_result_uses_the_exact_sentence_and_makes_no_health_claim():
    d = outcome_to_result("t", outcome(plan_for(CFG), []), CFG).to_dict()
    assert d["status"] == "empty" and d["summary"] == EMPTY_SUMMARY
    assert "does not establish that the system is healthy" in json.dumps(d["ANALYSIS"])
    zero = outcome_to_result("t", outcome(plan_for(CFG), [{"bin(1m)": "2026-09-20 11:10:00.000", "matches": 0}]), CFG).to_dict()
    assert zero["status"] == "empty"                                              # all-zero series is also 'no data'


def test_running_and_cancelled_never_present_numbers_as_facts():
    p = plan_for(CFG)
    running = outcome_to_result("t", outcome(p, [{"bin(1m)": "x", "matches": 99}], state=RUNNING, handle="qh_abc"), CFG).to_dict()
    assert running["status"] == "partial" and running["FACT"]["query_handle"] == "qh_abc"
    assert "series" not in running["FACT"] and "99" not in json.dumps(running["FACT"])
    cancelled = outcome_to_result("t", outcome(p, [], state="cancelled", reason="deadline"), CFG).to_dict()
    assert cancelled["status"] == "empty" and "cancelled" in cancelled["summary"] and cancelled["FACT"]["aws"]["status"] == "Cancelled"


def test_cached_outcome_is_labelled_and_price_shown_only_when_available():
    d = outcome_to_result("t", outcome(plan_for(CFG), [{"bin(1m)": "2026-09-20 11:10:00.000", "matches": 1}],
                                       cached=True, cache_age_s=12.0, price_usd=0.0001), CFG).to_dict()
    assert any("local result cache" in w for w in d["warnings"])
    assert d["FACT"]["cost"]["est_cost_usd"] == 0.0001
    assert d["meta"]["cached"] is True


def test_truncated_result_is_partial_and_flagged():
    p = plan_for(CFG, kind=KIND_COUNT_BY, dimension="log_group", limit=20)
    rows = [{"@log": f"{i}:/g", "matches": 1} for i in range(20)]
    small = make_insights_config(insights_max_rows=5)
    vp = validate_plan(plan_for(small, kind=KIND_COUNT_BY, dimension="log_group", limit=5), small)
    o = InsightsOutcome(state="complete", validated=vp, rows=rows, estimated_bytes=1, actual_bytes=1)
    d = outcome_to_result("t", o, small).to_dict()
    assert d["status"] == "partial" and d["FACT"]["truncated"] is True and d["FACT"]["row_count"] == 5


def test_log_stream_dimension_is_flagged_untrusted():
    p = plan_for(CFG, kind=KIND_COUNT_BY, dimension="log_stream")
    d = outcome_to_result("t", outcome(p, [{"@logStream": "pod-1", "matches": 2}]), CFG).to_dict()
    assert d["FACT"]["untrusted_log_content"] is True


def test_unparseable_bins_are_reported_not_invented():
    d = outcome_to_result("t", outcome(plan_for(CFG), [{"bin(1m)": "???", "matches": 5}]), CFG).to_dict()
    assert d["status"] == "empty" and any("unrecognised" in w for w in d["warnings"])


def test_time_range_and_bin_echoed_as_facts():
    d = outcome_to_result("t", outcome(plan_for(CFG), [{"bin(1m)": "2026-09-20 11:10:00.000", "matches": 1}]), CFG).to_dict()
    tr = d["FACT"]["scope"]["time_range"]
    assert tr == {"start": "2026-09-20T11:00:00Z", "end": "2026-09-20T12:00:00Z", "seconds": 3600}
    assert d["FACT"]["scope"]["bin_seconds"] == 60 and NOW.hour == 12
