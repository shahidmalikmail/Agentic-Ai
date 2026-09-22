"""series_stats must match Logs Insights semantics: endTime is INCLUSIVE.

Real-AWS evidence (validation, window 16:55:00Z-17:10:00Z, 1-minute bins): AWS returned bins 16:55, 17:00, 17:05 and
17:10 (500 each) and recordsMatched = 2000, but series_stats reported total=1500 and expected_bins=15 because it
treated the end boundary as half-open. No AWS calls here: pure functions plus the result builder."""
import random
from datetime import datetime, timezone

import pytest

from aws_cw_mcp.analysis import insights_stats as st
from aws_cw_mcp.insights.planner import build_plan
from aws_cw_mcp.insights.plans import KIND_COUNT_OVER_TIME
from aws_cw_mcp.insights.presets import bucket_count
from aws_cw_mcp.insights.results import InsightsOutcome, outcome_to_result
from aws_cw_mcp.insights.validator import validate_plan
from conftest import GROUP, make_insights_config


def at(h, m, s=0):
    return int(datetime(2026, 9, 20, h, m, s, tzinfo=timezone.utc).timestamp())


REAL_START, REAL_END = at(16, 55), at(17, 10)                     # the real validation window
REAL_POINTS = [(at(16, 55), 500), (at(17, 0), 500), (at(17, 5), 500), (at(17, 10), 500)]   # what AWS returned


# ---------------------------------------------------------------- 1. a bin exactly at endTime is included
def test_the_real_aws_result_including_the_end_boundary_bin_is_fully_counted():
    s = st.series_stats(REAL_POINTS, REAL_START, REAL_END, 60)
    assert s["last_nonempty_bin"] == REAL_END                     # the bin stamped exactly at endTime is recognised
    assert s["returned_bins"] == 4 and s["first_nonempty_bin"] == REAL_START
    assert s["peak_count"] == 500 and s["peak_bin_start"] == REAL_START      # ties resolve to the earliest bin


# ---------------------------------------------------------------- 2. totals include the boundary bin
def test_total_includes_the_end_boundary_bin():
    s = st.series_stats(REAL_POINTS, REAL_START, REAL_END, 60)
    assert s["total"] == 2000                                     # was 1500 before the fix; AWS recordsMatched = 2000
    assert s["total"] == sum(c for _, c in REAL_POINTS)


@pytest.mark.parametrize("bin_seconds", [60, 300, 900, 3600])
def test_total_always_equals_the_sum_of_returned_bins_inside_the_inclusive_window(bin_seconds):
    first = REAL_START // bin_seconds * bin_seconds
    last = REAL_END // bin_seconds * bin_seconds
    pts = [(t, 7) for t in range(first, last + 1, bin_seconds)]
    assert st.series_stats(pts, REAL_START, REAL_END, bin_seconds)["total"] == 7 * len(pts)


# ---------------------------------------------------------------- 3. expected bins include the end boundary
def test_expected_bins_include_the_end_boundary_where_it_lies_on_a_bin_boundary():
    assert st.expected_bin_count(REAL_START, REAL_END, 60) == 16          # 16:55 ... 17:10 inclusive (was 15)
    assert st.expected_bin_count(REAL_START, REAL_END, 300) == 4          # 16:55, 17:00, 17:05, 17:10 (was 3)
    assert st.series_stats(REAL_POINTS, REAL_START, REAL_END, 60)["expected_bins"] == 16
    assert st.series_stats(REAL_POINTS, REAL_START, REAL_END, 300)["expected_bins"] == 4
    assert st.series_stats(REAL_POINTS, REAL_START, REAL_END, 300)["empty_bins"] == 0


def test_empty_bins_agree_with_the_returned_series():
    s = st.series_stats(REAL_POINTS, REAL_START, REAL_END, 60)
    assert s["expected_bins"] - s["returned_bins"] == s["empty_bins"] == 12
    assert s["expected_bins"] >= s["returned_bins"]                       # the series can never exceed the expected bins


# ---------------------------------------------------------------- 4. normal windows (no end-boundary event) stay correct
def test_a_window_without_an_end_boundary_event_keeps_the_correct_total():
    inside_only = REAL_POINTS[:3]
    s = st.series_stats(inside_only, REAL_START, REAL_END, 60)
    assert s["total"] == 1500 and s["returned_bins"] == 3 and s["last_nonempty_bin"] == at(17, 5)
    assert s["expected_bins"] == 16 and s["empty_bins"] == 13             # the (empty) boundary bin is an expected bin


def test_a_window_ending_mid_bin_is_unchanged():
    """End at 17:09:30 (not on a 1-minute boundary): identical to the pre-fix half-open result (15 bins)."""
    end = at(17, 9, 30)
    s = st.series_stats(REAL_POINTS[:3], REAL_START, end, 60)
    assert s["expected_bins"] == 15 == bucket_count(REAL_START, end, 60)
    assert s["total"] == 1500 and s["empty_bins"] == 12


def test_relative_style_window_floored_to_the_minute_with_coarse_bins_is_unchanged():
    """A 15-minute window ending on a minute that is NOT a 5-minute boundary: no boundary bin exists."""
    start, end = at(11, 3), at(11, 18)                                    # bins start 11:00 ... last 11:15
    assert st.expected_bin_count(start, end, 300) == bucket_count(start, end, 300) == 4


# ---------------------------------------------------------------- 5. everything else unchanged
def test_old_and_new_bin_counts_differ_only_when_end_is_exactly_on_a_bin_boundary():
    rng = random.Random(42)
    for _ in range(2000):
        bin_s = rng.choice([60, 300, 900, 1800, 3600])
        start = rng.randrange(1_700_000_000, 1_800_000_000)
        end = start + rng.randrange(1, 7 * 86400)
        old, new = bucket_count(start, end, bin_s), st.expected_bin_count(start, end, bin_s)
        assert new == old + (1 if end % bin_s == 0 else 0), (start, end, bin_s)


def test_start_boundary_and_alignment_behaviour_is_unchanged():
    assert st.expected_bin_count(0, 3600, 60) == 61                      # inclusive end -> 61 (was 60)
    assert st.expected_bin_count(30, 3630, 60) == 61                     # mid-bin start/end: unchanged
    assert st.expected_bin_count(0, 1, 3600) == 1 and st.expected_bin_count(59, 60, 60) == 2


def test_median_peak_first_last_and_zero_fill_behave_as_before_on_a_mid_bin_window():
    end = at(12, 0) - 1                                                    # 11:59:59 -> not on a bin boundary
    pts = [(at(11, 10), 3), (at(11, 30), 12), (at(11, 40), 12)]
    s = st.series_stats(pts, at(11, 0), end, 300)
    assert (s["total"], s["expected_bins"], s["returned_bins"], s["empty_bins"]) == (27, 12, 3, 9)
    assert s["peak_count"] == 12 and s["peak_bin_start"] == at(11, 30)
    assert s["first_nonempty_bin"] == at(11, 10) and s["last_nonempty_bin"] == at(11, 40) and s["median_bin"] == 0
    empty = st.series_stats([], at(11, 0), end, 300)
    assert empty["total"] == 0 and empty["empty_bins"] == 12 and "peak_count" not in empty


def test_bucket_count_used_by_the_query_builder_is_untouched():
    assert bucket_count(0, 3600, 60) == 60 and bucket_count(30, 3630, 60) == 61 and bucket_count(0, 1, 3600) == 1


# ---------------------------------------------------------------- end to end through the result builder
def _real_outcome():
    cfg = make_insights_config()
    now = datetime(2026, 9, 20, 18, 0, tzinfo=timezone.utc)
    plan = build_plan(cfg, kind=KIND_COUNT_OVER_TIME, log_groups=[GROUP], start="2026-09-20T16:55:00Z",
                      end="2026-09-20T17:10:00Z", contains=["availability"], bin_seconds=60, now=now)
    vp = validate_plan(plan, cfg)
    rows = [{"bin(1m)": ts, "matches": "500"} for ts in ("2026-09-20 16:55:00.000", "2026-09-20 17:00:00.000",
                                                         "2026-09-20 17:05:00.000", "2026-09-20 17:10:00.000")]
    o = InsightsOutcome(state="complete", validated=vp, rows=rows, statistics={"recordsMatched": 2000.0},
                        estimated_bytes=1972211, actual_bytes=1972211)
    return cfg, vp, o


def test_the_result_builder_reports_the_real_aws_window_consistently():
    cfg, vp, o = _real_outcome()
    d = outcome_to_result("aws_insights_count_over_time", o, cfg).to_dict()
    f = d["FACT"]
    assert [c for _, c in f["series"]] == [500, 500, 500, 500] and f["series"][-1][0] == "2026-09-20T17:10:00Z"
    assert f["series_stats"]["total"] == 2000 == sum(c for _, c in f["series"]) == f["aws"]["statistics"]["recordsMatched"]
    assert f["series_stats"]["expected_bins"] == 16 and f["series_stats"]["returned_bins"] == 4
    text = " ".join(a["statement"] for a in d["ANALYSIS"] if isinstance(a, dict))
    assert "Total 2000 matching events in 16 bins of 60s; 12 bins had no matches." in text
    assert "last 2026-09-20T17:10:00Z" in text                                # the boundary bin is the last non-empty bin
    # 16:55-17:10 with 1-minute bins ends exactly on a bin boundary: 16 bins are possible, so the API limit is 16
    # (it was 15 before the inclusive-end fix, which could truncate the boundary bin).
    assert vp.api_limit == 16
