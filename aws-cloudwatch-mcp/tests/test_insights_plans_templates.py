"""Planner, presets, templates (golden renders), escaping, fingerprints, time ranges."""
from datetime import datetime, timedelta, timezone

import pytest

from aws_cw_mcp.insights import templates
from aws_cw_mcp.insights.planner import build_plan
from aws_cw_mcp.insights.plans import (KIND_COUNT_BY, KIND_COUNT_OVER_TIME, KIND_SAMPLE_EVENTS, MatchSpec,
                                       QueryPlan, plan_cache_key, request_fingerprint)
from aws_cw_mcp.insights.presets import (ALLOWED_BINS, PRESETS, REGEX_BODY_RE, bucket_count, default_bin_seconds)
from aws_cw_mcp.insights.validator import validate_plan, validate_query_text
from aws_cw_mcp.utils.errors import InputError, QueryRejected
from conftest import GROUP, NOW, make_insights_config, plan_for

CFG = make_insights_config()
ERR = r"(@message like /(?i)(error|exception|fatal|severe)/)"


# ------------------------------------------------------------------ golden renders
def test_golden_count_over_time():
    q = templates.render(plan_for(CFG))
    assert q == f"filter {ERR} | stats count(*) as matches by bin(1m)"


def test_golden_estimate_suffix_is_last_stage():
    q = templates.render(plan_for(CFG), estimate=True)
    assert q == f"filter {ERR} | stats count(*) as matches by bin(1m) | estimate"


def test_golden_contains_exclude_and_status_codes():
    plan = plan_for(CFG, preset=None, contains=["connection refused", "db2"], exclude=["healthcheck"],
                    status_codes=[503, 504])
    assert templates.render(plan) == (
        r'filter (@message like "connection refused" or @message like "db2" or @message like /\b(503|504)\b/)'
        r' and not (@message like "healthcheck") | stats count(*) as matches by bin(1m)')


def test_golden_count_by_dimensions():
    p = plan_for(CFG, kind=KIND_COUNT_BY, dimension="log_group", limit=5)
    assert templates.render(p) == (f"filter {ERR} | stats count(*) as matches by @log | sort matches desc | limit 5")
    p = plan_for(CFG, kind=KIND_COUNT_BY, dimension="log_stream", limit=7)
    assert "by @logStream | sort matches desc | limit 7" in templates.render(p)
    p = plan_for(CFG, kind=KIND_COUNT_BY, dimension="status_code", preset=None, status_codes=[403, 404, 503])
    assert templates.render(p) == (
        r"filter (@message like /\b(403|404|503)\b/) | parse @message /\b(?<status>403|404|503)\b/"
        r" | stats count(*) as matches by status | sort matches desc | limit 10")


def test_golden_sample_events():
    p = plan_for(CFG, kind=KIND_SAMPLE_EVENTS, limit=15)
    assert templates.render(p) == (f"fields @timestamp, @log, @message | filter {ERR} | sort @timestamp desc | limit 15")


@pytest.mark.parametrize("preset", sorted(PRESETS))
def test_every_preset_renders_a_query_that_passes_stage_b(preset):
    for kind, kw in ((KIND_COUNT_OVER_TIME, {}), (KIND_COUNT_BY, {"dimension": "log_group"}),
                     (KIND_SAMPLE_EVENTS, {"limit": 5})):
        vp = validate_plan(plan_for(CFG, kind=kind, preset=preset, **kw), CFG)
        validate_query_text(vp.query, CFG)
        validate_query_text(vp.estimate_query, CFG, estimate=True)


@pytest.mark.parametrize("preset,rx", sorted(PRESETS.items()))
def test_preset_regexes_use_only_the_tiny_safe_charset(preset, rx):
    assert REGEX_BODY_RE.fullmatch(rx), preset
    assert "/" not in rx and '"' not in rx and "\n" not in rx


def test_render_rejects_unsafe_literal_even_if_validation_were_skipped():
    plan = QueryPlan(KIND_COUNT_OVER_TIME, (GROUP,), NOW - timedelta(hours=1), NOW,
                     MatchSpec(contains=('x" or 1=1 | join',)), bin_seconds=60)
    with pytest.raises(QueryRejected):
        templates.render(plan)


def test_render_requires_a_match_criterion():
    plan = QueryPlan(KIND_COUNT_OVER_TIME, (GROUP,), NOW - timedelta(hours=1), NOW, MatchSpec(), bin_seconds=60)
    with pytest.raises(QueryRejected, match="at least one match"):
        templates.render(plan)


# ------------------------------------------------------------------ planner
def test_relative_range_is_floored_to_the_minute_for_stable_fingerprints():
    now = datetime(2026, 9, 20, 12, 0, 37, 123456, tzinfo=timezone.utc)
    p = build_plan(CFG, kind=KIND_COUNT_OVER_TIME, log_groups=[GROUP], lookback="1h", preset="errors", now=now)
    assert p.end == datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc) and p.seconds == 3600
    later = now + timedelta(seconds=10)
    p2 = build_plan(CFG, kind=KIND_COUNT_OVER_TIME, log_groups=[GROUP], lookback="1h", preset="errors", now=later)
    assert plan_cache_key(p) == plan_cache_key(p2)


def test_explicit_start_end_are_respected_exactly():
    p = build_plan(CFG, kind=KIND_COUNT_OVER_TIME, log_groups=[GROUP], start="2026-09-20T10:00:00Z",
                   end="2026-09-20T11:30:00Z", preset="errors", now=NOW)
    assert (p.start_s, p.end_s) == (int(datetime(2026, 9, 20, 10, tzinfo=timezone.utc).timestamp()),
                                    int(datetime(2026, 9, 20, 11, 30, tzinfo=timezone.utc).timestamp()))


def test_default_lookback_is_one_hour():
    p = build_plan(CFG, kind=KIND_COUNT_OVER_TIME, log_groups=[GROUP], preset="errors", now=NOW)
    assert p.seconds == 3600


@pytest.mark.parametrize("lookback", ["15m", "1h", "6h", "24h", "7d"])
def test_supported_lookback_forms(lookback):
    p = build_plan(CFG, kind=KIND_SAMPLE_EVENTS, log_groups=[GROUP], lookback=lookback, preset="errors", now=NOW)
    assert p.seconds > 0


def test_bad_time_inputs_are_input_errors():
    with pytest.raises(InputError):
        build_plan(CFG, kind=KIND_SAMPLE_EVENTS, log_groups=[GROUP], lookback="soon", preset="errors", now=NOW)
    with pytest.raises(InputError):
        build_plan(CFG, kind=KIND_SAMPLE_EVENTS, log_groups=[GROUP], start="2026-09-20T12:00:00Z",
                   end="2026-09-20T11:00:00Z", preset="errors", now=NOW)
    with pytest.raises(InputError, match="exceeds"):
        build_plan(CFG, kind=KIND_SAMPLE_EVENTS, log_groups=[GROUP], lookback="8d", preset="errors", now=NOW)


def test_input_type_coercion_and_rejection():
    p = build_plan(CFG, kind=KIND_COUNT_OVER_TIME, log_groups=GROUP, preset="errors", status_codes="503", now=NOW)
    assert p.log_groups == (GROUP,) and p.match.status_codes == (503,)
    for bad in ({"status_codes": ["x"]}, {"status_codes": [True]}, {"status_codes": {"a": 1}},
                {"preset": 5}, {"contains": 5}):
        with pytest.raises(QueryRejected):
            build_plan(CFG, kind=KIND_COUNT_OVER_TIME, log_groups=[GROUP], now=NOW, **{"preset": "errors", **bad})
    with pytest.raises(QueryRejected):
        build_plan(CFG, kind="delete_everything", log_groups=[GROUP], preset="errors", now=NOW)
    with pytest.raises(QueryRejected):
        build_plan(CFG, kind=KIND_COUNT_OVER_TIME, log_groups={"a": 1}, preset="errors", now=NOW)


def test_default_limits_per_kind():
    assert plan_for(CFG, kind=KIND_COUNT_BY, dimension="log_group").limit == 10
    assert plan_for(CFG, kind=KIND_SAMPLE_EVENTS).limit == 10
    with pytest.raises(QueryRejected):
        plan_for(CFG, kind=KIND_COUNT_OVER_TIME, limit=5)


# ------------------------------------------------------------------ bins, buckets, time policy
@pytest.mark.parametrize("seconds,expected", [(900, 60), (3600, 60), (3601, 300), (6 * 3600, 300),
                                              (6 * 3600 + 1, 900), (24 * 3600, 900), (24 * 3600 + 1, 3600),
                                              (7 * 86400, 3600)])
def test_default_bin_table(seconds, expected):
    assert default_bin_seconds(seconds) == expected


def test_bucket_count_counts_aligned_bins():
    assert bucket_count(0, 3600, 60) == 60 and bucket_count(30, 3630, 60) == 61 and bucket_count(0, 1, 3600) == 1


def test_seven_day_window_with_fine_bin_is_refused_by_row_cap():
    p = plan_for(CFG, lookback="7d", groups=(GROUP,))
    assert p.bin_seconds == 3600                                    # auto bin keeps 168 buckets <= 200
    validate_plan(p, CFG)
    fine = QueryPlan(**{**p.__dict__, "bin_seconds": 60})
    with pytest.raises(QueryRejected, match="buckets"):
        validate_plan(fine, CFG)


def test_standard_range_extended_range_and_hard_ceiling():
    assert validate_plan(plan_for(CFG, lookback="24h"), CFG).extended_range is False
    assert validate_plan(plan_for(CFG, lookback="25h"), CFG).extended_range is True
    assert validate_plan(plan_for(CFG, lookback="7d"), CFG).extended_range is True
    with pytest.raises(InputError):
        plan_for(CFG, lookback="169h")


def test_extended_range_allows_at_most_three_groups():
    groups = ("/a", "/b", "/c", "/d")
    ok = plan_for(CFG, lookback="48h", groups=groups[:3])
    validate_plan(ok, CFG)
    with pytest.raises(QueryRejected, match="at most 3"):
        validate_plan(plan_for(CFG, lookback="48h", groups=groups), CFG)
    validate_plan(plan_for(CFG, lookback="6h", groups=groups), CFG)      # fine inside the standard range


def test_configured_smaller_standard_range_makes_more_requests_extended():
    small = make_insights_config(insights_max_range_hours=6)
    assert validate_plan(plan_for(small, lookback="12h"), small).extended_range is True


# ------------------------------------------------------------------ fingerprints
def test_fingerprint_is_stable_order_independent_and_input_sensitive():
    base = request_fingerprint("q", ["/a", "/b"], 1, 2, 10)
    assert base == request_fingerprint("q", ["/b", "/a"], 1, 2, 10)
    for changed in (request_fingerprint("q2", ["/a", "/b"], 1, 2, 10), request_fingerprint("q", ["/a"], 1, 2, 10),
                    request_fingerprint("q", ["/a", "/b"], 2, 2, 10), request_fingerprint("q", ["/a", "/b"], 1, 3, 10),
                    request_fingerprint("q", ["/a", "/b"], 1, 2, 11)):
        assert changed != base


def test_estimate_and_real_query_have_different_fingerprints():
    vp = validate_plan(plan_for(CFG), CFG)
    assert vp.fingerprint != vp.estimate_fingerprint and len(vp.fingerprint) == 64


def test_cache_key_ignores_estimate_variant_but_tracks_scope():
    a = plan_for(CFG)
    assert plan_cache_key(a) == plan_cache_key(plan_for(CFG))
    assert plan_cache_key(a) != plan_cache_key(plan_for(CFG, preset="timeouts"))
    assert plan_cache_key(a) != plan_cache_key(plan_for(CFG, groups=("/x",)))
    assert plan_cache_key(a) != plan_cache_key(plan_for(CFG, lookback="6h"))


def test_bins_table_is_closed():
    assert ALLOWED_BINS == (60, 300, 900, 1800, 3600)
