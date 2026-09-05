"""Unit tests for commerce_correlation.py - pure logic, no SSH/network.

Timeline rows are hand-built in exactly the shape
commerce_tools.assemble_timeline() produces (see its _TIMELINE_BASE_ROW),
so these tests exercise the algorithm in isolation, the same way
test_commerce_log_analyzer.py's ParseTimestampTests do for parse_timestamp().
"""
from __future__ import annotations

import unittest

import commerce_correlation as cc


def _row(**overrides) -> dict:
    base = {
        "timestamp": None,
        "timestamp_source": None,
        "timezone_known": None,
        "timestamp_precision": None,
        "partial_time": None,
        "component": None,
        "leaf_component": None,
        "release": None,
        "release_group": None,
        "pod": None,
        "container": None,
        "log_source": None,
        "namespace": None,
        "involved_object": None,
        "reason": None,
        "category": None,
        "severity": None,
        "source": None,
        "summary": None,
    }
    base.update(overrides)
    return base


def _abs_known(ts_iso: str, **overrides) -> dict:
    return _row(timestamp=ts_iso, timestamp_precision="absolute", timezone_known=True, **overrides)


def _abs_unknown(ts_iso: str, **overrides) -> dict:
    return _row(timestamp=ts_iso, timestamp_precision="absolute", timezone_known=False, **overrides)


def _time_only(t_iso: str, **overrides) -> dict:
    return _row(partial_time=t_iso, timestamp_precision="time_only", **overrides)


def _no_ts(**overrides) -> dict:
    return _row(**overrides)


class WindowClusteringTests(unittest.TestCase):
    def test_events_within_window_form_one_group(self):
        timeline = [
            _abs_known("2026-09-04T12:00:00+00:00", component="ts-app", category="timeout", summary="a"),
            _abs_known("2026-09-04T12:00:30+00:00", component="crs-app", category="timeout", summary="b"),
        ]
        groups, uncorrelated, window = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].evidence_count, 2)
        self.assertEqual(uncorrelated, [])

    def test_events_outside_window_form_separate_groups(self):
        timeline = [
            _abs_known("2026-09-04T12:00:00+00:00", component="ts-app", category="timeout", summary="a"),
            _abs_known("2026-09-04T12:05:00+00:00", component="crs-app", category="timeout", summary="b"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 2)

    def test_rolling_window_chains_a_burst_beyond_first_to_last_span(self):
        # Each consecutive pair is 50s apart (within window) but the first
        # and last are 150s apart (outside a naive first-vs-all window) -
        # the approved rolling/chained algorithm must still merge them.
        timeline = [
            _abs_known("2026-09-04T12:00:00+00:00", summary="m0"),
            _abs_known("2026-09-04T12:00:50+00:00", summary="m1"),
            _abs_known("2026-09-04T12:01:40+00:00", summary="m2"),
            _abs_known("2026-09-04T12:02:30+00:00", summary="m3"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].evidence_count, 4)


class ComponentPodReleaseTests(unittest.TestCase):
    def test_same_component_events_correlate(self):
        timeline = [
            _abs_known("2026-09-04T12:00:00+00:00", component="ts-app", pod="p1"),
            _abs_known("2026-09-04T12:00:10+00:00", component="ts-app", pod="p1"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].components, ["ts-app"])

    def test_different_components_correlate_when_close_in_time(self):
        timeline = [
            _abs_known("2026-09-04T12:00:00+00:00", component="ts-app"),
            _abs_known("2026-09-04T12:00:05+00:00", component="crs-app"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].components, ["crs-app", "ts-app"])

    def test_different_pods_correlate_when_close_in_time(self):
        timeline = [
            _abs_known("2026-09-04T12:00:00+00:00", pod="pod-a"),
            _abs_known("2026-09-04T12:00:05+00:00", pod="pod-b"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(groups[0].pods, ["pod-a", "pod-b"])

    def test_different_releases_still_correlate_on_time_alone(self):
        timeline = [
            _abs_known("2026-09-04T12:00:00+00:00", release="ob-dev-live"),
            _abs_known("2026-09-04T12:00:05+00:00", release="ob-dev-share"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].releases, ["ob-dev-live", "ob-dev-share"])


class TimezoneTierTests(unittest.TestCase):
    def test_known_timezone_timestamps_grouped(self):
        timeline = [
            _abs_known("2026-09-04T12:00:00+05:30", summary="a"),
            _abs_known("2026-09-04T12:00:10+05:30", summary="b"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].temporal_comparability, "absolute_tz_known")

    def test_utc_equivalent_timestamps_grouped_across_offsets(self):
        # 12:00:00+05:30 == 06:30:00Z; 06:30:20Z is 20s later in real UTC
        # terms despite the printed offsets differing - proves comparison
        # uses the UTC-equivalent value, not the raw printed clock time.
        timeline = [
            _abs_known("2026-09-04T12:00:00+05:30", summary="a"),
            _abs_known("2026-09-04T06:30:20+00:00", summary="b"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].evidence_count, 2)

    def test_unknown_timezone_timestamps_grouped_among_themselves(self):
        timeline = [
            _abs_unknown("2026-09-04T12:00:00", summary="a"),
            _abs_unknown("2026-09-04T12:00:10", summary="b"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].temporal_comparability, "absolute_tz_unknown")

    def test_known_and_unknown_timezone_never_mixed_in_one_group(self):
        # Numerically "close" (same clock reading) but MUST stay in
        # separate groups/tiers - a tz-unknown value must never be
        # silently assumed to share the tz-known value's timeline.
        timeline = [
            _abs_known("2026-09-04T12:00:00+00:00", summary="known"),
            _abs_unknown("2026-09-04T12:00:01", summary="unknown"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 2)
        tiers = sorted(g.temporal_comparability for g in groups)
        self.assertEqual(tiers, ["absolute_tz_known", "absolute_tz_unknown"])


class TimeOnlyTests(unittest.TestCase):
    def test_time_only_rows_grouped_by_time_of_day(self):
        timeline = [
            _time_only("12:00:00", summary="a"),
            _time_only("12:00:20", summary="b"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].temporal_comparability, "time_only")
        self.assertEqual(groups[0].start_timestamp, "12:00:00")
        self.assertEqual(groups[0].end_timestamp, "12:00:20")

    def test_time_only_never_mixed_with_absolute(self):
        timeline = [
            _abs_known("2026-09-04T12:00:00+00:00", summary="absolute"),
            _time_only("12:00:01", summary="time-only"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 2)
        tiers = sorted(g.temporal_comparability for g in groups)
        self.assertEqual(tiers, ["absolute_tz_known", "time_only"])

    def test_time_only_no_wraparound_across_midnight(self):
        # Documented limitation: 23:59:59 and 00:00:01 are NOT treated as
        # 2 seconds apart, since no date exists to prove adjacency.
        timeline = [
            _time_only("23:59:59", summary="a"),
            _time_only("00:00:01", summary="b"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 2)


class MissingTimestampTests(unittest.TestCase):
    def test_missing_timestamp_rows_never_clustered(self):
        timeline = [
            _no_ts(summary="one", category="generic_error"),
            _no_ts(summary="two", category="timeout"),
        ]
        groups, uncorrelated, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(groups, [])
        self.assertEqual(len(uncorrelated), 2)

    def test_missing_timestamp_evidence_preserved_not_dropped(self):
        timeline = [_no_ts(summary="important error", category="database_error")]
        _, uncorrelated, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(uncorrelated), 1)
        self.assertEqual(uncorrelated[0]["summary"], "important error")

    def test_truncation_marker_row_is_skipped_not_treated_as_evidence(self):
        timeline = [
            _no_ts(summary="real evidence"),
            {"note": "...additional timeline entries omitted, capped at 200"},
        ]
        _, uncorrelated, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(uncorrelated), 1)


class DuplicateAndEvidenceCountTests(unittest.TestCase):
    def test_duplicate_distinct_messages_each_count_once(self):
        timeline = [
            _abs_known("2026-09-04T12:00:00+00:00", summary="ERROR connection refused"),
            _abs_known("2026-09-04T12:00:05+00:00", summary="ERROR connection refused"),
            _abs_known("2026-09-04T12:00:10+00:00", summary="ERROR timeout"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].evidence_count, 3)

    def test_evidence_count_reflects_true_total_when_observations_capped(self):
        timeline = [
            _abs_known(f"2026-09-04T12:00:{i:02d}+00:00", summary=f"m{i}") for i in range(25)
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].evidence_count, 25)
        self.assertLessEqual(len(groups[0].observations), 20)


class SeverityTests(unittest.TestCase):
    def test_severity_summary_present(self):
        timeline = [
            _abs_known("2026-09-04T12:00:00+00:00", severity="high"),
            _abs_known("2026-09-04T12:00:05+00:00", severity="low"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(groups[0].severities, ["high", "low"])

    def test_severity_does_not_reorder_observations_within_group(self):
        # Chronological order must survive regardless of severity value -
        # a "low" severity row logged first must stay first.
        timeline = [
            _abs_known("2026-09-04T12:00:00+00:00", severity="low", summary="first"),
            _abs_known("2026-09-04T12:00:05+00:00", severity="high", summary="second"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual([o["summary"] for o in groups[0].observations], ["first", "second"])


class EventIntegrationTests(unittest.TestCase):
    def test_kubernetes_events_participate_in_correlation(self):
        timeline = [
            _abs_known(
                "2026-09-04T12:00:00+00:00", source="log", component="ts-app", category="timeout"
            ),
            _abs_known(
                "2026-09-04T12:00:05+00:00", source="event", category="oom_killed",
                namespace="commerce", involved_object="obdevlivets-app-abc", reason="Killing",
            ),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].sources, ["event", "log"])


class LogSourceTests(unittest.TestCase):
    def test_current_and_previous_logs_correlate_only_by_timestamp(self):
        timeline = [
            _abs_known("2026-09-04T12:00:00+00:00", log_source="previous", summary="crash cause"),
            _abs_known("2026-09-04T12:00:10+00:00", log_source="current", summary="restart"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 1)

    def test_current_and_previous_logs_not_forced_together_when_far_apart(self):
        # A previous log from long before the window must NOT be dragged
        # into a recent group just because log_source differs - only the
        # actual timestamp gap decides.
        timeline = [
            _abs_known("2026-09-01T00:00:00+00:00", log_source="previous", summary="old crash"),
            _abs_known("2026-09-04T12:00:00+00:00", log_source="current", summary="recent"),
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertEqual(len(groups), 2)


class BoundsTests(unittest.TestCase):
    def test_bounded_observations_per_group(self):
        timeline = [
            _abs_known(f"2026-09-04T12:00:{i:02d}+00:00", summary=f"m{i}") for i in range(30)
        ]
        groups, _, _ = cc.correlate_timeline(timeline, window_seconds=60)
        self.assertLessEqual(len(groups[0].observations), 20)

    def test_window_seconds_clamped_to_max(self):
        _, _, resolved = cc.correlate_timeline([], window_seconds=999999)
        self.assertEqual(resolved, cc.MAX_WINDOW_SECONDS)

    def test_window_seconds_below_one_clamped_to_one(self):
        _, _, resolved = cc.correlate_timeline([], window_seconds=0)
        self.assertEqual(resolved, 1)

    def test_default_window_seconds_used_when_omitted(self):
        _, _, resolved = cc.correlate_timeline([])
        self.assertEqual(resolved, cc.DEFAULT_WINDOW_SECONDS)
        self.assertEqual(resolved, 60)


class DeterminismTests(unittest.TestCase):
    def test_group_id_deterministic_across_repeated_calls(self):
        timeline = [
            _abs_known("2026-09-04T12:00:00+00:00", component="ts-app", summary="a"),
            _abs_known("2026-09-04T12:00:05+00:00", component="crs-app", summary="b"),
        ]
        groups1, _, _ = cc.correlate_timeline(list(timeline), window_seconds=60)
        groups2, _, _ = cc.correlate_timeline(list(timeline), window_seconds=60)
        self.assertEqual(groups1[0].group_id, groups2[0].group_id)

    def test_group_id_never_random(self):
        # Same call twice in the same process must be identical - proves
        # no uuid4()/time.time()-based randomness is involved.
        timeline = [_abs_known("2026-09-04T12:00:00+00:00", summary="a")]
        ids = {cc.correlate_timeline(timeline, window_seconds=60)[0][0].group_id for _ in range(5)}
        self.assertEqual(len(ids), 1)

    def test_different_content_yields_different_group_id(self):
        t1 = [_abs_known("2026-09-04T12:00:00+00:00", summary="a")]
        t2 = [_abs_known("2026-09-04T12:00:00+00:00", summary="b")]
        id1 = cc.correlate_timeline(t1, window_seconds=60)[0][0].group_id
        id2 = cc.correlate_timeline(t2, window_seconds=60)[0][0].group_id
        self.assertNotEqual(id1, id2)


class EmptyAndMalformedInputTests(unittest.TestCase):
    def test_empty_timeline_yields_empty_groups(self):
        groups, uncorrelated, _ = cc.correlate_timeline([])
        self.assertEqual(groups, [])
        self.assertEqual(uncorrelated, [])

    def test_malformed_row_missing_fields_never_raises(self):
        timeline = [{}, {"timestamp": "not-a-real-timestamp", "timestamp_precision": "absolute"}]
        try:
            groups, uncorrelated, _ = cc.correlate_timeline(timeline, window_seconds=60)
        except Exception as exc:  # pragma: no cover - the point is this never fires
            self.fail(f"correlate_timeline raised on malformed rows: {exc}")
        self.assertEqual(groups, [])
        self.assertEqual(len(uncorrelated), 2)

    def test_non_dict_row_never_raises_and_is_skipped(self):
        timeline = [None, "not a row", 42, _abs_known("2026-09-04T12:00:00+00:00", summary="real")]
        try:
            groups, uncorrelated, _ = cc.correlate_timeline(timeline, window_seconds=60)
        except Exception as exc:  # pragma: no cover
            self.fail(f"correlate_timeline raised on non-dict rows: {exc}")
        self.assertEqual(len(groups), 1)
        self.assertEqual(uncorrelated, [])

    def test_malformed_partial_time_never_raises(self):
        timeline = [_row(partial_time="99:99:99", timestamp_precision="time_only")]
        try:
            groups, uncorrelated, _ = cc.correlate_timeline(timeline, window_seconds=60)
        except Exception as exc:  # pragma: no cover
            self.fail(f"correlate_timeline raised on malformed partial_time: {exc}")
        self.assertEqual(groups, [])
        self.assertEqual(len(uncorrelated), 1)


class NoCausalClaimTests(unittest.TestCase):
    def test_no_causal_fields_on_correlation_group(self):
        forbidden = {
            "likely_cause", "root_event", "causal_relationship", "confidence",
            "dependency", "upstream", "downstream", "cause", "recommendation",
        }
        fields = set(cc.CorrelationGroup.__dataclass_fields__.keys())
        self.assertEqual(fields & forbidden, set())

    def test_approved_schema_fields_present(self):
        expected = {
            "group_id", "temporal_comparability", "start_timestamp", "end_timestamp",
            "duration_seconds", "observations", "evidence_count", "components", "pods",
            "releases", "categories", "severities", "sources",
        }
        self.assertEqual(set(cc.CorrelationGroup.__dataclass_fields__.keys()), expected)


if __name__ == "__main__":
    unittest.main()
