"""Unit tests for commerce_tools.py.

Pure parsing logic is tested directly; everything that talks to the
cluster goes through kube_core._run() or kube_core.get_pod_logs_impl() as
imported into this module's namespace (`commerce_tools._run` /
`commerce_tools.get_pod_logs_impl`), so patching those two names is
sufficient to exercise every tool function with no SSH/network/live
cluster. Importing commerce_tools pulls in kube_core.py, which loads
config from the environment (.env) at import time; that's an existing
property of the module, not something these tests add.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import commerce_log_analyzer as cla
import commerce_mapping
import commerce_tools as ct


# --------------------------------------------------------------------------
# Test fixtures / fakes
# --------------------------------------------------------------------------

def _pod_line(name, namespace, phase="Running", release=None, group=None,
              restarts=None, waiting=None, containers=("ts-app",)):
    """Build one -o custom-columns row exactly as _parse_pod_discovery_line
    expects (8 whitespace-separated fields, matching _POD_DISCOVERY_COLUMNS)."""
    def tok(v):
        return v if v not in (None, "") else ct._CUSTOM_COLUMNS_NONE
    return "  ".join(
        [
            name,
            namespace,
            phase,
            tok(release),
            tok(group),
            tok(restarts),
            tok(waiting),
            ",".join(containers) if containers else ct._CUSTOM_COLUMNS_NONE,
        ]
    )


def _fake_run(pod_lines_by_ns=None, events_by_ns=None):
    """Build a fake kube_core._run() replacement: routes `get pods -n X` to
    canned custom-columns rows and `get events -n X` to canned Warning
    event JSON, keyed by namespace. Anything else errors loudly rather
    than silently returning nothing, so a test typo surfaces immediately."""
    pod_lines_by_ns = pod_lines_by_ns or {}
    events_by_ns = events_by_ns or {}

    def run(kubectl_command: str, env: str = "dev") -> str:
        if "get pods -n" in kubectl_command:
            ns = kubectl_command.split("-n ", 1)[1].split()[0]
            lines = pod_lines_by_ns.get(ns, [])
            if not lines:
                return f"[env={env}]\n(empty result - no matching resources)"
            return f"[env={env}]\n" + "\n".join(lines)
        if "get events -n" in kubectl_command:
            ns = kubectl_command.split("-n ", 1)[1].split()[0]
            items = events_by_ns.get(ns, [])
            return f"[env={env}]\n" + json.dumps({"items": items})
        raise AssertionError(f"unexpected kubectl command in test: {kubectl_command!r}")

    return run


def _fake_get_pod_logs(logs_by_pod):
    """logs_by_pod: {(pod_name, previous_bool): log_text}. Missing keys
    return an empty (but successful) log body."""

    def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                      previous=False, since=None, env="dev"):
        text = logs_by_pod.get((pod, previous), "")
        return f"[env={env}]\n{text}"

    return get_pod_logs


def _body(tool_result: str) -> dict:
    """Strip the leading "[env=...]\\n" tag and parse the JSON body."""
    return json.loads(tool_result.split("\n", 1)[1])


# --------------------------------------------------------------------------
# Pod discovery line parsing (restart/waiting-reason parsing)
# --------------------------------------------------------------------------

class ParsePodDiscoveryLineTests(unittest.TestCase):
    def test_release_and_group_present(self):
        line = _pod_line(
            "obdevlivets-app-59d4586466-tgfqf", "commerce", release="ob-dev-live",
            group="obdevlive", restarts="0", containers=("ts-app",),
        )
        item = ct._parse_pod_discovery_line(line)
        self.assertIsNotNone(item)
        self.assertEqual(item["metadata"]["name"], "obdevlivets-app-59d4586466-tgfqf")
        self.assertEqual(item["metadata"]["namespace"], "commerce")
        self.assertEqual(item["status"]["phase"], "Running")
        self.assertEqual(item["metadata"]["labels"]["release"], "ob-dev-live")
        self.assertEqual(item["metadata"]["labels"]["group"], "obdevlive")
        self.assertEqual(item["spec"]["containers"], [{"name": "ts-app"}])

    def test_share_release_parsed_distinctly(self):
        line = _pod_line(
            "obdevtooling-web-7c57c44b5b-hrplh", "commerce", release="ob-dev-share",
            group="obdev", restarts="0", containers=("tooling-web",),
        )
        item = ct._parse_pod_discovery_line(line)
        self.assertEqual(item["metadata"]["labels"]["release"], "ob-dev-share")
        self.assertEqual(item["metadata"]["labels"]["group"], "obdev")

    def test_none_release_and_group_omitted_from_labels(self):
        line = _pod_line(
            "dev-nginx-nginx-ingress-946556dbc-hfhdd", "nginx", restarts="0",
            containers=("dev-nginx-nginx-ingress",),
        )
        item = ct._parse_pod_discovery_line(line)
        self.assertNotIn("release", item["metadata"]["labels"])
        self.assertNotIn("group", item["metadata"]["labels"])

    def test_multiple_containers_comma_joined(self):
        line = _pod_line("somepod", "commerce", restarts="0,0", containers=("ts-app", "istio-proxy"))
        item = ct._parse_pod_discovery_line(line)
        names = [c["name"] for c in item["spec"]["containers"]]
        self.assertEqual(names, ["ts-app", "istio-proxy"])

    def test_none_containers_yields_empty_list(self):
        line = _pod_line("somepod", "commerce", phase="Pending", restarts=None, containers=None)
        item = ct._parse_pod_discovery_line(line)
        self.assertEqual(item["spec"]["containers"], [])

    def test_malformed_short_line_returns_none(self):
        self.assertIsNone(ct._parse_pod_discovery_line("only two fields"))

    def test_blank_line_returns_none(self):
        self.assertIsNone(ct._parse_pod_discovery_line(""))

    def test_restart_count_parsed_as_integer(self):
        line = _pod_line("somepod", "commerce", restarts="3")
        item = ct._parse_pod_discovery_line(line)
        self.assertEqual(item["status"]["restart_count"], 3)

    def test_restart_count_zero_when_none(self):
        line = _pod_line("somepod", "commerce", restarts=None)
        item = ct._parse_pod_discovery_line(line)
        self.assertEqual(item["status"]["restart_count"], 0)

    def test_restart_count_takes_max_of_multi_container_list(self):
        line = _pod_line("somepod", "commerce", restarts="1,5,2", containers=("a", "b", "c"))
        item = ct._parse_pod_discovery_line(line)
        self.assertEqual(item["status"]["restart_count"], 5)

    def test_restart_count_ignores_unparseable_tokens(self):
        # Defensive: a stray non-integer token must not crash parsing.
        line = _pod_line("somepod", "commerce", restarts="2,x", containers=("a", "b"))
        item = ct._parse_pod_discovery_line(line)
        self.assertEqual(item["status"]["restart_count"], 2)

    def test_waiting_reason_captured(self):
        line = _pod_line("somepod", "commerce", phase="Running", waiting="CrashLoopBackOff", restarts="4")
        item = ct._parse_pod_discovery_line(line)
        self.assertEqual(item["status"]["waiting_reason"], "CrashLoopBackOff")

    def test_waiting_reason_none_when_absent(self):
        line = _pod_line("somepod", "commerce", waiting=None, restarts="0")
        item = ct._parse_pod_discovery_line(line)
        self.assertIsNone(item["status"]["waiting_reason"])

    def test_waiting_reason_takes_first_non_none_of_multi_container_list(self):
        line = _pod_line(
            "somepod", "commerce", waiting="<none>,ImagePullBackOff", restarts="0,0",
            containers=("a", "b"),
        )
        item = ct._parse_pod_discovery_line(line)
        self.assertEqual(item["status"]["waiting_reason"], "ImagePullBackOff")


# --------------------------------------------------------------------------
# _fetch_pods / commerce_mapping integration
# --------------------------------------------------------------------------

class FetchPodsWithMockedRunTests(unittest.TestCase):
    def test_ts_app_release_and_group_flow_through_to_match_pods(self):
        line = _pod_line(
            "obdevlivets-app-59d4586466-tgfqf", "commerce", release="ob-dev-live",
            group="obdevlive", restarts="0", containers=("ts-app",),
        )
        with patch.object(ct, "_run", side_effect=_fake_run({"commerce": [line]})):
            items, err = ct._fetch_pods("commerce", "dev")
        self.assertIsNone(err)
        matches = commerce_mapping.match_pods("ts-app", items)
        self.assertEqual(matches[0].release, "ob-dev-live")
        self.assertEqual(matches[0].release_group, "obdevlive")

    def test_restart_and_waiting_reason_flow_through_to_match_pods(self):
        line = _pod_line(
            "obdevlivecrs-app-abc", "commerce", phase="Running",
            waiting="CrashLoopBackOff", restarts="7", containers=("crs-app",),
        )
        with patch.object(ct, "_run", side_effect=_fake_run({"commerce": [line]})):
            items, _ = ct._fetch_pods("commerce", "dev")
        matches = commerce_mapping.match_pods("crs-app", items)
        self.assertEqual(matches[0].restart_count, 7)
        self.assertEqual(matches[0].waiting_reason, "CrashLoopBackOff")
        health = commerce_mapping.pod_health_summary(matches[0])
        self.assertEqual(health["state"], "crash_looping")

    def test_error_output_returns_empty_items_and_error_message(self):
        def run(cmd, env="dev"):
            return "[env=dev] Error: kubectl failed"

        with patch.object(ct, "_run", side_effect=run):
            items, err = ct._fetch_pods("commerce", "dev")
        self.assertEqual(items, [])
        self.assertIsNotNone(err)


# --------------------------------------------------------------------------
# _collect_component_logs: previous-log decision + log coverage
# --------------------------------------------------------------------------

class CollectComponentLogsTests(unittest.TestCase):
    def _pods_fixture(self):
        return {
            "commerce": [
                _pod_line("obdevlivets-app-a", "commerce", release="ob-dev-live",
                          group="obdevlive", restarts="0", containers=("ts-app",)),
                _pod_line("obdevlivets-app-b", "commerce", release="ob-dev-live",
                          group="obdevlive", restarts="3", containers=("ts-app",)),
            ]
        }

    def test_zero_restarts_never_fetches_previous(self):
        run = _fake_run(self._pods_fixture())
        log_calls = []

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            log_calls.append((pod, previous))
            return f"[env={env}]\nsome log line"

        with patch.object(ct, "_run", side_effect=run), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            entries, errors, total = ct._collect_component_logs(
                "ts-app", "commerce", 100, None, False, "dev", auto_previous_on_restart=True
            )

        calls_for_a = [c for c in log_calls if c[0] == "obdevlivets-app-a"]
        self.assertEqual(calls_for_a, [("obdevlivets-app-a", False)])

    def test_nonzero_restarts_fetches_both_current_and_previous(self):
        run = _fake_run(self._pods_fixture())

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\nsome log line"

        with patch.object(ct, "_run", side_effect=run), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            entries, errors, total = ct._collect_component_logs(
                "ts-app", "commerce", 100, None, False, "dev", auto_previous_on_restart=True
            )

        sources_for_b = sorted(e["log_source"] for e in entries if e["pod"] == "obdevlivets-app-b")
        self.assertEqual(sources_for_b, ["current", "previous"])

    def test_explicit_previous_mode_does_not_auto_fetch(self):
        # auto_previous_on_restart=False (get_commerce_component_logs' path):
        # exactly one entry per pod, honoring only the explicit `previous` arg.
        run = _fake_run(self._pods_fixture())

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\nsome log line"

        with patch.object(ct, "_run", side_effect=run), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            entries, errors, total = ct._collect_component_logs(
                "ts-app", "commerce", 100, None, False, "dev", auto_previous_on_restart=False
            )

        pods_seen = [e["pod"] for e in entries]
        self.assertEqual(len(pods_seen), len(set(pods_seen)))  # exactly one entry per pod

    def test_log_coverage_tail_cap_hit_when_lines_equal_requested(self):
        run = _fake_run({"commerce": [_pod_line("p1", "commerce", restarts="0")]})

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\n" + "\n".join(f"line{i}" for i in range(tail_lines))

        with patch.object(ct, "_run", side_effect=run), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            entries, _, _ = ct._collect_component_logs("ts-app", "commerce", 50, None, False, "dev")

        self.assertEqual(entries[0]["log_coverage"]["requested_tail_lines"], 50)
        self.assertEqual(entries[0]["log_coverage"]["lines_returned"], 50)
        self.assertTrue(entries[0]["log_coverage"]["tail_cap_hit"])

    def test_log_coverage_tail_cap_not_hit_when_fewer_lines(self):
        run = _fake_run({"commerce": [_pod_line("p1", "commerce", restarts="0")]})

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\nonly one line"

        with patch.object(ct, "_run", side_effect=run), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            entries, _, _ = ct._collect_component_logs("ts-app", "commerce", 50, None, False, "dev")

        self.assertFalse(entries[0]["log_coverage"]["tail_cap_hit"])

    def test_release_and_health_fields_present_on_entry(self):
        run = _fake_run(self._pods_fixture())

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\nlog"

        with patch.object(ct, "_run", side_effect=run), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            entries, _, _ = ct._collect_component_logs("ts-app", "commerce", 100, None, False, "dev")

        entry = entries[0]
        for key in ("release", "release_group", "restart_count", "waiting_reason", "log_source", "log_coverage"):
            self.assertIn(key, entry)


# --------------------------------------------------------------------------
# _classify_warning_events
# --------------------------------------------------------------------------

class ClassifyWarningEventsTests(unittest.TestCase):
    def test_scheduling_failure_event_classified(self):
        events = {
            "commerce": [
                {
                    "type": "Warning", "reason": "FailedScheduling",
                    "message": "0/3 nodes are available: Insufficient cpu.",
                    "involvedObject": {"name": "obdevlivecrs-app-abc"},
                    "count": 5, "lastTimestamp": "2026-09-04T00:00:00Z",
                }
            ]
        }
        with patch.object(ct, "_run", side_effect=_fake_run(events_by_ns=events)):
            classified, errors = ct._classify_warning_events(["commerce"], "dev")
        self.assertEqual(errors, [])
        self.assertEqual(classified[0]["category"], "scheduling_failure")
        self.assertEqual(classified[0]["severity"], "high")
        self.assertEqual(classified[0]["source"], "event")
        self.assertEqual(classified[0]["namespace"], "commerce")
        self.assertEqual(classified[0]["involved_object"], "obdevlivecrs-app-abc")

    def test_unmatched_event_marked_unclassified(self):
        events = {"commerce": [{"type": "Warning", "reason": "SomeReason", "message": "nothing matches here"}]}
        with patch.object(ct, "_run", side_effect=_fake_run(events_by_ns=events)):
            classified, _ = ct._classify_warning_events(["commerce"], "dev")
        self.assertEqual(classified[0]["category"], "unclassified")

    def test_events_sorted_by_severity_then_count(self):
        events = {
            "commerce": [
                {"type": "Warning", "reason": "R1", "message": "ERROR generic issue", "count": 100},
                {"type": "Warning", "reason": "R2", "message": "OOMKilled", "count": 1},
            ]
        }
        with patch.object(ct, "_run", side_effect=_fake_run(events_by_ns=events)):
            classified, _ = ct._classify_warning_events(["commerce"], "dev")
        # oom_killed (high severity, count=1) must rank ABOVE generic_error
        # (low severity, count=100) - severity beats raw count.
        self.assertEqual(classified[0]["category"], "oom_killed")

    def test_events_capped_at_max(self):
        many_events = [
            {"type": "Warning", "reason": f"R{i}", "message": "ERROR issue", "count": 1}
            for i in range(ct._MAX_EVENTS_CLASSIFIED + 10)
        ]
        with patch.object(ct, "_run", side_effect=_fake_run(events_by_ns={"commerce": many_events})):
            classified, _ = ct._classify_warning_events(["commerce"], "dev")
        # capped list + one trailing "omitted" marker
        self.assertEqual(len(classified), ct._MAX_EVENTS_CLASSIFIED + 1)
        self.assertIn("note", classified[-1])

    def test_no_events_yields_empty_list(self):
        with patch.object(ct, "_run", side_effect=_fake_run(events_by_ns={"commerce": []})):
            classified, errors = ct._classify_warning_events(["commerce"], "dev")
        self.assertEqual(classified, [])
        self.assertEqual(errors, [])

    def test_first_timestamp_captured(self):
        events = {
            "commerce": [
                {"type": "Warning", "reason": "R", "message": "ERROR x",
                 "firstTimestamp": "2026-09-04T10:00:00Z", "lastTimestamp": "2026-09-04T10:05:00Z",
                 "eventTime": None},
            ]
        }
        with patch.object(ct, "_run", side_effect=_fake_run(events_by_ns=events)):
            classified, _ = ct._classify_warning_events(["commerce"], "dev")
        self.assertEqual(classified[0]["firstTimestamp"], "2026-09-04T10:00:00Z")

    def test_event_time_captured(self):
        events = {
            "commerce": [
                {"type": "Warning", "reason": "R", "message": "ERROR x",
                 "firstTimestamp": "2026-09-04T10:00:00Z", "lastTimestamp": "2026-09-04T10:05:00Z",
                 "eventTime": "2026-09-04T10:00:00.500Z"},
            ]
        }
        with patch.object(ct, "_run", side_effect=_fake_run(events_by_ns=events)):
            classified, _ = ct._classify_warning_events(["commerce"], "dev")
        self.assertEqual(classified[0]["eventTime"], "2026-09-04T10:00:00.500Z")

    def test_last_timestamp_preserved(self):
        events = {
            "commerce": [
                {"type": "Warning", "reason": "R", "message": "ERROR x",
                 "lastTimestamp": "2026-09-04T10:05:00Z"},
            ]
        }
        with patch.object(ct, "_run", side_effect=_fake_run(events_by_ns=events)):
            classified, _ = ct._classify_warning_events(["commerce"], "dev")
        self.assertEqual(classified[0]["lastTimestamp"], "2026-09-04T10:05:00Z")

    def test_missing_timestamp_fields_return_none(self):
        # eventTime in particular is null on the vast majority of real
        # events - must never be fabricated, always None when absent.
        events = {"commerce": [{"type": "Warning", "reason": "R", "message": "ERROR x"}]}
        with patch.object(ct, "_run", side_effect=_fake_run(events_by_ns=events)):
            classified, _ = ct._classify_warning_events(["commerce"], "dev")
        self.assertIsNone(classified[0]["firstTimestamp"])
        self.assertIsNone(classified[0]["lastTimestamp"])
        self.assertIsNone(classified[0]["eventTime"])

    def test_null_event_time_in_source_returns_none(self):
        events = {
            "commerce": [
                {"type": "Warning", "reason": "R", "message": "ERROR x", "eventTime": None},
            ]
        }
        with patch.object(ct, "_run", side_effect=_fake_run(events_by_ns=events)):
            classified, _ = ct._classify_warning_events(["commerce"], "dev")
        self.assertIsNone(classified[0]["eventTime"])


# --------------------------------------------------------------------------
# assemble_timeline (Phase 4A): pure, no SSH/network - built directly on
# commerce_log_analyzer.classify_log_text() output and
# _classify_warning_events()-shaped event dicts.
# --------------------------------------------------------------------------

class AssembleTimelineTests(unittest.TestCase):
    def _log_entry(self, text, **context):
        analysis = cla.classify_log_text(text)
        base = {
            "component": "ts-app", "leaf_component": "ts-app", "release": "ob-dev-live",
            "release_group": "obdevlive", "pod": "obdevlivets-app-a", "container": "ts-app",
            "log_source": "current",
        }
        base.update(context)
        base["findings"] = analysis.findings
        return base

    def test_timestamps_sort_ascending(self):
        entry = self._log_entry(
            "2026-09-04T12:00:10Z ERROR second one\n2026-09-04T12:00:05Z ERROR first one"
        )
        timeline = ct.assemble_timeline([entry], [])
        timestamps = [row["timestamp"] for row in timeline if row.get("timestamp")]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_null_timestamps_remain_in_timeline(self):
        entry = self._log_entry("ERROR no timestamp at all")
        timeline = ct.assemble_timeline([entry], [])
        self.assertEqual(len(timeline), 1)
        self.assertIsNone(timeline[0]["timestamp"])

    def test_null_timestamps_appear_after_timestamped_entries(self):
        entry = self._log_entry("2026-09-04T12:00:00Z ERROR timestamped\nERROR not timestamped")
        timeline = ct.assemble_timeline([entry], [])
        self.assertEqual(len(timeline), 2)
        self.assertIsNotNone(timeline[0]["timestamp"])
        self.assertIsNone(timeline[1]["timestamp"])

    def test_time_only_never_becomes_fake_absolute(self):
        entry = self._log_entry("[12:34:56] ERROR bracketed only")
        timeline = ct.assemble_timeline([entry], [])
        row = timeline[0]
        self.assertIsNone(row["timestamp"])
        self.assertEqual(row["timestamp_precision"], "time_only")
        self.assertEqual(row["partial_time"], "12:34:56")

    def test_time_only_sorts_after_absolute_and_before_null(self):
        entry = self._log_entry(
            "2026-09-04T12:00:00Z ERROR absolute one\n[08:00:00] ERROR time only one\nERROR no timestamp one"
        )
        timeline = ct.assemble_timeline([entry], [])
        precisions = [row["timestamp_precision"] for row in timeline]
        self.assertEqual(precisions, ["absolute", "time_only", None])

    def test_log_and_event_entries_coexist(self):
        log_entry = self._log_entry("2026-09-04T12:00:00Z ERROR app error")
        events = [
            {"category": "oom_killed", "severity": "high", "namespace": "commerce",
             "involved_object": "p1", "reason": "Killing", "message": "OOMKilled",
             "firstTimestamp": "2026-09-04T11:59:00Z", "lastTimestamp": None, "eventTime": None},
        ]
        timeline = ct.assemble_timeline([log_entry], events)
        sources = {row["source"] for row in timeline}
        self.assertEqual(sources, {"log", "event"})

    def test_source_remains_log_or_event(self):
        log_entry = self._log_entry("ERROR app error")
        events = [
            {"category": "timeout", "severity": "medium", "namespace": "commerce",
             "involved_object": "p1", "reason": "R", "message": "timeout"},
        ]
        timeline = ct.assemble_timeline([log_entry], events)
        for row in timeline:
            self.assertIn(row["source"], ("log", "event"))

    def test_component_context_survives_for_log_entries(self):
        entry = self._log_entry("ERROR app error", component="crs-app")
        timeline = ct.assemble_timeline([entry], [])
        self.assertEqual(timeline[0]["component"], "crs-app")

    def test_leaf_component_survives(self):
        entry = self._log_entry("ERROR app error", leaf_component="search-app-repeater")
        timeline = ct.assemble_timeline([entry], [])
        self.assertEqual(timeline[0]["leaf_component"], "search-app-repeater")

    def test_release_and_release_group_survive(self):
        entry = self._log_entry("ERROR app error", release="ob-uat-share", release_group="obuat")
        timeline = ct.assemble_timeline([entry], [])
        self.assertEqual(timeline[0]["release"], "ob-uat-share")
        self.assertEqual(timeline[0]["release_group"], "obuat")

    def test_pod_and_container_survive(self):
        entry = self._log_entry("ERROR app error", pod="mypod", container="mycontainer")
        timeline = ct.assemble_timeline([entry], [])
        self.assertEqual(timeline[0]["pod"], "mypod")
        self.assertEqual(timeline[0]["container"], "mycontainer")

    def test_current_previous_log_source_survives(self):
        current = self._log_entry("ERROR one", log_source="current")
        previous = self._log_entry("ERROR two", log_source="previous")
        timeline = ct.assemble_timeline([current, previous], [])
        sources = {row["log_source"] for row in timeline}
        self.assertEqual(sources, {"current", "previous"})

    def test_event_component_fields_are_null_not_guessed(self):
        # Must NEVER guess a Commerce component from involvedObject's name.
        events = [
            {"category": "oom_killed", "severity": "high", "namespace": "commerce",
             "involved_object": "obdevlivets-app-abc", "reason": "Killing", "message": "OOMKilled",
             "firstTimestamp": "2026-09-04T10:00:00Z"},
        ]
        timeline = ct.assemble_timeline([], events)
        self.assertIsNone(timeline[0]["component"])
        self.assertIsNone(timeline[0]["leaf_component"])
        self.assertIsNone(timeline[0]["pod"])
        self.assertEqual(timeline[0]["involved_object"], "obdevlivets-app-abc")

    def test_event_yields_one_row_per_available_timestamp_field(self):
        events = [
            {"category": "oom_killed", "severity": "high", "namespace": "commerce",
             "involved_object": "p1", "reason": "Killing", "message": "OOMKilled",
             "firstTimestamp": "2026-09-04T10:00:00Z", "lastTimestamp": "2026-09-04T10:05:00Z",
             "eventTime": "2026-09-04T10:00:00.100Z"},
        ]
        timeline = ct.assemble_timeline([], events)
        sources = sorted(row["timestamp_source"] for row in timeline)
        # alphabetical: "eventTime" sorts before "event_firstTimestamp"/
        # "event_lastTimestamp" ('T' < '_' in ASCII).
        self.assertEqual(sources, ["eventTime", "event_firstTimestamp", "event_lastTimestamp"])

    def test_event_with_no_timestamps_yields_one_null_row(self):
        events = [
            {"category": "unclassified", "severity": "medium", "namespace": "commerce",
             "involved_object": "p1", "reason": "R", "message": "m"},
        ]
        timeline = ct.assemble_timeline([], events)
        self.assertEqual(len(timeline), 1)
        self.assertIsNone(timeline[0]["timestamp"])

    def test_truncation_marker_from_events_classified_is_skipped_not_treated_as_event(self):
        events = [
            {"category": "timeout", "severity": "medium", "namespace": "commerce",
             "involved_object": "p1", "reason": "R", "message": "timeout"},
            {"note": "...additional events omitted, capped at 30"},
        ]
        timeline = ct.assemble_timeline([], events)
        self.assertEqual(len(timeline), 1)

    def test_timeline_remains_bounded(self):
        # Evidence is already capped at 8 distinct samples per category
        # (Phase 3), so one category alone can't exceed that - use several
        # distinct categories, each near its own cap, to get more than
        # max_entries total rows and actually exercise timeline truncation.
        lines = []
        for i in range(8):
            lines.append(f"ERROR generic failure kind {i}")
            lines.append(f"Read timed out variant {i}")
            lines.append(f"Connection refused variant {i}")
            lines.append(f"Login failed variant {i}")
        entry = self._log_entry("\n".join(lines))
        timeline = ct.assemble_timeline([entry], [], max_entries=10)
        self.assertEqual(len(timeline), 11)  # 10 entries + 1 truncation marker
        self.assertIn("note", timeline[-1])

    def test_redaction_remains_intact_in_timeline_summary(self):
        entry = self._log_entry("ERROR login failed password=hunter2")
        timeline = ct.assemble_timeline([entry], [])
        self.assertNotIn("hunter2", timeline[0]["summary"])

    def test_no_internal_objects_leak_into_output(self):
        entry = self._log_entry("2026-09-04T12:00:00Z ERROR app error")
        timeline = ct.assemble_timeline([entry], [])
        for row in timeline:
            for value in row.values():
                self.assertIsInstance(value, (str, int, float, bool, type(None)))

    def test_empty_inputs_yield_empty_timeline(self):
        self.assertEqual(ct.assemble_timeline([], []), [])

    # -- 17. timeline compatible with the new timestamp formats -------------
    def test_timeline_sorts_new_format_timestamps_alongside_iso(self):
        # WebSphere Liberty (AEST, tz-known) and nginx-error (no tz) lines
        # mixed with an existing ISO (Z) line - proves assemble_timeline()
        # needed no changes for the newly-supported formats: it only ever
        # reads ParsedTimestamp.kind/value/timezone_known, which are
        # unchanged in shape.
        text = "\n".join(
            [
                "2026-09-04T12:00:10Z ERROR iso one",
                "[9/4/26 02:00:00:000 AEST] ERROR liberty one",
                "2026/09/04 20:00:20 ERROR nginx one",
            ]
        )
        entry = self._log_entry(text)
        timeline = ct.assemble_timeline([entry], [])
        rows_with_ts = [row for row in timeline if row.get("timestamp")]
        self.assertEqual(len(rows_with_ts), 3)
        # Liberty's AEST (UTC+10) 02:00:00 on 9/4 -> UTC 2026-09-03T16:00,
        # sorts first; ISO Z 2026-09-04T12:00:10 UTC sorts second; nginx
        # (tz-unknown) sorts in its own tier after every tz-known entry
        # regardless of clock time.
        self.assertIn("liberty one", rows_with_ts[0]["summary"])
        self.assertIn("iso one", rows_with_ts[1]["summary"])
        self.assertIn("nginx one", rows_with_ts[2]["summary"])
        self.assertTrue(rows_with_ts[0]["timezone_known"])
        self.assertTrue(rows_with_ts[1]["timezone_known"])
        self.assertFalse(rows_with_ts[2]["timezone_known"])


# --------------------------------------------------------------------------
# Tool-level tests (item 9): one or more direct tests per @mcp.tool()
# --------------------------------------------------------------------------

class ListCommerceComponentsToolTests(unittest.TestCase):
    def test_release_and_health_state_present(self):
        pods = {
            "commerce": [
                _pod_line("obdevlivets-app-a", "commerce", release="ob-dev-live",
                          group="obdevlive", restarts="0", containers=("ts-app",)),
            ],
            "nginx": [],
            "redis": [],
        }
        with patch.object(ct, "_run", side_effect=_fake_run(pods)):
            result = ct.list_commerce_components(env="dev")
        body = _body(result)
        role = body["components"]["ts-app"]["roles"][0]
        pod_entry = role["matched_pods"][0]
        self.assertEqual(pod_entry["release"], "ob-dev-live")
        self.assertEqual(pod_entry["release_group"], "obdevlive")
        self.assertEqual(pod_entry["state"], "running_stable")

    def test_wcbd_reports_not_deployed(self):
        with patch.object(ct, "_run", side_effect=_fake_run({"commerce": [], "nginx": [], "redis": []})):
            result = ct.list_commerce_components(env="dev")
        body = _body(result)
        self.assertEqual(body["components"]["wcbd"]["status"], "not_deployed")


class GetCommerceComponentLogsToolTests(unittest.TestCase):
    def test_log_coverage_present_in_output(self):
        pods = {"commerce": [_pod_line("obdevlivets-app-a", "commerce", restarts="0", containers=("ts-app",))]}

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\nline1\nline2"

        with patch.object(ct, "_run", side_effect=_fake_run(pods)), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.get_commerce_component_logs(component="ts-app", env="dev")
        body = _body(result)
        self.assertIn("log_coverage", body["logs"][0])
        self.assertEqual(body["logs"][0]["log_coverage"]["lines_returned"], 2)

    def test_not_deployed_component_reports_status(self):
        with patch.object(ct, "_run", side_effect=_fake_run({"commerce": []})):
            result = ct.get_commerce_component_logs(component="wcbd", env="dev")
        body = _body(result)
        self.assertIn("not_deployed", body["status"])


class AnalyzeCommerceComponentErrorsToolTests(unittest.TestCase):
    def test_findings_include_dedup_and_severity_fields(self):
        pods = {"commerce": [_pod_line("obdevlivets-app-a", "commerce", restarts="0", containers=("ts-app",))]}
        log_text = "ERROR connection refused\n" * 5

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\n{log_text}"

        with patch.object(ct, "_run", side_effect=_fake_run(pods)), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.analyze_commerce_component_errors(component="ts-app", env="dev")
        body = _body(result)
        finding = body["pods"][0]["findings"][0]
        for key in ("category", "severity", "count", "total_occurrences", "distinct_messages", "evidence"):
            self.assertIn(key, finding)
        self.assertEqual(finding["count"], 5)
        self.assertEqual(finding["distinct_messages"], 1)  # 5 identical lines -> 1 distinct message

    def test_restarted_pod_gets_current_and_previous_reports(self):
        pods = {"commerce": [_pod_line("obdevlivets-app-a", "commerce", restarts="2", containers=("ts-app",))]}

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\nlog for previous={previous}"

        with patch.object(ct, "_run", side_effect=_fake_run(pods)), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.analyze_commerce_component_errors(component="ts-app", env="dev")
        body = _body(result)
        sources = sorted(p["log_source"] for p in body["pods"])
        self.assertEqual(sources, ["current", "previous"])

    def test_leaf_component_present_in_pod_reports(self):
        # Correction 1: leaf_component must survive the reshape from
        # _collect_component_logs' entries into analyze's pod_reports -
        # this is what distinguishes search-app-repeater from
        # search-app-slave when analyzing the "search-app" role group.
        pods = {
            "commerce": [
                _pod_line("obdevlivesearch-app-repeater-a", "commerce", restarts="0",
                          containers=("search-app-repeater",)),
                _pod_line("obdevlivesearch-app-slave-a", "commerce", restarts="0",
                          containers=("search-app-slave",)),
            ]
        }

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\nINFO ok"

        with patch.object(ct, "_run", side_effect=_fake_run(pods)), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.analyze_commerce_component_errors(component="search-app", env="dev")
        body = _body(result)
        leaf_components = sorted(p["leaf_component"] for p in body["pods"])
        self.assertEqual(leaf_components, ["search-app-repeater", "search-app-slave"])


class CorrelateCommerceErrorsToolTests(unittest.TestCase):
    def test_co_occurring_categories_detected(self):
        pods = {
            "commerce": [
                _pod_line("obdevlivets-app-a", "commerce", restarts="0", containers=("ts-app",)),
                _pod_line("obdevlivecrs-app-a", "commerce", restarts="0", containers=("crs-app",)),
            ]
        }

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\nRead timed out"

        with patch.object(ct, "_run", side_effect=_fake_run(pods)), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.correlate_commerce_errors(components=["ts-app", "crs-app"], env="dev")
        body = _body(result)
        self.assertIn("timeout", body["co_occurring_categories"])
        self.assertEqual(sorted(body["co_occurring_categories"]["timeout"]), ["crs-app", "ts-app"])
        self.assertIn("top_findings", body["components"]["ts-app"])

    def test_release_group_present_per_component(self):
        # Correction 2: release_group must be computed from the collected
        # entries, the same live-data approach already used for release.
        pods = {
            "commerce": [
                _pod_line("obdevlivets-app-a", "commerce", release="ob-dev-live",
                          group="obdevlive", restarts="0", containers=("ts-app",)),
            ]
        }

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\nINFO ok"

        with patch.object(ct, "_run", side_effect=_fake_run(pods)), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.correlate_commerce_errors(components=["ts-app"], env="dev")
        body = _body(result)
        self.assertEqual(body["components"]["ts-app"]["release"], "ob-dev-live")
        self.assertEqual(body["components"]["ts-app"]["release_group"], "obdevlive")

    def test_empty_components_list_errors(self):
        result = ct.correlate_commerce_errors(components=[], env="dev")
        self.assertTrue(result.startswith("Error:"))


class DiagnoseCommerceIssueToolTests(unittest.TestCase):
    def test_confidence_is_per_component_not_aggregated(self):
        pods = {
            "commerce": [
                _pod_line("obdevlivets-app-a", "commerce", phase="Running", restarts="0", containers=("ts-app",)),
                # crs-app: zero matching pods (down)
            ]
        }

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\nINFO nothing wrong here"

        with patch.object(ct, "_run", side_effect=_fake_run(pods)), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.diagnose_commerce_issue(
                issue_description="test", components=["ts-app", "crs-app"], env="dev"
            )
        body = _body(result)
        self.assertIsInstance(body["confidence"], dict)
        self.assertIn("ts-app", body["confidence"])
        self.assertIn("crs-app", body["confidence"])
        self.assertIn("none", body["confidence"]["crs-app"])

    def test_event_derived_category_reaches_likely_cause(self):
        # oom_killed can basically never appear in app log text - it must
        # still surface via the classified-events path.
        pods = {"commerce": [_pod_line("obdevlivets-app-a", "commerce", restarts="0", containers=("ts-app",))]}
        events = {
            "commerce": [
                {"type": "Warning", "reason": "Killing", "message": "OOMKilled", "count": 1,
                 "involvedObject": {"name": "obdevlivets-app-a"}},
            ]
        }

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\nINFO clean log"

        with patch.object(ct, "_run", side_effect=_fake_run(pods, events)), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.diagnose_commerce_issue(
                issue_description="test", components=["ts-app"], env="dev"
            )
        body = _body(result)
        self.assertTrue(any("oom_killed" in line for line in body["likely_cause"]))
        self.assertTrue(
            any(e["category"] == "oom_killed" for e in body["cross_component_signals"]["events_classified"])
        )

    def test_components_grouped_shape(self):
        pods = {"commerce": [_pod_line("obdevlivets-app-a", "commerce", restarts="0", containers=("ts-app",))]}

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\nINFO fine"

        with patch.object(ct, "_run", side_effect=_fake_run(pods)), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.diagnose_commerce_issue(
                issue_description="test", components=["ts-app"], env="dev"
            )
        body = _body(result)
        for key in ("env", "since", "namespaces_checked", "components", "cross_component_signals"):
            self.assertIn(key, body if key != "env" else {"env": None, **body})
        ts_app = body["components"]["ts-app"]
        for key in ("release", "release_group", "pod_status", "log_coverage", "top_findings"):
            self.assertIn(key, ts_app)
        self.assertIn("co_occurring_categories", body["cross_component_signals"])
        self.assertIn("events_classified", body["cross_component_signals"])


class GetCommerceHealthToolTests(unittest.TestCase):
    def test_crash_looping_pod_not_reported_healthy(self):
        pods = {
            "commerce": [
                _pod_line("obdevlivecrs-app-a", "commerce", phase="Running",
                          waiting="CrashLoopBackOff", restarts="9", containers=("crs-app",)),
            ],
            "nginx": [], "redis": [],
        }
        with patch.object(ct, "_run", side_effect=_fake_run(pods)):
            result = ct.get_commerce_health(env="dev")
        body = _body(result)
        crs = body["components"]["crs-app"]
        self.assertEqual(crs["status"], "attention_needed")
        self.assertEqual(crs["pod_status"]["crash_looping"], 1)

    def test_all_running_zero_restarts_reports_healthy(self):
        pods = {
            "commerce": [
                _pod_line("obdevlivets-app-a", "commerce", phase="Running", restarts="0", containers=("ts-app",)),
            ],
            "nginx": [], "redis": [],
        }
        with patch.object(ct, "_run", side_effect=_fake_run(pods)):
            result = ct.get_commerce_health(env="dev")
        body = _body(result)
        self.assertEqual(body["components"]["ts-app"]["status"], "healthy")

    def test_events_classified_present(self):
        pods = {"commerce": [], "nginx": [], "redis": []}
        events = {"commerce": [{"type": "Warning", "reason": "R", "message": "timeout occurred", "count": 1}]}
        with patch.object(ct, "_run", side_effect=_fake_run(pods, events)):
            result = ct.get_commerce_health(env="dev")
        body = _body(result)
        self.assertTrue(any(e.get("category") == "timeout" for e in body["events_classified"]))

    def test_release_group_present_per_component(self):
        # Correction 3: release_group must be computed from the matched
        # pods, the same existing live release_group value used for release.
        pods = {
            "commerce": [
                _pod_line("obdevlivets-app-a", "commerce", phase="Running", release="ob-dev-live",
                          group="obdevlive", restarts="0", containers=("ts-app",)),
            ],
            "nginx": [], "redis": [],
        }
        with patch.object(ct, "_run", side_effect=_fake_run(pods)):
            result = ct.get_commerce_health(env="dev")
        body = _body(result)
        self.assertEqual(body["components"]["ts-app"]["release"], "ob-dev-live")
        self.assertEqual(body["components"]["ts-app"]["release_group"], "obdevlive")


class CorrelateCommerceTimelineToolTests(unittest.TestCase):
    """Phase 4B new tool - correlate_commerce_errors()/diagnose_commerce_issue()
    are exercised again here purely as regression checks (unchanged)."""

    def _pods_fixture(self):
        return {
            "commerce": [
                _pod_line("obdevlivets-app-a", "commerce", release="ob-dev-live",
                          group="obdevlive", restarts="0", containers=("ts-app",)),
                _pod_line("obdevlivecrs-app-a", "commerce", release="ob-dev-live",
                          group="obdevlive", restarts="0", containers=("crs-app",)),
            ],
            "nginx": [], "redis": [],
        }

    def test_tool_registered_and_returns_expected_top_level_shape(self):
        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\n2026-09-04T12:00:00Z ERROR timeout occurred"

        with patch.object(ct, "_run", side_effect=_fake_run(self._pods_fixture())), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.correlate_commerce_timeline(components=["ts-app", "crs-app"], env="dev")
        body = _body(result)
        for key in ("components", "since", "window_seconds", "namespaces_checked",
                    "fetch_errors", "timeline_entries_considered", "correlation_groups",
                    "uncorrelated", "note"):
            self.assertIn(key, body)
        self.assertEqual(body["window_seconds"], 60)

    def test_per_pod_classification_and_pod_attribution_preserved(self):
        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            if pod == "obdevlivets-app-a":
                return f"[env={env}]\n2026-09-04T12:00:00Z ERROR timeout occurred"
            return f"[env={env}]\n2026-09-04T12:00:05Z ERROR connection refused"

        with patch.object(ct, "_run", side_effect=_fake_run(self._pods_fixture())), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.correlate_commerce_timeline(components=["ts-app", "crs-app"], env="dev")
        body = _body(result)
        self.assertEqual(len(body["correlation_groups"]), 1)
        group = body["correlation_groups"][0]
        pods = {o["pod"] for o in group["observations"]}
        self.assertEqual(pods, {"obdevlivets-app-a", "obdevlivecrs-app-a"})
        self.assertEqual(sorted(group["components"]), ["crs-app", "ts-app"])

    def test_release_and_release_group_preserved_in_observations(self):
        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\n2026-09-04T12:00:00Z ERROR timeout occurred"

        with patch.object(ct, "_run", side_effect=_fake_run(self._pods_fixture())), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.correlate_commerce_timeline(components=["ts-app"], env="dev")
        body = _body(result)
        obs = body["correlation_groups"][0]["observations"][0]
        self.assertEqual(obs["release"], "ob-dev-live")
        self.assertEqual(obs["release_group"], "obdevlive")

    def test_event_integration(self):
        events = {
            "commerce": [
                {"type": "Warning", "reason": "Killing", "message": "OOMKilled",
                 "involvedObject": {"name": "obdevlivets-app-a"}, "count": 1,
                 "lastTimestamp": "2026-09-04T12:00:02Z"},
            ]
        }

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\n2026-09-04T12:00:00Z ERROR timeout occurred"

        with patch.object(ct, "_run", side_effect=_fake_run(self._pods_fixture(), events)), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.correlate_commerce_timeline(components=["ts-app"], env="dev")
        body = _body(result)
        sources = {o["source"] for g in body["correlation_groups"] for o in g["observations"]}
        self.assertIn("event", sources)

    def test_window_parameter_respected_and_returned(self):
        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\n2026-09-04T12:00:00Z ERROR timeout occurred"

        with patch.object(ct, "_run", side_effect=_fake_run(self._pods_fixture())), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.correlate_commerce_timeline(components=["ts-app"], window_seconds=120, env="dev")
        body = _body(result)
        self.assertEqual(body["window_seconds"], 120)

    def test_window_parameter_clamped_to_max(self):
        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\n2026-09-04T12:00:00Z ERROR timeout occurred"

        with patch.object(ct, "_run", side_effect=_fake_run(self._pods_fixture())), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.correlate_commerce_timeline(components=["ts-app"], window_seconds=99999, env="dev")
        body = _body(result)
        self.assertEqual(body["window_seconds"], 3600)

    def test_bounded_group_count(self):
        pods = {"commerce": [_pod_line("obdevlivets-app-a", "commerce", restarts="0",
                                        containers=("ts-app",))], "nginx": [], "redis": []}

        # 24 lines across 3 categories (8 distinct messages each, so none
        # hit the per-category evidence cap), each 5 minutes apart -
        # guaranteed 24 singleton groups at the default 60s window, well
        # beyond the 20-group cap.
        templates = ["ERROR unique failure {i}", "Read timed out variant {i}", "Connection refused variant {i}"]
        lines = []
        for idx in range(24):
            hour = 12 + (idx * 5) // 60
            minute = (idx * 5) % 60
            template = templates[idx % 3]
            lines.append(f"2026-09-04T{hour:02d}:{minute:02d}:00Z " + template.format(i=idx))
        log_text = "\n".join(lines)

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\n{log_text}"

        with patch.object(ct, "_run", side_effect=_fake_run(pods)), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.correlate_commerce_timeline(components=["ts-app"], env="dev")
        body = _body(result)
        self.assertEqual(len(body["correlation_groups"]), ct._MAX_CORRELATION_GROUPS + 1)
        self.assertIn("note", body["correlation_groups"][-1])

    def test_empty_components_list_errors(self):
        result = ct.correlate_commerce_timeline(components=[], env="dev")
        self.assertTrue(result.startswith("Error:"))

    def test_unknown_component_errors(self):
        result = ct.correlate_commerce_timeline(components=["not-a-real-component"], env="dev")
        self.assertTrue(result.startswith("Error:"))

    def test_correlate_commerce_errors_unchanged_regression(self):
        pods = {
            "commerce": [
                _pod_line("obdevlivets-app-a", "commerce", restarts="0", containers=("ts-app",)),
                _pod_line("obdevlivecrs-app-a", "commerce", restarts="0", containers=("crs-app",)),
            ]
        }

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\nRead timed out"

        with patch.object(ct, "_run", side_effect=_fake_run(pods)), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.correlate_commerce_errors(components=["ts-app", "crs-app"], env="dev")
        body = _body(result)
        self.assertIn("timeout", body["co_occurring_categories"])
        self.assertIn("top_findings", body["components"]["ts-app"])
        self.assertNotIn("correlation_groups", body)

    def test_diagnose_commerce_issue_unchanged_regression(self):
        pods = {"commerce": [_pod_line("obdevlivets-app-a", "commerce", restarts="0", containers=("ts-app",))]}

        def get_pod_logs(namespace, pod, container=None, tail_lines=100,
                          previous=False, since=None, env="dev"):
            return f"[env={env}]\nINFO fine"

        with patch.object(ct, "_run", side_effect=_fake_run(pods)), \
             patch.object(ct, "get_pod_logs_impl", side_effect=get_pod_logs):
            result = ct.diagnose_commerce_issue(issue_description="test", components=["ts-app"], env="dev")
        body = _body(result)
        self.assertIn("likely_cause", body)
        self.assertIn("confidence", body)
        self.assertNotIn("correlation_groups", body)


if __name__ == "__main__":
    unittest.main()
