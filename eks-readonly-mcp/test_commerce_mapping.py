"""Unit tests for commerce_mapping.py - pure logic, no SSH/network."""
from __future__ import annotations

import unittest

import commerce_mapping as cm


def _pod(name, namespace, containers, phase="Running", release=None, release_group=None,
         restart_count=0, waiting_reason=None):
    labels = {}
    if release is not None:
        labels["release"] = release
    if release_group is not None:
        labels["group"] = release_group
    return {
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": {"containers": [{"name": c} for c in containers]},
        "status": {"phase": phase, "restart_count": restart_count, "waiting_reason": waiting_reason},
    }


class NormalizeComponentTests(unittest.TestCase):
    def test_known_component_lowercased(self):
        self.assertEqual(cm.normalize_component("TS-App"), "ts-app")

    def test_unknown_component_raises(self):
        with self.assertRaises(ValueError):
            cm.normalize_component("not-a-real-component")

    def test_empty_raises(self):
        with self.assertRaises(ValueError):
            cm.normalize_component("")


class ExpandRolesTests(unittest.TestCase):
    def test_plain_component_expands_to_itself(self):
        self.assertEqual(cm.expand_roles("ts-app"), ("ts-app",))

    def test_search_app_expands_to_repeater_and_slave(self):
        self.assertEqual(
            set(cm.expand_roles("search-app")), {"search-app-repeater", "search-app-slave"}
        )


class ResolveNamespaceTests(unittest.TestCase):
    def test_default_namespace_used_when_no_override(self):
        self.assertEqual(cm.resolve_namespace("ts-app", "commerce"), "commerce")

    def test_nginx_namespace_override(self):
        self.assertEqual(cm.resolve_namespace("nginx", "commerce"), "nginx")

    def test_redis_namespace_override(self):
        self.assertEqual(cm.resolve_namespace("redis", "commerce"), "redis")


class MatchPodsTests(unittest.TestCase):
    def test_exact_container_name_match(self):
        pods = [_pod("obdevlivets-app-abc123-xyz", "commerce", ["ts-app"])]
        matches = cm.match_pods("ts-app", pods)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].pod, "obdevlivets-app-abc123-xyz")
        self.assertEqual(matches[0].container, "ts-app")
        self.assertEqual(matches[0].namespace, "commerce")
        # No release label supplied by the test pod - must default to None,
        # never an empty string or a guessed value.
        self.assertIsNone(matches[0].release)
        self.assertIsNone(matches[0].release_group)

    def test_no_hardcoded_pod_name_needed_different_prefix_still_matches(self):
        # DEV and UAT pod names differ (obdevlive* vs obuatlive*) but the
        # container name is stable - this is the core discovery finding.
        dev_pods = [_pod("obdevlivecrs-app-58fd9dc58d-7q6vk", "commerce", ["crs-app"])]
        uat_pods = [_pod("obuatlivecrs-app-86f87cdb7f-8snvd", "commerce", ["crs-app"])]
        self.assertEqual(len(cm.match_pods("crs-app", dev_pods)), 1)
        self.assertEqual(len(cm.match_pods("crs-app", uat_pods)), 1)

    def test_pattern_fallback_matches_nginx_quirky_container_name(self):
        pods = [_pod("dev-nginx-nginx-ingress-946556dbc-hfhdd", "nginx", ["dev-nginx-nginx-ingress"])]
        matches = cm.match_pods("nginx", pods)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].container, "dev-nginx-nginx-ingress")

    def test_unrelated_container_does_not_match(self):
        pods = [_pod("some-other-app-abc", "commerce", ["some-other-container"])]
        self.assertEqual(cm.match_pods("ts-app", pods), [])

    def test_absent_component_returns_empty_not_error(self):
        # wcbd/utils are known to be absent in current deployments - this
        # must resolve to an empty list, never raise.
        pods = [_pod("obdevlivets-app-abc", "commerce", ["ts-app"])]
        self.assertEqual(cm.match_pods("wcbd", pods), [])
        self.assertEqual(cm.match_pods("utils", pods), [])

    def test_match_pods_on_role_group_raises(self):
        pods = [_pod("x", "commerce", ["search-app-repeater"])]
        with self.assertRaises(ValueError):
            cm.match_pods("search-app", pods)

    def test_multiple_replica_pods_all_matched(self):
        pods = [
            _pod("obdevlivecrs-app-58fd9dc58d-7q6vk", "commerce", ["crs-app"]),
            _pod("obdevlivecrs-app-58fd9dc58d-vcdl2", "commerce", ["crs-app"]),
        ]
        self.assertEqual(len(cm.match_pods("crs-app", pods)), 2)

    def test_pod_phase_is_captured(self):
        pods = [_pod("obdevlivets-app-abc", "commerce", ["ts-app"], phase="Pending")]
        matches = cm.match_pods("ts-app", pods)
        self.assertEqual(matches[0].phase, "Pending")


class AllComponentsTests(unittest.TestCase):
    def test_expected_components_present(self):
        expected = {
            "ts-app", "crs-app", "ts-web", "store-web", "search-app", "cache-app",
            "nginx", "redis", "tooling-web", "wcbd", "utils",
            "search-app-repeater", "search-app-slave",
        }
        self.assertEqual(set(cm.ALL_COMPONENTS), expected)

    def test_no_hardcoded_reference_to_unverified_auth_release(self):
        # ob-uat-auth was NOT found in live UAT discovery (2026-09-04) - the
        # mapping must never bake in a specific release name at all, this
        # guards against that regressing.
        for spec in cm.COMPONENT_MAP.values():
            haystack = " ".join(spec.containers) + " ".join(spec.container_patterns)
            self.assertNotIn("auth", haystack.lower())


class ReleaseDiscoveryTests(unittest.TestCase):
    """release/release_group must come from live pod labels only - the
    mapping never assumes a fixed set of release names (e.g. only
    live/share); any label value the pod actually carries is surfaced."""

    def test_release_and_group_captured_from_labels(self):
        pods = [
            _pod(
                "obdevlivets-app-abc123-xyz", "commerce", ["ts-app"],
                release="ob-dev-live", release_group="obdevlive",
            )
        ]
        matches = cm.match_pods("ts-app", pods)
        self.assertEqual(matches[0].release, "ob-dev-live")
        self.assertEqual(matches[0].release_group, "obdevlive")

    def test_share_release_captured_distinctly_from_live(self):
        pods = [
            _pod(
                "obdevtooling-web-abc", "commerce", ["tooling-web"],
                release="ob-dev-share", release_group="obdev",
            )
        ]
        matches = cm.match_pods("tooling-web", pods)
        self.assertEqual(matches[0].release, "ob-dev-share")

    def test_no_release_label_yields_none_not_guess(self):
        # nginx/redis are not part of the hcl-commerce chart and carry no
        # `release` label in real discovery.
        pods = [_pod("dev-nginx-nginx-ingress-abc", "nginx", ["dev-nginx-nginx-ingress"])]
        matches = cm.match_pods("nginx", pods)
        self.assertIsNone(matches[0].release)

    def test_arbitrary_release_name_discovered_without_mapping_change(self):
        # Proves the discovery mechanism is generic: if a real release
        # (auth-named or otherwise) ever appears, no code change here is
        # needed to see it - this does NOT assert such a release exists.
        pods = [
            _pod(
                "obuatauthts-app-xyz", "commerce", ["ts-app"],
                release="ob-uat-auth", release_group="obuatauth",
            )
        ]
        matches = cm.match_pods("ts-app", pods)
        self.assertEqual(matches[0].release, "ob-uat-auth")


class DistinctReleasesTests(unittest.TestCase):
    def test_multiple_releases_enumerated(self):
        pods = [
            _pod("p1", "commerce", ["ts-app"], release="ob-dev-live", release_group="obdevlive"),
            _pod("p2", "commerce", ["tooling-web"], release="ob-dev-share", release_group="obdev"),
        ]
        self.assertEqual(cm.distinct_releases(pods), ["ob-dev-live", "ob-dev-share"])

    def test_pods_without_release_label_excluded(self):
        pods = [
            _pod("p1", "commerce", ["ts-app"], release="ob-dev-live"),
            _pod("p2", "nginx", ["dev-nginx-nginx-ingress"]),  # no release label
        ]
        self.assertEqual(cm.distinct_releases(pods), ["ob-dev-live"])

    def test_no_releases_present(self):
        pods = [_pod("p1", "nginx", ["dev-nginx-nginx-ingress"])]
        self.assertEqual(cm.distinct_releases(pods), [])

    def test_empty_pod_list(self):
        self.assertEqual(cm.distinct_releases([]), [])

    def test_duplicate_release_values_deduplicated(self):
        pods = [
            _pod("p1", "commerce", ["ts-app"], release="ob-dev-live"),
            _pod("p2", "commerce", ["crs-app"], release="ob-dev-live"),
        ]
        self.assertEqual(cm.distinct_releases(pods), ["ob-dev-live"])


class MatchPodsRestartWaitingTests(unittest.TestCase):
    def test_restart_count_and_waiting_reason_flow_into_matched_pod(self):
        pods = [_pod("p1", "commerce", ["crs-app"], restart_count=6, waiting_reason="CrashLoopBackOff")]
        matches = cm.match_pods("crs-app", pods)
        self.assertEqual(matches[0].restart_count, 6)
        self.assertEqual(matches[0].waiting_reason, "CrashLoopBackOff")

    def test_defaults_when_absent(self):
        pods = [_pod("p1", "commerce", ["ts-app"])]
        matches = cm.match_pods("ts-app", pods)
        self.assertEqual(matches[0].restart_count, 0)
        self.assertIsNone(matches[0].waiting_reason)


class PodHealthSummaryTests(unittest.TestCase):
    def test_running_zero_restarts_is_running_stable(self):
        matched = cm.MatchedPod(pod="p1", namespace="commerce", container="ts-app", phase="Running")
        self.assertEqual(cm.pod_health_summary(matched)["state"], "running_stable")

    def test_running_with_restarts_is_flagged(self):
        matched = cm.MatchedPod(
            pod="p1", namespace="commerce", container="ts-app", phase="Running", restart_count=2
        )
        self.assertEqual(cm.pod_health_summary(matched)["state"], "running_with_restarts")

    def test_crash_loop_backoff_detected_even_when_phase_running(self):
        # This is the core bug being fixed: a crash-looping container
        # commonly still reports pod phase="Running" - phase alone must
        # never be read as "healthy".
        matched = cm.MatchedPod(
            pod="p1", namespace="commerce", container="crs-app", phase="Running",
            restart_count=12, waiting_reason="CrashLoopBackOff",
        )
        health = cm.pod_health_summary(matched)
        self.assertEqual(health["state"], "crash_looping")
        self.assertEqual(health["phase"], "Running")

    def test_image_pull_backoff_detected(self):
        matched = cm.MatchedPod(
            pod="p1", namespace="commerce", container="ts-app", phase="Pending",
            waiting_reason="ImagePullBackOff",
        )
        self.assertEqual(cm.pod_health_summary(matched)["state"], "image_pull_backoff")

    def test_err_image_pull_also_detected(self):
        matched = cm.MatchedPod(
            pod="p1", namespace="commerce", container="ts-app", phase="Pending",
            waiting_reason="ErrImagePull",
        )
        self.assertEqual(cm.pod_health_summary(matched)["state"], "image_pull_backoff")

    def test_unrecognized_waiting_reason_still_surfaced(self):
        matched = cm.MatchedPod(
            pod="p1", namespace="commerce", container="ts-app", phase="Pending",
            waiting_reason="ContainerCreating",
        )
        self.assertEqual(cm.pod_health_summary(matched)["state"], "waiting:ContainerCreating")

    def test_non_running_no_waiting_reason_falls_back_to_phase(self):
        matched = cm.MatchedPod(pod="p1", namespace="commerce", container="ts-app", phase="Pending")
        self.assertEqual(cm.pod_health_summary(matched)["state"], "pending")


if __name__ == "__main__":
    unittest.main()
