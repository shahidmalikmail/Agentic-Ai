"""Tests for prod_pod_columns.py (P10.3K).

Pure unit tests against representative FAKE `kubectl get pods -o
custom-columns ... --no-headers` text only - never real PROD output. No
SSH, no kubectl, no PROD contact of any kind; this module has no I/O at
all. NOT executed as part of P10.3K's own implementation - execution is
deferred to P10.3L per the phase instructions.
"""
from __future__ import annotations

import json
import unittest

import prod_pod_columns


def _row(
    name="checkout-7d9",
    namespace="commerce",
    phase="Running",
    pod_ip="10.13.4.55",
    node="ip-10-13-1-20.ec2.internal",
    containers="checkout",
    images="registry.internal/checkout:1.4.2",
    ready="true",
    restarts="0",
):
    return "\t".join([name, namespace, phase, pod_ip, node, containers, images, ready, restarts])


def _lines(*rows):
    return "\n".join(rows)


class NormalCasesTests(unittest.TestCase):
    def test_1_one_normal_pod(self):
        out = prod_pod_columns.parse_get_pods_columns(_row())
        data = json.loads(out)
        self.assertEqual(len(data["pods"]), 1)
        pod = data["pods"][0]
        self.assertEqual(pod["name"], "checkout-7d9")
        self.assertEqual(pod["namespace"], "commerce")
        self.assertEqual(pod["phase"], "Running")
        self.assertEqual(pod["pod_ip"], "10.13.4.55")
        self.assertEqual(pod["node"], "ip-10-13-1-20.ec2.internal")
        self.assertEqual(pod["containers"], [{"name": "checkout", "image": "registry.internal/checkout:1.4.2"}])
        self.assertEqual(pod["ready"], {"ready_count": 1, "total_count": 1})
        self.assertEqual(pod["restarts"], {"max": 0})

    def test_2_multiple_pods(self):
        raw = _lines(_row(name="a"), _row(name="b"), _row(name="c"))
        data = json.loads(prod_pod_columns.parse_get_pods_columns(raw))
        self.assertEqual([p["name"] for p in data["pods"]], ["a", "b", "c"])

    def test_3_multiple_namespaces(self):
        raw = _lines(_row(name="a", namespace="commerce"), _row(name="b", namespace="kube-system"))
        data = json.loads(prod_pod_columns.parse_get_pods_columns(raw))
        self.assertEqual({p["namespace"] for p in data["pods"]}, {"commerce", "kube-system"})

    def test_4_running_pod(self):
        data = json.loads(prod_pod_columns.parse_get_pods_columns(_row(phase="Running")))
        self.assertEqual(data["pods"][0]["phase"], "Running")

    def test_5_pending_pod(self):
        data = json.loads(
            prod_pod_columns.parse_get_pods_columns(
                _row(phase="Pending", pod_ip="<none>", node="<none>", ready="<none>", restarts="<none>")
            )
        )
        pod = data["pods"][0]
        self.assertEqual(pod["phase"], "Pending")
        self.assertIsNone(pod["pod_ip"])
        self.assertIsNone(pod["node"])
        self.assertEqual(pod["ready"], {"ready_count": 0, "total_count": 0})
        self.assertEqual(pod["restarts"], {"max": 0})

    def test_6_failed_pod(self):
        data = json.loads(prod_pod_columns.parse_get_pods_columns(_row(phase="Failed", ready="false")))
        pod = data["pods"][0]
        self.assertEqual(pod["phase"], "Failed")
        self.assertEqual(pod["ready"], {"ready_count": 0, "total_count": 1})

    def test_7_missing_pod_ip_becomes_null(self):
        data = json.loads(prod_pod_columns.parse_get_pods_columns(_row(pod_ip="<none>")))
        self.assertIsNone(data["pods"][0]["pod_ip"])
        self.assertNotIn("<none>", json.dumps(data))

    def test_8_missing_node_becomes_null(self):
        data = json.loads(prod_pod_columns.parse_get_pods_columns(_row(node="<none>")))
        self.assertIsNone(data["pods"][0]["node"])

    def test_9_one_container(self):
        data = json.loads(prod_pod_columns.parse_get_pods_columns(_row(containers="app", images="img:1")))
        self.assertEqual(data["pods"][0]["containers"], [{"name": "app", "image": "img:1"}])

    def test_10_multiple_containers(self):
        data = json.loads(
            prod_pod_columns.parse_get_pods_columns(
                _row(
                    containers="app,sidecar",
                    images="img:1,sidecar:1",
                    ready="true,false",
                    restarts="0,2",
                )
            )
        )
        pod = data["pods"][0]
        self.assertEqual(
            pod["containers"], [{"name": "app", "image": "img:1"}, {"name": "sidecar", "image": "sidecar:1"}]
        )
        self.assertEqual(pod["ready"], {"ready_count": 1, "total_count": 2})
        self.assertEqual(pod["restarts"], {"max": 2})

    def test_11_container_image_alignment(self):
        data = json.loads(
            prod_pod_columns.parse_get_pods_columns(_row(containers="a,b,c", images="ia:1,ib:1,ic:1", ready="true,true,true", restarts="0,0,0"))
        )
        containers = data["pods"][0]["containers"]
        self.assertEqual(containers[0], {"name": "a", "image": "ia:1"})
        self.assertEqual(containers[1], {"name": "b", "image": "ib:1"})
        self.assertEqual(containers[2], {"name": "c", "image": "ic:1"})

    def test_12_ready_aggregate(self):
        data = json.loads(
            prod_pod_columns.parse_get_pods_columns(
                _row(containers="a,b,c", images="ia,ib,ic", ready="true,false,true", restarts="0,0,0")
            )
        )
        self.assertEqual(data["pods"][0]["ready"], {"ready_count": 2, "total_count": 3})

    def test_13_restart_max_aggregate(self):
        data = json.loads(
            prod_pod_columns.parse_get_pods_columns(
                _row(containers="a,b", images="ia,ib", ready="true,true", restarts="1,7")
            )
        )
        self.assertEqual(data["pods"][0]["restarts"], {"max": 7})

    def test_14_none_pod_ip(self):
        data = json.loads(prod_pod_columns.parse_get_pods_columns(_row(pod_ip="<none>")))
        self.assertIsNone(data["pods"][0]["pod_ip"])

    def test_15_none_node(self):
        data = json.loads(prod_pod_columns.parse_get_pods_columns(_row(node="<none>")))
        self.assertIsNone(data["pods"][0]["node"])


class FailClosedRequiredFieldTests(unittest.TestCase):
    def _assert_fail_closed(self, raw):
        out = prod_pod_columns.parse_get_pods_columns(raw)
        self.assertEqual(out, prod_pod_columns._WITHHELD_FAIL_CLOSED)

    def test_16_none_required_field_fails_closed(self):
        for field in ("name", "namespace", "phase", "containers", "images"):
            with self.subTest(field=field):
                self._assert_fail_closed(_row(**{field: "<none>"}))

    def test_17_malformed_line(self):
        self._assert_fail_closed("this is not a valid custom-columns row at all")

    def test_18_short_line(self):
        self._assert_fail_closed("only\tfour\tfields\there")

    def test_19_extra_column(self):
        self._assert_fail_closed(_row() + "\textra-unexpected-column")

    def test_20_blank_line_amid_data(self):
        self._assert_fail_closed(_row() + "\n\n" + _row(name="b"))

    def test_23_invalid_boolean(self):
        self._assert_fail_closed(_row(ready="maybe"))

    def test_24_invalid_restart_count(self):
        self._assert_fail_closed(_row(restarts="not-a-number"))

    def test_25_malformed_multi_value_field(self):
        self._assert_fail_closed(_row(containers="a,,c", images="ia,ib,ic", ready="true,true,true", restarts="0,0,0"))

    def test_26_inconsistent_container_image_lists(self):
        self._assert_fail_closed(_row(containers="a,b", images="ia", ready="true,true", restarts="0,0"))

    def test_ready_restart_count_mismatch_fails_closed(self):
        self._assert_fail_closed(_row(containers="a,b", images="ia,ib", ready="true", restarts="0,0"))

    def test_28_no_partial_results_on_failure(self):
        raw = _lines(_row(name="good-pod"), "malformed garbage line")
        out = prod_pod_columns.parse_get_pods_columns(raw)
        self.assertEqual(out, prod_pod_columns._WITHHELD_FAIL_CLOSED)
        self.assertNotIn("good-pod", out)

    def test_29_no_raw_stdout_fallback(self):
        raw = "totally-unparseable-raw-stdout-content-marker-XYZ"
        out = prod_pod_columns.parse_get_pods_columns(raw)
        self.assertNotIn("totally-unparseable-raw-stdout-content-marker-XYZ", out)


class EmptyResultTests(unittest.TestCase):
    def test_21_empty_stdout(self):
        data = json.loads(prod_pod_columns.parse_get_pods_columns(""))
        self.assertEqual(data, {"pods": []})

    def test_21b_whitespace_only_stdout(self):
        data = json.loads(prod_pod_columns.parse_get_pods_columns("   \n  \n"))
        self.assertEqual(data, {"pods": []})

    def test_22_no_resources_found_message(self):
        data = json.loads(
            prod_pod_columns.parse_get_pods_columns("No resources found in commerce namespace.\n")
        )
        self.assertEqual(data, {"pods": []})


class ParserExceptionTests(unittest.TestCase):
    def test_27_parser_exception_yields_fixed_fail_closed_output(self):
        # None is not a valid input type for this function - simulates an
        # unexpected internal condition rather than a normal malformed row.
        out = prod_pod_columns.parse_get_pods_columns(None)  # type: ignore[arg-type]
        self.assertEqual(out, prod_pod_columns._WITHHELD_FAIL_CLOSED)


class SecurityStaticTests(unittest.TestCase):
    """30 (P10.3L.1 correction): the fixed column spec must never
    reference a sensitive field PATH - checked as real path/token
    references, not arbitrary substrings. The original version of this
    test checked the bare substring "data", which false-positived against
    the legitimate, required, always-safe `.metadata.name`/
    `.metadata.namespace` paths (both of which contain "data" as part of
    "meta-data"). See test_30b below for a regression guard on that exact
    mistake."""

    # These specific tokens ("env"/"envFrom"/"data"/"stringData") are
    # substrings of legitimate field names elsewhere in Kubernetes' schema
    # ("metadata" contains "data") - checked with a leading dot, matching
    # how a JSONPath-style custom-columns expression actually references a
    # field (".data", ".stringData", ...), so "metadata" can never trigger
    # a false positive here.
    _FORBIDDEN_DOTTED_PATHS = (".env", ".envFrom", ".data", ".stringData")

    # These tokens are NOT substrings of any legitimate field name used
    # anywhere in this project's column specs, so a plain substring check
    # cannot false-positive against them - a bare check is precise enough.
    _FORBIDDEN_BARE_SUBSTRINGS = (
        "secretKeyRef",
        "configMapKeyRef",
        "secretRef",
        "configMapRef",
        "serviceAccount",
        "labels",
        "annotations",
    )

    # The complete, exact set of field paths POD_COLUMNS_SPEC is approved
    # to reference (P10.3J design). Asserting these are PRESENT, not just
    # that forbidden ones are ABSENT, pins the spec against an accidental
    # future change silently dropping (or replacing with something
    # unreviewed) an approved safe field.
    _APPROVED_SAFE_PATHS = (
        ".metadata.name",
        ".metadata.namespace",
        ".status.phase",
        ".status.podIP",
        ".spec.nodeName",
        ".spec.containers[*].name",
        ".spec.containers[*].image",
        ".status.containerStatuses[*].ready",
        ".status.containerStatuses[*].restartCount",
    )

    def test_30_column_spec_excludes_sensitive_field_paths(self):
        spec = prod_pod_columns.POD_COLUMNS_SPEC
        for forbidden in self._FORBIDDEN_DOTTED_PATHS:
            self.assertNotIn(forbidden, spec, f"column spec unexpectedly references sensitive path {forbidden!r}")
        for forbidden in self._FORBIDDEN_BARE_SUBSTRINGS:
            self.assertNotIn(forbidden, spec, f"column spec unexpectedly references {forbidden!r}")

    def test_30b_metadata_paths_present_without_triggering_false_positive(self):
        # Regression guard for the exact P10.3L false positive: the
        # legitimate, required .metadata.name/.metadata.namespace paths
        # are present, and their presence does not itself trip the
        # sensitive-path check above (which it incorrectly did before this
        # correction, via the bare substring "data").
        spec = prod_pod_columns.POD_COLUMNS_SPEC
        self.assertIn(".metadata.name", spec)
        self.assertIn(".metadata.namespace", spec)
        for forbidden in self._FORBIDDEN_DOTTED_PATHS:
            self.assertNotIn(forbidden, spec)

    def test_column_spec_contains_exactly_the_approved_safe_paths(self):
        spec = prod_pod_columns.POD_COLUMNS_SPEC
        for path in self._APPROVED_SAFE_PATHS:
            self.assertIn(path, spec, f"expected safe path {path!r} missing from column spec")

    def test_column_spec_is_a_fixed_module_constant(self):
        # Calling the parser twice with different input must never change
        # the spec - it is not caller/namespace-derived in any way.
        spec_before = prod_pod_columns.POD_COLUMNS_SPEC
        prod_pod_columns.parse_get_pods_columns(_row(namespace="some-other-namespace"))
        self.assertEqual(prod_pod_columns.POD_COLUMNS_SPEC, spec_before)

    def test_exactly_nine_columns_expected(self):
        self.assertEqual(prod_pod_columns._EXPECTED_COLUMN_COUNT, 9)

    def test_sentinel_value_in_unexpected_position_never_leaks_on_failure(self):
        raw = "SENTINEL_MARKER_99999\textra\tfields\there\tthat\tare\twrong\tcount"
        out = prod_pod_columns.parse_get_pods_columns(raw)
        self.assertNotIn("SENTINEL_MARKER_99999", out)


class OutputSchemaTests(unittest.TestCase):
    """P10.3L.1 (Task 4): proves the parser's controlled output structure
    can never carry an unknown/raw Kubernetes field - every returned
    dict's key set is checked for EXACT equality (not merely "contains"),
    so an accidentally-added field (e.g. a stray `kind`, `metadata`,
    `env`, or anything else copied in from real Kubernetes JSON) would
    fail this test immediately."""

    def test_pod_object_has_exactly_the_approved_keys_and_no_others(self):
        raw = _row(
            containers="app,sidecar",
            images="img:1,sidecar:1",
            ready="true,false",
            restarts="0,2",
        )
        data = json.loads(prod_pod_columns.parse_get_pods_columns(raw))
        pod = data["pods"][0]

        self.assertEqual(
            set(pod.keys()),
            {"name", "namespace", "phase", "pod_ip", "node", "containers", "ready", "restarts"},
        )
        for container in pod["containers"]:
            self.assertEqual(set(container.keys()), {"name", "image"})
        self.assertEqual(set(pod["ready"].keys()), {"ready_count", "total_count"})
        self.assertEqual(set(pod["restarts"].keys()), {"max"})

    def test_top_level_response_has_exactly_the_pods_key(self):
        data = json.loads(prod_pod_columns.parse_get_pods_columns(_row()))
        self.assertEqual(set(data.keys()), {"pods"})


if __name__ == "__main__":
    unittest.main()
