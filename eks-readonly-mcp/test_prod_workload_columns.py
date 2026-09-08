"""Tests for prod_workload_columns.py (P11B).

Pure unit tests against representative FAKE `kubectl get {deployments,
replicasets,statefulsets,daemonsets} -o custom-columns ... --no-headers`
text only - never real PROD output. No SSH, no kubectl, no PROD contact of
any kind; this module has no I/O at all.
"""
from __future__ import annotations

import json
import unittest

import prod_workload_columns as pwc

# --- Row builders -----------------------------------------------------

_RESOURCE_PARSERS = {
    "deployments": (pwc.parse_get_deployments_columns, True, "deployments"),
    "replicasets": (pwc.parse_get_replicasets_columns, False, "replicasets"),
    "statefulsets": (pwc.parse_get_statefulsets_columns, True, "statefulsets"),
    "daemonsets": (pwc.parse_get_daemonsets_columns, True, "daemonsets"),
}

_RESOURCE_SPECS = {
    "deployments": pwc.DEPLOYMENT_COLUMNS_SPEC,
    "replicasets": pwc.REPLICASET_COLUMNS_SPEC,
    "statefulsets": pwc.STATEFULSET_COLUMNS_SPEC,
    "daemonsets": pwc.DAEMONSET_COLUMNS_SPEC,
}


def _row(
    has_updated,
    name="checkout",
    namespace="commerce",
    desired="3",
    ready="3",
    available="3",
    updated="3",
    containers="checkout",
    images="registry.internal/checkout:1.4.2",
):
    fields = [name, namespace, desired, ready, available]
    if has_updated:
        fields.append(updated)
    fields.extend([containers, images])
    return "\t".join(fields)


def _lines(*rows):
    return "\n".join(rows)


# --- 1-4: happy path per resource --------------------------------------

class HappyPathTests(unittest.TestCase):
    def test_1_deployment_happy_path(self):
        parser, has_updated, key = _RESOURCE_PARSERS["deployments"]
        out = parser(_row(has_updated))
        data = json.loads(out)
        item = data[key][0]
        self.assertEqual(item["name"], "checkout")
        self.assertEqual(item["namespace"], "commerce")
        self.assertEqual(item["desired"], 3)
        self.assertEqual(item["ready"], 3)
        self.assertEqual(item["available"], 3)
        self.assertEqual(item["updated"], 3)
        self.assertEqual(item["containers"], [{"name": "checkout", "image": "registry.internal/checkout:1.4.2"}])

    def test_2_replicaset_happy_path(self):
        parser, has_updated, key = _RESOURCE_PARSERS["replicasets"]
        out = parser(_row(has_updated))
        data = json.loads(out)
        item = data[key][0]
        self.assertEqual(item["name"], "checkout")
        self.assertEqual(item["desired"], 3)
        self.assertEqual(item["ready"], 3)
        self.assertEqual(item["available"], 3)
        self.assertIsNone(item["updated"])

    def test_3_statefulset_happy_path(self):
        parser, has_updated, key = _RESOURCE_PARSERS["statefulsets"]
        out = parser(_row(has_updated))
        data = json.loads(out)
        item = data[key][0]
        self.assertEqual(item["desired"], 3)
        self.assertEqual(item["updated"], 3)

    def test_4_daemonset_happy_path(self):
        parser, has_updated, key = _RESOURCE_PARSERS["daemonsets"]
        out = parser(_row(has_updated, desired="5", ready="5", available="5", updated="5"))
        data = json.loads(out)
        item = data[key][0]
        self.assertEqual(item["desired"], 5)
        self.assertEqual(item["ready"], 5)
        self.assertEqual(item["available"], 5)
        self.assertEqual(item["updated"], 5)


# --- 5-7: exact key tests ------------------------------------------------

class ExactSchemaTests(unittest.TestCase):
    def test_5_exact_top_level_key(self):
        for resource, (parser, has_updated, key) in _RESOURCE_PARSERS.items():
            with self.subTest(resource=resource):
                data = json.loads(parser(_row(has_updated)))
                self.assertEqual(set(data.keys()), {key})

    def test_6_exact_item_keys(self):
        for resource, (parser, has_updated, key) in _RESOURCE_PARSERS.items():
            with self.subTest(resource=resource):
                data = json.loads(parser(_row(has_updated)))
                item = data[key][0]
                self.assertEqual(
                    set(item.keys()),
                    {"name", "namespace", "desired", "ready", "available", "updated", "containers"},
                )

    def test_7_exact_container_keys(self):
        for resource, (parser, has_updated, key) in _RESOURCE_PARSERS.items():
            with self.subTest(resource=resource):
                data = json.loads(parser(_row(has_updated)))
                for c in data[key][0]["containers"]:
                    self.assertEqual(set(c.keys()), {"name", "image"})


# --- 8-10: security static checks (path-aware, per P10.3L.1 methodology) --

class SecurityStaticTests(unittest.TestCase):
    """Uses the corrected, path-aware methodology from P10.3L.1 - never a
    naive substring check for tokens (like bare "data") that collide with
    legitimate field names such as ".metadata"."""

    _FORBIDDEN_DOTTED_PATHS = (".env", ".envFrom", ".data", ".stringData")
    _FORBIDDEN_BARE_SUBSTRINGS = (
        "secretKeyRef",
        "configMapKeyRef",
        "secretRef",
        "configMapRef",
        "serviceAccount",
        "labels",
        "annotations",
        "volumes",
        "imagePullSecrets",
        "command",
        "args",
    )

    def test_8_security_static_checks_for_every_spec(self):
        for resource, spec in _RESOURCE_SPECS.items():
            with self.subTest(resource=resource):
                for forbidden in self._FORBIDDEN_DOTTED_PATHS:
                    self.assertNotIn(forbidden, spec, f"{resource} spec references sensitive path {forbidden!r}")
                for forbidden in self._FORBIDDEN_BARE_SUBSTRINGS:
                    self.assertNotIn(forbidden, spec, f"{resource} spec references {forbidden!r}")

    def test_9_positive_pin_of_approved_paths(self):
        common_paths = (".metadata.name", ".metadata.namespace",
                        ".spec.template.spec.containers[*].name", ".spec.template.spec.containers[*].image")
        for resource, spec in _RESOURCE_SPECS.items():
            with self.subTest(resource=resource):
                for path in common_paths:
                    self.assertIn(path, spec, f"{resource} spec missing approved path {path!r}")

        self.assertIn(".spec.replicas", pwc.DEPLOYMENT_COLUMNS_SPEC)
        self.assertIn(".status.readyReplicas", pwc.DEPLOYMENT_COLUMNS_SPEC)
        self.assertIn(".status.availableReplicas", pwc.DEPLOYMENT_COLUMNS_SPEC)
        self.assertIn(".status.updatedReplicas", pwc.DEPLOYMENT_COLUMNS_SPEC)

        self.assertIn(".spec.replicas", pwc.REPLICASET_COLUMNS_SPEC)
        self.assertIn(".status.readyReplicas", pwc.REPLICASET_COLUMNS_SPEC)
        self.assertIn(".status.availableReplicas", pwc.REPLICASET_COLUMNS_SPEC)

        self.assertIn(".spec.replicas", pwc.STATEFULSET_COLUMNS_SPEC)
        self.assertIn(".status.updatedReplicas", pwc.STATEFULSET_COLUMNS_SPEC)

        self.assertIn(".status.desiredNumberScheduled", pwc.DAEMONSET_COLUMNS_SPEC)
        self.assertIn(".status.numberReady", pwc.DAEMONSET_COLUMNS_SPEC)
        self.assertIn(".status.numberAvailable", pwc.DAEMONSET_COLUMNS_SPEC)
        self.assertIn(".status.updatedNumberScheduled", pwc.DAEMONSET_COLUMNS_SPEC)

    def test_10_metadata_paths_present_without_false_positive(self):
        # Regression guard for the exact P10.3L false positive: legitimate
        # .metadata.name/.metadata.namespace are present, and their
        # presence never trips the sensitive-path check.
        for resource, spec in _RESOURCE_SPECS.items():
            with self.subTest(resource=resource):
                self.assertIn(".metadata.name", spec)
                self.assertIn(".metadata.namespace", spec)
                for forbidden in self._FORBIDDEN_DOTTED_PATHS:
                    self.assertNotIn(forbidden, spec)


# --- 11-13: multi-container behavior ------------------------------------

class MultiContainerTests(unittest.TestCase):
    def test_11_one_container(self):
        parser, has_updated, key = _RESOURCE_PARSERS["deployments"]
        data = json.loads(parser(_row(has_updated, containers="app", images="img:1")))
        self.assertEqual(data[key][0]["containers"], [{"name": "app", "image": "img:1"}])

    def test_12_multiple_containers(self):
        parser, has_updated, key = _RESOURCE_PARSERS["deployments"]
        data = json.loads(
            parser(_row(has_updated, containers="app,sidecar", images="img:1,sidecar:1"))
        )
        self.assertEqual(
            data[key][0]["containers"],
            [{"name": "app", "image": "img:1"}, {"name": "sidecar", "image": "sidecar:1"}],
        )

    def test_13_container_image_mismatch_fails_closed(self):
        for resource, (parser, has_updated, key) in _RESOURCE_PARSERS.items():
            with self.subTest(resource=resource):
                out = parser(_row(has_updated, containers="app,sidecar", images="img:1"))
                self.assertEqual(out, pwc._WITHHELD_FAIL_CLOSED)


# --- 14-19: missing required fields --------------------------------------

class MissingRequiredFieldTests(unittest.TestCase):
    def _assert_fail_closed(self, resource, **overrides):
        parser, has_updated, _key = _RESOURCE_PARSERS[resource]
        out = parser(_row(has_updated, **overrides))
        self.assertEqual(out, pwc._WITHHELD_FAIL_CLOSED)

    def test_14_missing_required_name(self):
        for resource in _RESOURCE_PARSERS:
            with self.subTest(resource=resource):
                self._assert_fail_closed(resource, name="<none>")

    def test_15_missing_required_namespace(self):
        for resource in _RESOURCE_PARSERS:
            with self.subTest(resource=resource):
                self._assert_fail_closed(resource, namespace="<none>")

    def test_16_missing_required_desired(self):
        for resource in _RESOURCE_PARSERS:
            with self.subTest(resource=resource):
                self._assert_fail_closed(resource, desired="<none>")

    def test_17_missing_required_ready(self):
        for resource in _RESOURCE_PARSERS:
            with self.subTest(resource=resource):
                self._assert_fail_closed(resource, ready="<none>")

    def test_18_missing_required_containers(self):
        for resource in _RESOURCE_PARSERS:
            with self.subTest(resource=resource):
                self._assert_fail_closed(resource, containers="<none>")

    def test_19_missing_required_images(self):
        for resource in _RESOURCE_PARSERS:
            with self.subTest(resource=resource):
                self._assert_fail_closed(resource, images="<none>")


# --- 20-21: optional <none> handling --------------------------------------

class OptionalFieldTests(unittest.TestCase):
    def test_20_none_for_optional_available(self):
        for resource, (parser, has_updated, key) in _RESOURCE_PARSERS.items():
            with self.subTest(resource=resource):
                data = json.loads(parser(_row(has_updated, available="<none>")))
                self.assertIsNone(data[key][0]["available"])
                self.assertNotIn("<none>", json.dumps(data))

    def test_21_none_for_optional_updated(self):
        for resource, (parser, has_updated, key) in _RESOURCE_PARSERS.items():
            if not has_updated:
                continue
            with self.subTest(resource=resource):
                data = json.loads(parser(_row(has_updated, updated="<none>")))
                self.assertIsNone(data[key][0]["updated"])

    def test_available_zero_is_distinct_from_none(self):
        parser, has_updated, key = _RESOURCE_PARSERS["deployments"]
        data_zero = json.loads(parser(_row(has_updated, available="0")))
        data_none = json.loads(parser(_row(has_updated, available="<none>")))
        self.assertEqual(data_zero[key][0]["available"], 0)
        self.assertIsNone(data_none[key][0]["available"])

    def test_invalid_available_value_fails_closed_not_silently_null(self):
        parser, has_updated, _key = _RESOURCE_PARSERS["deployments"]
        out = parser(_row(has_updated, available="not-a-number"))
        self.assertEqual(out, pwc._WITHHELD_FAIL_CLOSED)


# --- 22-26: malformed input ------------------------------------------------

class MalformedInputTests(unittest.TestCase):
    def test_22_invalid_integer_required(self):
        for resource in _RESOURCE_PARSERS:
            with self.subTest(resource=resource):
                parser, has_updated, _key = _RESOURCE_PARSERS[resource]
                out = parser(_row(has_updated, desired="not-a-number"))
                self.assertEqual(out, pwc._WITHHELD_FAIL_CLOSED)

    def test_23_malformed_row(self):
        for resource in _RESOURCE_PARSERS:
            with self.subTest(resource=resource):
                parser, _has_updated, _key = _RESOURCE_PARSERS[resource]
                out = parser("this is not a valid custom-columns row at all here")
                self.assertEqual(out, pwc._WITHHELD_FAIL_CLOSED)

    def test_24_short_row(self):
        for resource in _RESOURCE_PARSERS:
            with self.subTest(resource=resource):
                parser, _has_updated, _key = _RESOURCE_PARSERS[resource]
                out = parser("only\tthree\tfields")
                self.assertEqual(out, pwc._WITHHELD_FAIL_CLOSED)

    def test_25_extra_column_row(self):
        for resource in _RESOURCE_PARSERS:
            with self.subTest(resource=resource):
                parser, has_updated, _key = _RESOURCE_PARSERS[resource]
                out = parser(_row(has_updated) + "\textra-unexpected-column")
                self.assertEqual(out, pwc._WITHHELD_FAIL_CLOSED)

    def test_26_blank_line_amid_data_fails_closed(self):
        for resource in _RESOURCE_PARSERS:
            with self.subTest(resource=resource):
                parser, has_updated, _key = _RESOURCE_PARSERS[resource]
                raw = _lines(_row(has_updated, name="a"), "", _row(has_updated, name="b"))
                out = parser(raw)
                self.assertEqual(out, pwc._WITHHELD_FAIL_CLOSED)

    def test_blank_or_invalid_overall_output(self):
        for resource, (parser, _has_updated, key) in _RESOURCE_PARSERS.items():
            with self.subTest(resource=resource):
                data = json.loads(parser(""))
                self.assertEqual(data, {key: []})
                data_ws = json.loads(parser("   \n  \n"))
                self.assertEqual(data_ws, {key: []})
                data_norsrc = json.loads(parser("No resources found in commerce namespace.\n"))
                self.assertEqual(data_norsrc, {key: []})


# --- 27-29: exceptions, no fallback, no partial ---------------------------

class ParserSafetyTests(unittest.TestCase):
    def test_27_parser_exception_yields_fixed_fail_closed_output(self):
        for resource, (parser, _has_updated, _key) in _RESOURCE_PARSERS.items():
            with self.subTest(resource=resource):
                out = parser(None)  # type: ignore[arg-type]
                self.assertEqual(out, pwc._WITHHELD_FAIL_CLOSED)

    def test_28_no_raw_fallback(self):
        for resource, (parser, _has_updated, _key) in _RESOURCE_PARSERS.items():
            with self.subTest(resource=resource):
                sentinel = "TOTALLY-UNPARSEABLE-MARKER-XYZ-99999"
                out = parser(sentinel)
                self.assertNotIn(sentinel, out)

    def test_29_no_partial_result_on_failure(self):
        for resource in _RESOURCE_PARSERS:
            with self.subTest(resource=resource):
                parser, has_updated, _key = _RESOURCE_PARSERS[resource]
                raw = _lines(_row(has_updated, name="good-item"), "malformed garbage line here")
                out = parser(raw)
                self.assertEqual(out, pwc._WITHHELD_FAIL_CLOSED)
                self.assertNotIn("good-item", out)


# --- 30: namespace/scope behavior (parser independence) -------------------

class NamespaceScopeTests(unittest.TestCase):
    def test_30_parser_output_independent_of_namespace_value(self):
        for resource, (parser, has_updated, key) in _RESOURCE_PARSERS.items():
            for ns in ("commerce", "kube-system", "default"):
                with self.subTest(resource=resource, namespace=ns):
                    data = json.loads(parser(_row(has_updated, namespace=ns)))
                    self.assertEqual(data[key][0]["namespace"], ns)


# --- 31-32: resource-specific field mapping -------------------------------

class ResourceSpecificFieldTests(unittest.TestCase):
    def test_31_replicaset_never_requests_updated(self):
        self.assertNotIn("UPDATED", pwc.REPLICASET_COLUMNS_SPEC)
        self.assertEqual(pwc.REPLICASET_COLUMNS_SPEC.count(":"), 7)  # 7 columns, no UPDATED

    def test_31b_replicaset_updated_always_null(self):
        parser, has_updated, key = _RESOURCE_PARSERS["replicasets"]
        for row_kwargs in ({}, {"available": "<none>"}):
            with self.subTest(row_kwargs=row_kwargs):
                data = json.loads(parser(_row(has_updated, **row_kwargs)))
                self.assertIsNone(data[key][0]["updated"])

    def test_32_daemonset_uses_correct_status_fields(self):
        spec = pwc.DAEMONSET_COLUMNS_SPEC
        self.assertIn("DESIRED:.status.desiredNumberScheduled", spec)
        self.assertIn("READY:.status.numberReady", spec)
        self.assertIn("AVAILABLE:.status.numberAvailable", spec)
        self.assertIn("UPDATED:.status.updatedNumberScheduled", spec)
        self.assertNotIn(".spec.replicas", spec)


# --- 33: end-to-end mocked run_readonly pipeline ---------------------------

class EndToEndPipelineTests(unittest.TestCase):
    def test_33_end_to_end_via_real_run_readonly(self):
        from unittest.mock import Mock

        import readonly_exec
        from ssh_client import CommandResult

        for resource, (parser, has_updated, key) in _RESOURCE_PARSERS.items():
            with self.subTest(resource=resource):
                ssh = Mock()
                ssh.run_kubectl.return_value = CommandResult(
                    command=f"kubectl get {resource} -A -o custom-columns=... --no-headers",
                    stdout=_row(has_updated, containers="app,sidecar", images="img:1,sidecar:1"),
                    stderr="",
                    exit_code=0,
                )
                out = readonly_exec.run_readonly(
                    ssh, f"kubectl get {resource} -A -o custom-columns=... --no-headers",
                    tag="prod", sanitizer=parser,
                )
                self.assertTrue(out.startswith("[prod]\n"))
                body = out.split("\n", 1)[1]
                data = json.loads(body)
                self.assertEqual(len(data[key]), 1)


if __name__ == "__main__":
    unittest.main()
