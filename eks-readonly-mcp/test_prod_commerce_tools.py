"""Unit tests for prod_commerce_tools.py (P12A).

No real SSH connection, no real kubectl, no PROD contact of any kind.
Importing prod_commerce_tools pulls in prod_commerce_config.py, which loads
PROD_BASTION_* configuration and builds one BastionSSHClient at import time
- a throwaway temp file stands in for the PROD private key (existence-
checked only) and paramiko.SSHClient.connect is patched to raise if
anything ever tries to actually open a socket. All tool-level tests then
patch `prod_commerce_tools.run_prod_commerce_readonly` (the name as
imported into this module's own namespace) so no SSH client is ever
actually invoked.
"""
from __future__ import annotations

import importlib
import inspect
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

_MODULE_NAME = "prod_commerce_tools"

_NONE = "<none>"


def _pod_line(name, namespace, phase="Running", release=None, group=None,
              restarts=None, waiting=None, containers=("ts-app",)):
    """Build one -o custom-columns row exactly as _parse_pod_discovery_line
    expects (8 whitespace-separated fields)."""
    def tok(v):
        return v if v not in (None, "") else _NONE
    return "  ".join(
        [
            name,
            namespace,
            phase,
            tok(release),
            tok(group),
            tok(restarts),
            tok(waiting),
            ",".join(containers) if containers else _NONE,
        ]
    )


def _fake_readonly(pod_lines_by_ns=None, error_namespaces=None, malformed_namespaces=None):
    """Build a fake run_prod_commerce_readonly() replacement: routes
    `get pods -n X` to canned custom-columns rows keyed by namespace.
    Anything else errors loudly rather than silently returning nothing, so
    a test typo surfaces immediately."""
    pod_lines_by_ns = pod_lines_by_ns or {}
    error_namespaces = error_namespaces or set()
    malformed_namespaces = malformed_namespaces or set()

    def run(kubectl_command: str) -> str:
        if "get pods -n" not in kubectl_command:
            raise AssertionError(f"unexpected kubectl command in test: {kubectl_command!r}")
        ns = kubectl_command.split("-n ", 1)[1].split()[0]
        if ns in error_namespaces:
            return f"[prod-commerce] Error: could not connect to the bastion for namespace {ns}."
        if ns in malformed_namespaces:
            return "[prod-commerce]\nthis is not a valid custom-columns row at all"
        lines = pod_lines_by_ns.get(ns, [])
        if not lines:
            return "[prod-commerce]\n(empty result - no matching resources)"
        return "[prod-commerce]\n" + "\n".join(lines)

    return run


def _body(tool_result: str) -> dict:
    """Strip the leading "[prod-commerce]\\n" tag and parse the JSON body."""
    return json.loads(tool_result.split("\n", 1)[1])


class ProdCommerceToolsTestCase(unittest.TestCase):
    def setUp(self):
        self._env_patcher = patch.dict(os.environ, {}, clear=False)
        self._env_patcher.start()

        fd, self._tmp_key_path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(b"not a real private key - existence check only")
        self.addCleanup(os.unlink, self._tmp_key_path)

        os.environ.update(
            {
                "PROD_BASTION_HOST": "10.13.96.105",
                "PROD_BASTION_PORT": "22",
                "PROD_BASTION_USER": "ubuntu",
                "PROD_BASTION_KEY_PATH": self._tmp_key_path,
                "KUBERNETES_USER": "solveda",
            }
        )

        self._connect_patcher = patch(
            "paramiko.SSHClient.connect",
            side_effect=AssertionError("must never open a real SSH connection in tests"),
        )
        self._connect_patcher.start()
        self.addCleanup(self._connect_patcher.stop)

        self.pct = self._fresh_import()

    def tearDown(self):
        self._env_patcher.stop()

    def _fresh_import(self):
        saved = {
            mod: sys.modules.pop(mod, None)
            for mod in (_MODULE_NAME, "prod_commerce_config", "readonly_exec", "prod_config")
        }
        try:
            return importlib.import_module(_MODULE_NAME)
        finally:
            for mod, prior in saved.items():
                if mod not in sys.modules and prior is not None:
                    sys.modules[mod] = prior


# --------------------------------------------------------------------------
# 3/8. no environment parameter; namespace handling
# --------------------------------------------------------------------------

class NoEnvironmentParameterTests(ProdCommerceToolsTestCase):
    def test_list_components_has_no_env_parameter(self):
        params = set(inspect.signature(self.pct.list_prod_commerce_components).parameters)
        self.assertNotIn("env", params)
        self.assertNotIn("environment", params)
        self.assertEqual(params, {"namespace"})

    def test_get_health_has_no_env_parameter(self):
        params = set(inspect.signature(self.pct.get_prod_commerce_health).parameters)
        self.assertNotIn("env", params)
        self.assertNotIn("environment", params)
        self.assertEqual(params, {"namespace"})


class NamespaceHandlingTests(ProdCommerceToolsTestCase):
    def test_default_namespace_is_commerce(self):
        sig = inspect.signature(self.pct.list_prod_commerce_components)
        self.assertEqual(sig.parameters["namespace"].default, "commerce")

    def test_namespace_all_is_rejected(self):
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly()):
            result = self.pct.list_prod_commerce_components(namespace="all")
        self.assertTrue(result.startswith("Error:"))
        self.assertIn("all", result.lower())

    def test_namespace_empty_string_defaults_to_commerce_not_all(self):
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly()) as fake:
            self.pct.list_prod_commerce_components(namespace="")
        called_namespaces = {call.args[0].split("-n ", 1)[1].split()[0] for call in fake.call_args_list}
        self.assertIn("commerce", called_namespaces)
        self.assertNotIn("-A", " ".join(c.args[0] for c in fake.call_args_list))

    def test_namespace_none_defaults_to_commerce(self):
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly()) as fake:
            self.pct.list_prod_commerce_components(namespace=None)
        called_namespaces = {call.args[0].split("-n ", 1)[1].split()[0] for call in fake.call_args_list}
        self.assertIn("commerce", called_namespaces)

    def test_explicit_namespace_is_scoped_not_expanded(self):
        # nginx/redis have their own fixed namespace overrides in
        # commerce_mapping and are always additionally checked - that is
        # intentional (each is still one specific namespace), not "all
        # namespaces". The requested default namespace ("monitoring") must
        # be one of the namespaces queried, and `-A` must never appear.
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly()) as fake:
            self.pct.list_prod_commerce_components(namespace="monitoring")
        queried_commands = [call.args[0] for call in fake.call_args_list]
        self.assertTrue(any("-n monitoring" in cmd for cmd in queried_commands))
        for cmd in queried_commands:
            self.assertNotIn("-A", cmd)

    def test_invalid_namespace_syntax_rejected(self):
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly()):
            result = self.pct.list_prod_commerce_components(namespace="Not_Valid!!")
        self.assertTrue(result.startswith("Error:"))


# --------------------------------------------------------------------------
# 9/10/11. expected components, optional components, unknown component
# --------------------------------------------------------------------------

class ComponentCoverageTests(ProdCommerceToolsTestCase):
    def test_all_expected_components_reported(self):
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly()):
            result = self.pct.list_prod_commerce_components()
        body = _body(result)
        expected = {
            "ts-app", "crs-app", "ts-web", "store-web", "cache-app",
            "tooling-web", "search-app", "search-app-repeater", "search-app-slave",
            "nginx", "redis", "wcbd", "utils",
        }
        self.assertEqual(set(body["components"].keys()), expected)

    def test_known_optional_component_reports_not_deployed_when_absent(self):
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly()):
            result = self.pct.list_prod_commerce_components()
        body = _body(result)
        self.assertEqual(body["components"]["wcbd"]["status"], "not_deployed")
        self.assertEqual(body["components"]["utils"]["status"], "not_deployed")
        self.assertEqual(body["components"]["tooling-web"]["status"], "not_deployed")

    def test_required_component_reports_no_matching_pods_when_absent(self):
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly()):
            result = self.pct.list_prod_commerce_components()
        body = _body(result)
        self.assertEqual(body["components"]["ts-app"]["status"], "no_matching_pods")

    def test_unknown_component_is_not_reachable_via_public_tool_surface(self):
        # Neither tool accepts a `component` argument at all, so there is no
        # user-supplied component name to mis-resolve or silently guess -
        # both tools always enumerate the fixed, known ALL_COMPONENTS set.
        self.assertNotIn("component", inspect.signature(self.pct.list_prod_commerce_components).parameters)
        self.assertNotIn("component", inspect.signature(self.pct.get_prod_commerce_health).parameters)

    def test_commerce_mapping_itself_never_silently_guesses_unknown_component(self):
        import commerce_mapping
        with self.assertRaises(ValueError):
            commerce_mapping.normalize_component("totally-unknown-component")


# --------------------------------------------------------------------------
# 12/13. controlled output schema, sensitive-field exclusion
# --------------------------------------------------------------------------

class OutputSchemaTests(ProdCommerceToolsTestCase):
    def test_list_components_top_level_shape(self):
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly()):
            result = self.pct.list_prod_commerce_components()
        body = _body(result)
        self.assertEqual(set(body.keys()), {"namespaces_checked", "fetch_errors", "components"})

    def test_health_top_level_shape(self):
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly()):
            result = self.pct.get_prod_commerce_health()
        body = _body(result)
        self.assertEqual(set(body.keys()), {"namespaces_checked", "fetch_errors", "components"})
        for comp_body in body["components"].values():
            self.assertEqual(set(comp_body.keys()), {"status", "release", "release_group", "pod_status"})
            self.assertEqual(
                set(comp_body["pod_status"].keys()),
                {"total", "phase_counts", "crash_looping", "image_pull_backoff", "pods_with_restarts"},
            )

    def test_column_spec_never_requests_sensitive_fields(self):
        spec = self.pct._POD_DISCOVERY_COLUMNS_SPEC
        # "data" is deliberately excluded from this list: it is a substring
        # of the legitimate, required ".metadata.*" jsonpath segments, so a
        # bare "data" check would false-positive on every column spec that
        # references metadata at all. "stringData" (the actual Secret
        # field of concern) has no such collision and is checked directly.
        for forbidden in (
            "env", "envFrom", "stringData", "secretKeyRef", "configMapKeyRef",
            "secretRef", "configMapRef", "serviceAccount", "annotations", "volumes",
            "imagePullSecrets", "command", "args", "image",
        ):
            self.assertNotIn(forbidden, spec)
        # Only these two label keys are ever requested - nothing broader.
        self.assertIn("labels.release", spec)
        self.assertIn("labels.group", spec)
        self.assertNotIn("metadata.labels]", spec)

    def test_output_never_contains_raw_pod_object_keys(self):
        pods = {"commerce": [_pod_line("obliveap-ts-app-a", "commerce", release="ob-live",
                                        group="oblive", restarts="0", containers=("ts-app",))]}
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly(pods)):
            result = self.pct.list_prod_commerce_components()
        for forbidden in ("envFrom", "secretKeyRef", "configMapKeyRef", "imagePullSecrets",
                           "apiVersion", "\"kind\"", "spec\":", "annotations"):
            self.assertNotIn(forbidden, result)


# --------------------------------------------------------------------------
# P12A.1: exact custom-columns field allow-list (structured parsing, not
# substring matching - a substring check cannot distinguish
# ".metadata.labels.release" (approved) from ".metadata.labels" or
# ".metadata.labels[*]" (forbidden wildcards), since the former contains
# the latter as a literal substring).
# --------------------------------------------------------------------------

_APPROVED_JSONPATHS = {
    ".metadata.name",
    ".metadata.namespace",
    ".status.phase",
    ".metadata.labels.release",
    ".metadata.labels.group",
    ".status.containerStatuses[*].restartCount",
    ".status.containerStatuses[*].state.waiting.reason",
    ".spec.containers[*].name",
}


def _parse_custom_columns_spec(spec: str) -> dict[str, str]:
    """Parse a `-o custom-columns=NAME:.path,NAME2:.path2,...` spec string
    into {column_name: jsonpath}. Splitting on "," is exact here (not a
    heuristic) because none of this module's approved jsonpaths contain a
    comma themselves."""
    pairs = {}
    for entry in spec.split(","):
        name, path = entry.split(":", 1)
        pairs[name] = path
    return pairs


class ExactFieldAllowlistTests(ProdCommerceToolsTestCase):
    def test_column_spec_jsonpaths_exactly_match_approved_allowlist(self):
        # Proves the COMPLETE set: no approved field missing, and no
        # additional/wildcard/forbidden field present - a set equality
        # check, not a "does it contain X" substring scan.
        columns = _parse_custom_columns_spec(self.pct._POD_DISCOVERY_COLUMNS_SPEC)
        self.assertEqual(set(columns.values()), _APPROVED_JSONPATHS)

    def test_release_label_is_the_exact_approved_path(self):
        columns = _parse_custom_columns_spec(self.pct._POD_DISCOVERY_COLUMNS_SPEC)
        self.assertEqual(columns["RELEASE"], ".metadata.labels.release")

    def test_group_label_is_the_exact_approved_path(self):
        columns = _parse_custom_columns_spec(self.pct._POD_DISCOVERY_COLUMNS_SPEC)
        self.assertEqual(columns["GROUP"], ".metadata.labels.group")

    def test_no_wildcard_or_bare_labels_path_present(self):
        columns = _parse_custom_columns_spec(self.pct._POD_DISCOVERY_COLUMNS_SPEC)
        paths = set(columns.values())
        # A bare `.metadata.labels` (all labels as one blob) or a
        # `.metadata.labels[*]` wildcard would each be a DIFFERENT string
        # from the two approved exact-key paths - assert neither is present,
        # and that no path is merely ".metadata.labels" as a prefix used
        # any way other than the two approved exact suffixes.
        self.assertNotIn(".metadata.labels", paths)
        self.assertNotIn(".metadata.labels[*]", paths)
        label_paths = {p for p in paths if p.startswith(".metadata.labels")}
        self.assertEqual(label_paths, {".metadata.labels.release", ".metadata.labels.group"})

    def test_no_annotations_path_present(self):
        columns = _parse_custom_columns_spec(self.pct._POD_DISCOVERY_COLUMNS_SPEC)
        for path in columns.values():
            self.assertNotIn("annotations", path)

    def test_no_env_or_secret_or_configmap_reference_path_present(self):
        columns = _parse_custom_columns_spec(self.pct._POD_DISCOVERY_COLUMNS_SPEC)
        for path in columns.values():
            for forbidden in ("env", "envFrom", "secretKeyRef", "configMapKeyRef",
                               "secretRef", "configMapRef", "serviceAccount", "stringData"):
                self.assertNotIn(forbidden, path)

    def test_no_volumes_or_image_pull_secrets_path_present(self):
        columns = _parse_custom_columns_spec(self.pct._POD_DISCOVERY_COLUMNS_SPEC)
        for path in columns.values():
            self.assertNotIn("volumes", path)
            self.assertNotIn("imagePullSecrets", path)

    def test_no_command_args_or_image_path_present(self):
        columns = _parse_custom_columns_spec(self.pct._POD_DISCOVERY_COLUMNS_SPEC)
        for path in columns.values():
            self.assertNotIn("command", path)
            self.assertNotIn("args", path)
            self.assertNotIn("image", path)  # container images are not requested

    def test_no_conditions_or_arbitrary_status_path_present(self):
        columns = _parse_custom_columns_spec(self.pct._POD_DISCOVERY_COLUMNS_SPEC)
        for path in columns.values():
            self.assertNotIn("conditions", path)

    def test_column_count_matches_approved_field_count(self):
        columns = _parse_custom_columns_spec(self.pct._POD_DISCOVERY_COLUMNS_SPEC)
        self.assertEqual(len(columns), 8)
        self.assertEqual(len(columns), len(_APPROVED_JSONPATHS))


class ReleaseGroupProvenanceTests(ProdCommerceToolsTestCase):
    """Prove release/release_group in output come ONLY from the two
    approved label paths, and that a missing label is represented safely
    as None - never guessed, never leaking an arbitrary label instead."""

    def test_release_and_group_present_when_labels_present(self):
        line = _pod_line("pod-a", "commerce", release="ob-live", group="oblive",
                          restarts="0", containers=("ts-app",))
        item = self.pct._parse_pod_discovery_line(line)
        self.assertEqual(item["metadata"]["labels"], {"release": "ob-live", "group": "oblive"})

    def test_missing_release_and_group_yield_no_label_keys_at_all(self):
        line = _pod_line("pod-a", "commerce", release=None, group=None,
                          restarts="0", containers=("ts-app",))
        item = self.pct._parse_pod_discovery_line(line)
        self.assertEqual(item["metadata"]["labels"], {})

    def test_missing_labels_surface_as_none_in_matched_pod_output(self):
        pods = {"commerce": [_pod_line("pod-a", "commerce", release=None, group=None,
                                        restarts="0", containers=("ts-app",))]}
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly(pods)):
            result = self.pct.list_prod_commerce_components()
        body = _body(result)
        matched = body["components"]["ts-app"]["roles"][0]["matched_pods"][0]
        self.assertIsNone(matched["release"])
        self.assertIsNone(matched["release_group"])

    def test_matched_pod_entry_has_exactly_the_documented_keys(self):
        # No arbitrary label/annotation field can appear alongside the
        # documented ones - the key set is exact, not "at least these".
        pods = {"commerce": [_pod_line("pod-a", "commerce", release="ob-live", group="oblive",
                                        restarts="0", containers=("ts-app",))]}
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly(pods)):
            result = self.pct.list_prod_commerce_components()
        body = _body(result)
        matched = body["components"]["ts-app"]["roles"][0]["matched_pods"][0]
        self.assertEqual(
            set(matched.keys()),
            {"pod", "container", "release", "release_group", "phase", "restart_count", "waiting_reason", "state"},
        )


# --------------------------------------------------------------------------
# 14/15/16/17. malformed input/output, fail-closed, parser exceptions, no raw fallback
# --------------------------------------------------------------------------

class FailClosedTests(ProdCommerceToolsTestCase):
    def test_malformed_pod_row_withholds_that_namespace_not_partial_junk(self):
        self.assertIsNone(self.pct._parse_pod_discovery("this row has way too few fields"))

    def test_malformed_row_recorded_as_fetch_error_not_silently_empty(self):
        with patch.object(
            self.pct, "run_prod_commerce_readonly",
            side_effect=_fake_readonly(malformed_namespaces={"commerce"}),
        ):
            result = self.pct.list_prod_commerce_components()
        body = _body(result)
        self.assertTrue(any("could not be safely parsed" in e for e in body["fetch_errors"]))

    def test_bastion_error_recorded_as_fetch_error(self):
        with patch.object(
            self.pct, "run_prod_commerce_readonly",
            side_effect=_fake_readonly(error_namespaces={"commerce"}),
        ):
            result = self.pct.list_prod_commerce_components()
        body = _body(result)
        self.assertTrue(any("could not connect" in e for e in body["fetch_errors"]))

    def test_unparseable_restart_count_fails_closed_not_defaulted(self):
        line = "pod1  commerce  Running  <none>  <none>  not-an-int  <none>  ts-app"
        self.assertIsNone(self.pct._parse_pod_discovery_line(line))

    def test_empty_containers_fails_closed(self):
        line = "pod1  commerce  Running  <none>  <none>  0  <none>  <none>"
        self.assertIsNone(self.pct._parse_pod_discovery_line(line))

    def test_wrong_column_count_fails_closed(self):
        self.assertIsNone(self.pct._parse_pod_discovery_line("only two fields"))

    def test_blank_line_amid_output_fails_closed(self):
        raw = "pod1  commerce  Running  <none>  <none>  0  <none>  ts-app\n\npod2  commerce  Running  <none>  <none>  0  <none>  ts-app"
        self.assertIsNone(self.pct._parse_pod_discovery(raw))

    def test_unexpected_internal_exception_returns_withheld_not_raw(self):
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=RuntimeError("boom")):
            result = self.pct.list_prod_commerce_components()
        self.assertIn("[prod-commerce]", result)
        body = _body(result)
        self.assertEqual(body, {"error": "PROD Commerce data could not be safely parsed and was withheld before being returned."})

    def test_no_raw_kubectl_output_ever_returned_on_failure(self):
        raw_error_text = "SOME_RAW_UNEXPECTED_KUBECTL_STDERR_TEXT"
        with patch.object(self.pct, "run_prod_commerce_readonly",
                           side_effect=RuntimeError(raw_error_text)):
            result = self.pct.list_prod_commerce_components()
        self.assertNotIn(raw_error_text, result)


# --------------------------------------------------------------------------
# 18. end-to-end mocked tool path
# --------------------------------------------------------------------------

class EndToEndMockedPathTests(ProdCommerceToolsTestCase):
    def test_healthy_component_end_to_end(self):
        pods = {
            "commerce": [
                _pod_line("obliveapts-app-a", "commerce", release="ob-live", group="oblive",
                          restarts="0", containers=("ts-app",)),
            ],
            "nginx": [], "redis": [],
        }
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly(pods)):
            components_result = self.pct.list_prod_commerce_components()
            health_result = self.pct.get_prod_commerce_health()

        components_body = _body(components_result)
        role = components_body["components"]["ts-app"]["roles"][0]
        self.assertEqual(role["matched_pods"][0]["release"], "ob-live")
        self.assertEqual(role["matched_pods"][0]["state"], "running_stable")

        health_body = _body(health_result)
        self.assertEqual(health_body["components"]["ts-app"]["status"], "healthy")
        self.assertEqual(health_body["components"]["ts-app"]["release"], "ob-live")

    def test_crash_looping_component_reports_attention_needed(self):
        pods = {
            "commerce": [
                _pod_line("obliveapcrs-app-a", "commerce", release="ob-live", group="oblive",
                          restarts="5", waiting="CrashLoopBackOff", containers=("crs-app",)),
            ],
            "nginx": [], "redis": [],
        }
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly(pods)):
            result = self.pct.get_prod_commerce_health()
        body = _body(result)
        self.assertEqual(body["components"]["crs-app"]["status"], "attention_needed")
        self.assertEqual(body["components"]["crs-app"]["pod_status"]["crash_looping"], 1)

    def test_nginx_and_redis_namespace_overrides_are_checked(self):
        pods = {
            "commerce": [],
            "nginx": [_pod_line("dev-nginx-nginx-ingress-a", "nginx", containers=("dev-nginx-nginx-ingress",))],
            "redis": [_pod_line("redis-a", "redis", containers=("redis",))],
        }
        with patch.object(self.pct, "run_prod_commerce_readonly", side_effect=_fake_readonly(pods)) as fake:
            result = self.pct.list_prod_commerce_components()
        body = _body(result)
        self.assertEqual(set(body["namespaces_checked"]), {"commerce", "nginx", "redis"})
        self.assertEqual(body["components"]["nginx"]["status"], "found")
        self.assertEqual(body["components"]["redis"]["status"], "found")
        queried = {c.args[0].split("-n ", 1)[1].split()[0] for c in fake.call_args_list}
        self.assertEqual(queried, {"commerce", "nginx", "redis"})


if __name__ == "__main__":
    unittest.main()
