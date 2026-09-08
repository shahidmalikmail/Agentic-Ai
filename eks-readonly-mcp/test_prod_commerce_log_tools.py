"""Unit tests for prod_commerce_log_tools.py (P12B).

No real SSH connection, no real kubectl, no PROD contact of any kind.
Importing prod_commerce_log_tools pulls in prod_commerce_config.py (via
prod_commerce_tools), which loads PROD_BASTION_* configuration and builds
one BastionSSHClient at import time - a throwaway temp file stands in for
the PROD private key (existence-checked only) and paramiko.SSHClient.connect
is patched to raise if anything ever tries to actually open a socket.

Two module-global references to run_prod_commerce_readonly exist and must
BOTH be patched for a fully mocked call: prod_commerce_tools's own copy
(used internally by the reused _fetch_pods pod-discovery helper) and
prod_commerce_log_tools's own copy (used by this module's log-fetching
code) - each `from x import y` creates an independent local binding.
"""
from __future__ import annotations

import importlib
import inspect
import json
import os
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

_MODULE_NAME = "prod_commerce_log_tools"


def _pod_line(name, namespace, phase="Running", release=None, group=None,
              restarts=None, waiting=None, containers=("ts-app",)):
    def tok(v):
        return v if v not in (None, "") else "<none>"
    return "  ".join([
        name, namespace, phase, tok(release), tok(group), tok(restarts), tok(waiting),
        ",".join(containers) if containers else "<none>",
    ])


_LIBERTY_EXCEPTION_LOG = (
    "[9/8/26 10:00:00:123 UTC] 00000021 SystemErr     R "
    "com.ibm.commerce.foo.BarException: connection pool exhausted\n"
    "\tat com.ibm.commerce.foo.Bar.doThing(Bar.java:42)\n"
    "\tat com.ibm.commerce.foo.Baz.run(Baz.java:10)\n"
)

_ISO_TIMESTAMPED_LOG = (
    "2026-09-08T10:00:00.123Z ERROR com.ibm.commerce.foo.BarException: connection pool exhausted\n"
    "\tat com.ibm.commerce.foo.Bar.doThing(Bar.java:42)\n"
    "2026-09-08T10:05:00.456Z ERROR com.ibm.commerce.foo.BarException: connection pool exhausted\n"
    "\tat com.ibm.commerce.foo.Bar.doThing(Bar.java:42)\n"
)

_CREDENTIAL_BEARING_LOG = (
    "2026-09-08T10:00:00Z ERROR authentication failed: password=hunter2SuperSecret\n"
)


def _fake_readonly(pod_lines_by_ns=None, logs_by_pod=None, error_pods=None, previous_unavailable_pods=None):
    pod_lines_by_ns = pod_lines_by_ns or {}
    logs_by_pod = logs_by_pod or {}
    error_pods = error_pods or set()
    previous_unavailable_pods = previous_unavailable_pods or set()

    def run(cmd: str) -> str:
        if "get pods -n" in cmd:
            ns = cmd.split("-n ", 1)[1].split()[0]
            lines = pod_lines_by_ns.get(ns, [])
            if not lines:
                return "[prod-commerce]\n(empty result - no matching resources)"
            return "[prod-commerce]\n" + "\n".join(lines)
        if "kubectl logs" in cmd:
            pod_name = cmd.split("kubectl logs ", 1)[1].split()[0]
            is_previous = "--previous" in cmd
            if is_previous and pod_name in previous_unavailable_pods:
                return "[prod-commerce] Error: kubectl failed (exit 1): previous terminated container not found"
            if pod_name in error_pods:
                return "[prod-commerce] Error: could not connect to the bastion."
            text = logs_by_pod.get((pod_name, is_previous), "")
            return "[prod-commerce]\n" + text
        raise AssertionError(f"unexpected kubectl command in test: {cmd!r}")

    return run


def _body(tool_result: str) -> dict:
    return json.loads(tool_result.split("\n", 1)[1])


class ProdCommerceLogToolsTestCase(unittest.TestCase):
    def setUp(self):
        self._env_patcher = patch.dict(os.environ, {}, clear=False)
        self._env_patcher.start()

        fd, self._tmp_key_path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(b"not a real private key - existence check only")
        self.addCleanup(os.unlink, self._tmp_key_path)

        os.environ.update({
            "PROD_BASTION_HOST": "10.13.96.105",
            "PROD_BASTION_PORT": "22",
            "PROD_BASTION_USER": "ubuntu",
            "PROD_BASTION_KEY_PATH": self._tmp_key_path,
            "KUBERNETES_USER": "solveda",
        })

        self._connect_patcher = patch(
            "paramiko.SSHClient.connect",
            side_effect=AssertionError("must never open a real SSH connection in tests"),
        )
        self._connect_patcher.start()
        self.addCleanup(self._connect_patcher.stop)

        self.plt = self._fresh_import()
        import prod_commerce_tools as pct
        self.pct = pct

    def tearDown(self):
        self._env_patcher.stop()

    def _fresh_import(self):
        saved = {
            mod: sys.modules.pop(mod, None)
            for mod in (_MODULE_NAME, "prod_commerce_tools", "prod_commerce_config", "readonly_exec", "prod_config")
        }
        try:
            return importlib.import_module(_MODULE_NAME)
        finally:
            for mod, prior in saved.items():
                if mod not in sys.modules and prior is not None:
                    sys.modules[mod] = prior

    def _mock_both(self, fake_fn):
        """Patch BOTH module-global bindings of run_prod_commerce_readonly
        (see module docstring)."""
        return (
            patch.object(self.pct, "run_prod_commerce_readonly", side_effect=fake_fn),
            patch.object(self.plt, "run_prod_commerce_readonly", side_effect=fake_fn),
        )


# --------------------------------------------------------------------------
# Input contract: no env, no pod, no since, no arbitrary command
# --------------------------------------------------------------------------

class InputContractTests(ProdCommerceLogToolsTestCase):
    def test_no_env_or_environment_parameter(self):
        params = set(inspect.signature(self.plt.get_prod_commerce_logs).parameters)
        self.assertNotIn("env", params)
        self.assertNotIn("environment", params)

    def test_no_pod_parameter(self):
        params = set(inspect.signature(self.plt.get_prod_commerce_logs).parameters)
        self.assertNotIn("pod", params)

    def test_no_since_parameter(self):
        params = set(inspect.signature(self.plt.get_prod_commerce_logs).parameters)
        self.assertNotIn("since", params)

    def test_no_arbitrary_command_parameter(self):
        params = set(inspect.signature(self.plt.get_prod_commerce_logs).parameters)
        self.assertEqual(params, {"component", "namespace", "container", "tail_lines", "previous"})

    def test_calling_with_env_kwarg_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.plt.get_prod_commerce_logs(component="ts-app", env="dev")

    def test_calling_with_pod_kwarg_raises_type_error(self):
        with self.assertRaises(TypeError):
            self.plt.get_prod_commerce_logs(component="ts-app", pod="some-pod")

    def test_defaults(self):
        sig = inspect.signature(self.plt.get_prod_commerce_logs)
        self.assertEqual(sig.parameters["namespace"].default, "commerce")
        self.assertIsNone(sig.parameters["container"].default)
        self.assertEqual(sig.parameters["tail_lines"].default, 50)
        self.assertEqual(sig.parameters["previous"].default, False)


class NamespaceHandlingTests(ProdCommerceLogToolsTestCase):
    def test_namespace_all_rejected(self):
        p1, p2 = self._mock_both(_fake_readonly())
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="ts-app", namespace="all")
        self.assertTrue(result.startswith("Error:"))

    def test_namespace_empty_defaults_to_commerce(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods))
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="ts-app", namespace="")
        body = _body(result)
        self.assertEqual(body["namespace"], "commerce")

    def test_namespace_never_expands_to_all(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        issued_commands: list[str] = []

        def capturing_fake(cmd: str) -> str:
            issued_commands.append(cmd)
            return _fake_readonly(pod_lines_by_ns=pods)(cmd)

        p1, p2 = self._mock_both(capturing_fake)
        with p1, p2:
            self.plt.get_prod_commerce_logs(component="ts-app")
        self.assertTrue(issued_commands)
        for cmd in issued_commands:
            self.assertNotIn("-A", cmd.split())


class TailLinesClampingTests(ProdCommerceLogToolsTestCase):
    def test_default_tail(self):
        self.assertEqual(self.plt._validate_tail_lines(None), 50)

    def test_negative_clamped_to_minimum(self):
        self.assertEqual(self.plt._validate_tail_lines(-5), 1)

    def test_over_max_clamped_to_200(self):
        self.assertEqual(self.plt._validate_tail_lines(99999), 200)

    def test_non_integer_falls_back_to_default(self):
        self.assertEqual(self.plt._validate_tail_lines("not-a-number"), 50)

    def test_valid_value_passthrough(self):
        self.assertEqual(self.plt._validate_tail_lines(75), 75)


class ContainerValidationTests(ProdCommerceLogToolsTestCase):
    def test_none_container_allowed(self):
        self.assertIsNone(self.plt._validate_container_for_component(["ts-app"], None))

    def test_valid_exact_container_allowed(self):
        self.assertEqual(self.plt._validate_container_for_component(["ts-app"], "ts-app"), "ts-app")

    def test_valid_pattern_container_allowed(self):
        # nginx uses a container_patterns fallback, not an exact name.
        self.assertEqual(
            self.plt._validate_container_for_component(["nginx"], "dev-nginx-nginx-ingress"), "dev-nginx-nginx-ingress"
        )

    def test_arbitrary_container_rejected(self):
        with self.assertRaises(self.plt.ProdCommerceContainerError):
            self.plt._validate_container_for_component(["ts-app"], "totally-unrelated-container")

    def test_container_from_wrong_component_rejected(self):
        with self.assertRaises(self.plt.ProdCommerceContainerError):
            self.plt._validate_container_for_component(["ts-app"], "redis")


class ComponentResolutionTests(ProdCommerceLogToolsTestCase):
    def test_unknown_component_rejected(self):
        result = self.plt.get_prod_commerce_logs(component="totally-unknown-component")
        self.assertTrue(result.startswith("Error:"))

    def test_role_group_expands_and_caps_at_3_pods(self):
        pods = {
            "commerce": [
                _pod_line("obliveapsearch-app-repeater-a", "commerce", containers=("search-app-repeater",)),
                _pod_line("obliveapsearch-app-repeater-b", "commerce", containers=("search-app-repeater",)),
                _pod_line("obliveapsearch-app-slave-a", "commerce", containers=("search-app-slave",)),
                _pod_line("obliveapsearch-app-slave-b", "commerce", containers=("search-app-slave",)),
            ],
        }
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods))
        with p1, p2:
            pods_resolved, _errs = self.plt._resolve_pods_for_logs("search-app", "commerce")
        self.assertLessEqual(len(pods_resolved), 3)


# --------------------------------------------------------------------------
# Security: never a raw log line/body anywhere in the output
# --------------------------------------------------------------------------

class NoRawLogLeakTests(ProdCommerceLogToolsTestCase):
    def test_credential_bearing_log_never_leaks_the_credential(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        logs = {("obliveapts-app-a", False): _CREDENTIAL_BEARING_LOG}
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs))
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="ts-app")
        self.assertNotIn("hunter2SuperSecret", result)
        self.assertNotIn("password=", result)

    def test_raw_stack_frame_line_never_appears(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        logs = {("obliveapts-app-a", False): _ISO_TIMESTAMPED_LOG}
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs))
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="ts-app")
        self.assertNotIn("Bar.java:42", result)
        self.assertNotIn("\tat com.ibm.commerce.foo.Bar.doThing", result)

    def test_exact_output_schema_top_level(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        logs = {("obliveapts-app-a", False): _ISO_TIMESTAMPED_LOG}
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs))
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="ts-app")
        body = _body(result)
        self.assertEqual(set(body.keys()), self.plt._TOP_LEVEL_KEYS)
        self.assertEqual(set(body["log_coverage"].keys()), self.plt._COVERAGE_KEYS)
        for record in body["evidence"]:
            self.assertEqual(set(record.keys()), self.plt._EVIDENCE_KEYS)
        for err in body["fetch_errors"]:
            self.assertEqual(set(err.keys()), self.plt._FETCH_ERROR_KEYS)
            self.assertIn(err["category"], self.plt._FETCH_ERROR_CATEGORIES)

    def test_no_forbidden_field_names_anywhere_structurally(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        logs = {("obliveapts-app-a", False): _ISO_TIMESTAMPED_LOG}
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs))
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="ts-app")
        body = _body(result)

        def walk_keys(obj):
            found = set()
            if isinstance(obj, dict):
                for k, v in obj.items():
                    found.add(k)
                    found |= walk_keys(v)
            elif isinstance(obj, list):
                for item in obj:
                    found |= walk_keys(item)
            return found

        all_keys = walk_keys(body)
        forbidden_exact = {
            "env", "envFrom", "data", "stringData", "secretKeyRef", "configMapKeyRef",
            "secretRef", "configMapRef", "serviceAccount", "labels", "annotations",
            "volumes", "imagePullSecrets", "command", "args", "image", "conditions",
            "events", "metadata", "spec", "status",
        }
        # Exact-key-set comparison, never substring - see P12A.2 for why
        # substring checks against key names produce false positives.
        self.assertEqual(all_keys & forbidden_exact, set())

    def test_stack_trace_lines_represented_only_as_frame_count(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        logs = {("obliveapts-app-a", False): _ISO_TIMESTAMPED_LOG}
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs))
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="ts-app")
        body = _body(result)
        stack_records = [r for r in body["evidence"] if r["category"] == "stack_trace"]
        self.assertTrue(stack_records)
        for r in stack_records:
            self.assertIsInstance(r["frame_count"], int)
            self.assertGreater(r["frame_count"], 0)
            self.assertNotIn("at com.ibm", r["normalized_message"] or "")


# --------------------------------------------------------------------------
# Multi-line / aggregation behavior
# --------------------------------------------------------------------------

class MultilineAggregationTests(ProdCommerceLogToolsTestCase):
    def test_liberty_timestamped_exception_produces_exception_class(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        logs = {("obliveapts-app-a", False): _LIBERTY_EXCEPTION_LOG}
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs))
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="ts-app")
        body = _body(result)
        exc_records = [r for r in body["evidence"] if r["exception_class"]]
        self.assertTrue(any("BarException" in (r["exception_class"] or "") for r in exc_records))

    def test_repeated_identical_trace_deduplicated_with_occurrence_count(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        logs = {("obliveapts-app-a", False): _ISO_TIMESTAMPED_LOG}
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs))
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="ts-app")
        body = _body(result)
        exc_records = [r for r in body["evidence"] if r["category"] == "database_error"]
        self.assertEqual(len(exc_records), 1)
        self.assertEqual(exc_records[0]["occurrence_count"], 2)

    def test_first_and_last_seen_populated_when_timestamps_known(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        logs = {("obliveapts-app-a", False): _ISO_TIMESTAMPED_LOG}
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs))
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="ts-app")
        body = _body(result)
        exc_records = [r for r in body["evidence"] if r["category"] == "database_error"]
        self.assertTrue(exc_records[0]["timestamp_known"])
        self.assertIsNotNone(exc_records[0]["first_seen"])
        self.assertIsNotNone(exc_records[0]["last_seen"])

    def test_deterministic_fingerprint_across_two_identical_calls(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        logs = {("obliveapts-app-a", False): _ISO_TIMESTAMPED_LOG}
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs))
        with p1, p2:
            r1 = _body(self.plt.get_prod_commerce_logs(component="ts-app"))
        p1b, p2b = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs))
        with p1b, p2b:
            r2 = _body(self.plt.get_prod_commerce_logs(component="ts-app"))
        fp1 = next(r["stack_fingerprint"] for r in r1["evidence"] if r["category"] == "database_error")
        fp2 = next(r["stack_fingerprint"] for r in r2["evidence"] if r["category"] == "database_error")
        self.assertEqual(fp1, fp2)

    def test_no_timestamp_present_yields_timestamp_known_false(self):
        pods = {"commerce": [_pod_line("obliveapredis-a", "redis", containers=("redis",))], "redis": [
            _pod_line("obliveapredis-a", "redis", containers=("redis",))
        ]}
        logs = {("obliveapredis-a", False): "some ERROR line with no timestamp at all\n"}
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs))
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="redis")
        body = _body(result)
        for r in body["evidence"]:
            if not r["timestamp_known"]:
                self.assertIsNone(r["first_seen"])
                self.assertIsNone(r["last_seen"])


class CommandShapeTests(ProdCommerceLogToolsTestCase):
    """Every kubectl command this tool issues must match exactly one fixed
    shape - no pipe, redirect, semicolon, or extra clause of any kind."""

    _ALLOWED_LOG_COMMAND = re.compile(
        r"^kubectl logs [a-z0-9.-]+ -n [a-z0-9-]+ --tail=\d+( -c [A-Za-z0-9._-]+)?( --previous)?$"
    )

    def test_every_issued_log_command_matches_the_fixed_shape(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        logs = {("obliveapts-app-a", False): _ISO_TIMESTAMPED_LOG}
        issued: list[str] = []

        def capturing_fake(cmd: str) -> str:
            issued.append(cmd)
            return _fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs)(cmd)

        p1, p2 = self._mock_both(capturing_fake)
        with p1, p2:
            self.plt.get_prod_commerce_logs(component="ts-app", container="ts-app")

        log_commands = [c for c in issued if c.startswith("kubectl logs")]
        self.assertTrue(log_commands)
        for cmd in log_commands:
            self.assertRegex(cmd, self._ALLOWED_LOG_COMMAND)
            for forbidden in ("|", ";", "&&", ">", "<", "`", "$("):
                self.assertNotIn(forbidden, cmd)


# --------------------------------------------------------------------------
# Previous logs
# --------------------------------------------------------------------------

class PreviousLogsTests(ProdCommerceLogToolsTestCase):
    def test_previous_true_uses_previous_log_source(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        logs = {("obliveapts-app-a", True): _ISO_TIMESTAMPED_LOG}
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs))
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="ts-app", previous=True)
        body = _body(result)
        self.assertTrue(body["evidence"])
        for r in body["evidence"]:
            self.assertEqual(r["log_source"], "previous")

    def test_previous_unavailable_reported_as_controlled_fetch_error(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        p1, p2 = self._mock_both(_fake_readonly(
            pod_lines_by_ns=pods, previous_unavailable_pods={"obliveapts-app-a"}
        ))
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="ts-app", previous=True)
        body = _body(result)
        self.assertTrue(any(e["category"] == "previous_logs_unavailable" for e in body["fetch_errors"]))
        # Never silently substituted with current logs instead.
        self.assertEqual(body["evidence"], [])

    def test_previous_unavailable_never_exposes_raw_kubectl_stderr(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        p1, p2 = self._mock_both(_fake_readonly(
            pod_lines_by_ns=pods, previous_unavailable_pods={"obliveapts-app-a"}
        ))
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="ts-app", previous=True)
        self.assertNotIn("terminated container not found", result)


# --------------------------------------------------------------------------
# Fail-closed behavior
# --------------------------------------------------------------------------

class FailClosedTests(ProdCommerceLogToolsTestCase):
    def test_log_fetch_error_recorded_not_raised(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, error_pods={"obliveapts-app-a"}))
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="ts-app")
        body = _body(result)
        self.assertTrue(any(e["category"] == "log_fetch_failed" for e in body["fetch_errors"]))
        self.assertEqual(body["evidence"], [])

    def test_pod_discovery_failure_recorded_as_controlled_category(self):
        def raiser(cmd):
            if "get pods -n" in cmd:
                return "[prod-commerce] Error: could not connect to the bastion."
            raise AssertionError("should not reach kubectl logs")
        p1, p2 = self._mock_both(raiser)
        with p1, p2:
            result = self.plt.get_prod_commerce_logs(component="ts-app")
        body = _body(result)
        self.assertTrue(any(e["category"] == "pod_discovery_failed" for e in body["fetch_errors"]))

    def test_unexpected_exception_in_classification_yields_withheld_response(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        logs = {("obliveapts-app-a", False): _ISO_TIMESTAMPED_LOG}
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs))
        with p1, p2, patch.object(self.plt, "_resolve_pods_for_logs", side_effect=RuntimeError("boom")):
            result = self.plt.get_prod_commerce_logs(component="ts-app")
        self.assertIn("[prod-commerce]", result)
        body = _body(result)
        self.assertEqual(
            body,
            {"error": "PROD Commerce log data could not be safely parsed and was withheld before being returned."},
        )

    def test_no_raw_fallback_on_exception_message(self):
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        logs = {("obliveapts-app-a", False): _ISO_TIMESTAMPED_LOG}
        raw_marker = "RAW_LOG_TEXT_SHOULD_NEVER_APPEAR"

        def boom(*args, **kwargs):
            raise RuntimeError(raw_marker)

        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs))
        with p1, p2, patch.object(self.plt, "_build_evidence_records", side_effect=boom):
            result = self.plt.get_prod_commerce_logs(component="ts-app")
        self.assertNotIn(raw_marker, result)

    def test_output_truncation_flagged_when_over_limit(self):
        # Force more than _MAX_EVIDENCE_RECORDS synthetic records out of a
        # single (mocked) pod fetch, to exercise the real cap+flag logic
        # in get_prod_commerce_logs rather than the constant alone.
        pods = {"commerce": [_pod_line("obliveapts-app-a", "commerce", containers=("ts-app",))]}
        logs = {("obliveapts-app-a", False): "ERROR one line is enough to fetch something\n"}
        oversized = [
            {
                "pod": "obliveapts-app-a", "container": "ts-app", "log_source": "current",
                "category": "generic_error", "severity": "low", "exception_class": None,
                "normalized_message": f"synthetic message {i}", "stack_fingerprint": f"fp{i}",
                "frame_count": 0, "occurrence_count": 1, "first_seen": None, "last_seen": None,
                "timestamp_known": False, "excerpt": None,
            }
            for i in range(self.plt._MAX_EVIDENCE_RECORDS + 5)
        ]
        p1, p2 = self._mock_both(_fake_readonly(pod_lines_by_ns=pods, logs_by_pod=logs))
        with p1, p2, patch.object(self.plt, "_build_evidence_records", return_value=oversized):
            result = self.plt.get_prod_commerce_logs(component="ts-app")
        body = _body(result)
        self.assertEqual(len(body["evidence"]), self.plt._MAX_EVIDENCE_RECORDS)
        self.assertTrue(body["log_coverage"]["output_truncated"])


if __name__ == "__main__":
    unittest.main()
