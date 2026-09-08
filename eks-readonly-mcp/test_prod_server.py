"""Tests for prod_server.py: the eks-prod-readonly MCP server.

No real SSH connection, no real kubectl, no PROD contact of any kind. A
throwaway temp file stands in for the PROD private key (existence-checked
only, matching prod_config.py's contract) so load_prod_config() succeeds
during import, and paramiko.SSHClient.connect is patched to raise if
anything in this test file ever tries to actually open a socket.
"""
from __future__ import annotations

import ast
import importlib
import inspect
import os
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

import kube_core

_MODULE_NAME = "prod_server"

_EXPECTED_PROD_TOOLS = {
    "get_cluster_info",
    "get_namespaces",
    "get_nodes",
    "get_pods",
    "get_deployments",
    "get_services",
    "get_events",
    "get_version",
    "get_hpa",
    "get_replicasets",
    "get_statefulsets",
    "get_daemonsets",
}

_EXPECTED_STANDARD_TOOLS = {
    "get_cluster_info", "get_namespaces", "get_nodes", "get_pods",
    "get_deployments", "get_services", "get_ingress", "get_hpa",
    "get_events", "get_version", "get_api_resources", "get_replicasets",
    "get_statefulsets", "get_daemonsets", "get_jobs", "get_cronjobs",
    "get_endpoints", "get_endpointslices", "get_networkpolicies", "get_pdb",
    "get_configmaps", "get_secrets_metadata", "get_persistentvolumes",
    "get_persistentvolumeclaims", "get_storageclasses",
    "get_serviceaccounts", "get_roles", "get_rolebindings",
    "get_clusterroles", "get_clusterrolebindings", "get_pod_logs",
}

_EXPECTED_COMMERCE_TOOLS = {
    "list_commerce_components", "get_commerce_component_logs",
    "analyze_commerce_component_errors", "correlate_commerce_errors",
    "diagnose_commerce_issue", "get_commerce_health",
    "correlate_commerce_timeline",
}

_FORBIDDEN_VERB_PATTERN = re.compile(
    r"\b(delete|apply|create|patch|edit|replace|scale|rollout|exec|port-forward|cp|"
    r"cordon|drain|uncordon|label|annotate|taint|expose|attach|debug|proxy|"
    r"set\s+(image|env)|auth\s+can-i)\b",
    re.IGNORECASE,
)
_READONLY_VERB_PATTERN = re.compile(r"^kubectl\s+(get|cluster-info|version|api-resources|logs)\b")


class ProdServerTestCase(unittest.TestCase):
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

        # Any attempt by this test file (directly or via a bug in
        # prod_server.py) to actually open an SSH connection - including
        # during a fresh import - fails the test loudly instead of quietly
        # reaching out to a real host.
        self._connect_patcher = patch(
            "paramiko.SSHClient.connect",
            side_effect=AssertionError("must never open a real SSH connection in tests"),
        )
        self._connect_patcher.start()
        self.addCleanup(self._connect_patcher.stop)

    def tearDown(self):
        self._env_patcher.stop()

    def _fresh_import(self):
        saved = {mod: sys.modules.pop(mod, None) for mod in (_MODULE_NAME, "readonly_exec", "prod_config")}
        try:
            return importlib.import_module(_MODULE_NAME)
        finally:
            for mod, prior in saved.items():
                if mod not in sys.modules and prior is not None:
                    sys.modules[mod] = prior

    def _source(self) -> str:
        with open("prod_server.py", encoding="utf-8") as f:
            return f.read()

    def _imports(self) -> set[str]:
        tree = ast.parse(self._source())
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        return imported


class ServerIdentityTests(ProdServerTestCase):
    def test_server_name_is_eks_prod_readonly(self):
        prod_server = self._fresh_import()
        self.assertEqual(prod_server.mcp.name, "eks-prod-readonly")

    def test_import_does_not_open_a_socket(self):
        # setUp's paramiko.SSHClient.connect patcher raises if called; a
        # clean fresh import proves BastionSSHClient(...) at module scope
        # only stored config, exactly as ssh_client.py's __init__ does.
        prod_server = self._fresh_import()
        self.assertIsNotNone(prod_server._prod_ssh)


class ToolRegistryTests(ProdServerTestCase):
    def test_exactly_12_tools_registered_with_exact_names(self):
        prod_server = self._fresh_import()
        names = {t.name for t in prod_server.mcp._tool_manager.list_tools()}
        self.assertEqual(len(names), 12)
        self.assertEqual(names, _EXPECTED_PROD_TOOLS)

    def test_no_overlap_with_excluded_standard_tools(self):
        prod_server = self._fresh_import()
        names = {t.name for t in prod_server.mcp._tool_manager.list_tools()}
        excluded = _EXPECTED_STANDARD_TOOLS - _EXPECTED_PROD_TOOLS
        self.assertTrue(names.isdisjoint(excluded), names & excluded)
        self.assertNotIn("get_pod_logs", names)
        self.assertNotIn("get_secrets_metadata", names)
        self.assertNotIn("get_configmaps", names)
        self.assertNotIn("get_api_resources", names)
        self.assertNotIn("get_serviceaccounts", names)
        self.assertNotIn("get_clusterrolebindings", names)

    def test_no_overlap_with_commerce_tools(self):
        prod_server = self._fresh_import()
        names = {t.name for t in prod_server.mcp._tool_manager.list_tools()}
        self.assertTrue(names.isdisjoint(_EXPECTED_COMMERCE_TOOLS), names & _EXPECTED_COMMERCE_TOOLS)


class NoEnvironmentParameterTests(ProdServerTestCase):
    def test_no_tool_function_has_an_env_parameter(self):
        prod_server = self._fresh_import()
        for name in _EXPECTED_PROD_TOOLS:
            fn = getattr(prod_server, name)
            sig = inspect.signature(fn)
            self.assertNotIn("env", sig.parameters, f"{name} must not accept env")

    def test_calling_a_tool_with_env_kwarg_raises_type_error(self):
        prod_server = self._fresh_import()
        with self.assertRaises(TypeError):
            prod_server.get_pods(env="dev")
        with self.assertRaises(TypeError):
            prod_server.get_cluster_info(env="uat")

    def test_no_env_parameter_anywhere_in_prod_server_source(self):
        tree = ast.parse(self._source())
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                arg_names = {a.arg for a in node.args.args}
                self.assertNotIn("env", arg_names, f"{node.name} must not accept env")


class ImportHygieneTests(ProdServerTestCase):
    def test_does_not_import_server(self):
        self.assertNotIn("server", self._imports())

    def test_does_not_import_commerce_server(self):
        self.assertNotIn("commerce_server", self._imports())

    def test_does_not_import_commerce_tools(self):
        self.assertNotIn("commerce_tools", self._imports())

    def test_does_not_import_kube_core(self):
        # prod_server.py must not depend on the DEV/UAT-specific module at
        # all - it has its own environment-neutral execution path.
        self.assertNotIn("kube_core", self._imports())

    def test_does_not_import_dev_uat_config_loader_function(self):
        # Checked via AST (imported names + call targets), not a raw text
        # search - the module's own docstring explains in prose that it
        # never imports config.load_configs(), which would otherwise give
        # a false positive against a substring search.
        tree = ast.parse(self._source())
        imported_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported_names.update(alias.name for alias in node.names)
        self.assertNotIn("load_configs", imported_names)

        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertNotIn("load_configs", called_names)


class SingleClientTests(ProdServerTestCase):
    def test_exactly_one_bastionsshclient_constructed_in_source(self):
        tree = ast.parse(self._source())
        constructions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "BastionSSHClient"
        ]
        self.assertEqual(len(constructions), 1)

    def test_all_tools_use_the_single_module_level_prod_ssh_client(self):
        prod_server = self._fresh_import()
        calls = []

        def fake_run_readonly(ssh, command, tag, sanitizer=None):
            calls.append((ssh, command, tag))
            return f"[{tag}]\nfake"

        with patch.object(prod_server, "run_readonly", side_effect=fake_run_readonly):
            for name in sorted(_EXPECTED_PROD_TOOLS):
                fn = getattr(prod_server, name)
                kwargs = {"namespace": None} if "namespace" in inspect.signature(fn).parameters else {}
                fn(**kwargs)

        self.assertEqual(len(calls), len(_EXPECTED_PROD_TOOLS))
        for ssh, _command, tag in calls:
            self.assertIs(ssh, prod_server._prod_ssh)
            self.assertEqual(tag, "prod")


class ReadOnlyCommandTests(ProdServerTestCase):
    def test_every_tool_builds_a_readonly_command(self):
        prod_server = self._fresh_import()
        calls = []

        def fake_run_readonly(ssh, command, tag, sanitizer=None):
            calls.append(command)
            return f"[{tag}]\nfake"

        with patch.object(prod_server, "run_readonly", side_effect=fake_run_readonly):
            for name in sorted(_EXPECTED_PROD_TOOLS):
                fn = getattr(prod_server, name)
                kwargs = {"namespace": None} if "namespace" in inspect.signature(fn).parameters else {}
                fn(**kwargs)

        self.assertEqual(len(calls), 12)
        for command in calls:
            self.assertRegex(command, _READONLY_VERB_PATTERN, command)
            self.assertNotRegex(command, _FORBIDDEN_VERB_PATTERN, command)

    def test_no_write_verbs_appear_anywhere_in_source(self):
        source = self._source()
        # Static sweep of the whole file, not just constructed commands -
        # catches a forbidden verb even if it were hidden in an unreachable
        # branch.
        for verb in ("delete", "apply", "patch", "exec", "port-forward", "rollout", "drain", "cordon"):
            self.assertNotIn(f"kubectl {verb}", source)


class OutputBoundednessTests(ProdServerTestCase):
    def test_prod_server_does_not_reimplement_its_own_output_formatter(self):
        tree = ast.parse(self._source())
        defined_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
        self.assertNotIn("run_readonly", defined_names)
        self.assertNotIn("_run", defined_names)

    def test_readonly_exec_output_cap_matches_kube_core_cap(self):
        import readonly_exec

        self.assertEqual(readonly_exec._MAX_OUTPUT_CHARS, kube_core._MAX_OUTPUT_CHARS)


class DevUatRegressionCanaryTests(unittest.TestCase):
    def test_kube_core_allowed_envs_unchanged(self):
        self.assertEqual(kube_core._ALLOWED_ENVS, ("dev", "uat"))


class PodDataRedactionWiringTests(ProdServerTestCase):
    """get_pods (P10.3K) and get_deployments/get_replicasets/
    get_statefulsets/get_daemonsets (P11B) all use prevention-based
    custom-columns parsers - none of the 12 tools use
    prod_pod_sanitizer.sanitize_pod_list_json()/sanitize_workload_list_json()
    any more (both retained, unused, in prod_pod_sanitizer.py). The
    remaining 7 tools return no container data and must pass no
    sanitizer/parser at all."""

    _EXPECTED_WORKLOAD_PARSERS = {
        "get_deployments": "parse_get_deployments_columns",
        "get_replicasets": "parse_get_replicasets_columns",
        "get_statefulsets": "parse_get_statefulsets_columns",
        "get_daemonsets": "parse_get_daemonsets_columns",
    }

    def _call_every_tool_and_capture_sanitizers(self, prod_server):
        calls_by_tool = {}

        def fake_run_readonly(ssh, command, tag, sanitizer=None):
            calls_by_tool[current_tool[0]] = sanitizer
            return f"[{tag}]\nfake"

        current_tool = [None]
        with patch.object(prod_server, "run_readonly", side_effect=fake_run_readonly):
            for name in sorted(_EXPECTED_PROD_TOOLS):
                current_tool[0] = name
                fn = getattr(prod_server, name)
                kwargs = {"namespace": None} if "namespace" in inspect.signature(fn).parameters else {}
                fn(**kwargs)
        return calls_by_tool

    def test_exactly_five_tools_pass_a_sanitizer_or_parser(self):
        prod_server = self._fresh_import()
        calls_by_tool = self._call_every_tool_and_capture_sanitizers(prod_server)

        used_tools = {name for name, s in calls_by_tool.items() if s is not None}
        expected = set(self._EXPECTED_WORKLOAD_PARSERS) | {"get_pods"}
        self.assertEqual(used_tools, expected)

    def test_get_pods_uses_parse_get_pods_columns(self):
        prod_server = self._fresh_import()
        calls_by_tool = self._call_every_tool_and_capture_sanitizers(prod_server)
        self.assertIs(calls_by_tool["get_pods"], prod_server.parse_get_pods_columns)

    def test_get_pods_does_not_use_sanitize_pod_list_json(self):
        prod_server = self._fresh_import()
        calls_by_tool = self._call_every_tool_and_capture_sanitizers(prod_server)
        import prod_pod_sanitizer

        self.assertIsNot(calls_by_tool["get_pods"], prod_pod_sanitizer.sanitize_pod_list_json)

    def test_each_workload_tool_uses_its_own_prevention_based_parser(self):
        prod_server = self._fresh_import()
        calls_by_tool = self._call_every_tool_and_capture_sanitizers(prod_server)
        for name, parser_attr in self._EXPECTED_WORKLOAD_PARSERS.items():
            expected_parser = getattr(prod_server, parser_attr)
            self.assertIs(calls_by_tool[name], expected_parser, f"{name} parser mismatch")

    def test_workload_tools_do_not_use_sanitize_workload_list_json(self):
        prod_server = self._fresh_import()
        calls_by_tool = self._call_every_tool_and_capture_sanitizers(prod_server)
        import prod_pod_sanitizer

        for name in self._EXPECTED_WORKLOAD_PARSERS:
            self.assertIsNot(
                calls_by_tool[name], prod_pod_sanitizer.sanitize_workload_list_json, f"{name} still uses old sanitizer"
            )

    def test_sanitizer_and_parser_functions_are_the_expected_module_functions(self):
        import prod_pod_columns
        import prod_workload_columns

        prod_server = self._fresh_import()
        self.assertIs(prod_server.parse_get_pods_columns, prod_pod_columns.parse_get_pods_columns)
        self.assertIs(prod_server.parse_get_deployments_columns, prod_workload_columns.parse_get_deployments_columns)
        self.assertIs(prod_server.parse_get_replicasets_columns, prod_workload_columns.parse_get_replicasets_columns)
        self.assertIs(prod_server.parse_get_statefulsets_columns, prod_workload_columns.parse_get_statefulsets_columns)
        self.assertIs(prod_server.parse_get_daemonsets_columns, prod_workload_columns.parse_get_daemonsets_columns)

    def test_old_workload_sanitizer_retained_but_unused_by_prod_server(self):
        # prod_pod_sanitizer.sanitize_workload_list_json() must still exist
        # and work (P11B instruction: do not delete it), and none of the
        # four workload tools may be wired to it. This is a structural,
        # identity-based check (what the tool actually calls at runtime),
        # not a textual search of the source file - the function may be
        # named in documentation/docstrings without being wired to anything.
        import prod_pod_sanitizer

        self.assertTrue(callable(prod_pod_sanitizer.sanitize_workload_list_json))

        prod_server = self._fresh_import()
        calls_by_tool = self._call_every_tool_and_capture_sanitizers(prod_server)
        for name in self._EXPECTED_WORKLOAD_PARSERS:
            self.assertIsNot(
                calls_by_tool[name],
                prod_pod_sanitizer.sanitize_workload_list_json,
                f"{name} still uses old sanitizer",
            )

    def test_get_pods_command_uses_custom_columns_not_json(self):
        prod_server = self._fresh_import()
        calls = []

        def fake_run_readonly(ssh, command, tag, sanitizer=None):
            calls.append(command)
            return f"[{tag}]\nfake"

        with patch.object(prod_server, "run_readonly", side_effect=fake_run_readonly):
            prod_server.get_pods()

        self.assertEqual(len(calls), 1)
        command = calls[0]
        self.assertIn("custom-columns=", command)
        self.assertIn("--no-headers", command)
        self.assertNotIn("-o json", command)

    def test_get_pods_command_includes_the_fixed_column_spec(self):
        import prod_pod_columns

        prod_server = self._fresh_import()
        calls = []

        def fake_run_readonly(ssh, command, tag, sanitizer=None):
            calls.append(command)
            return f"[{tag}]\nfake"

        with patch.object(prod_server, "run_readonly", side_effect=fake_run_readonly):
            prod_server.get_pods()

        self.assertIn(prod_pod_columns.POD_COLUMNS_SPEC, calls[0])

    def test_get_pods_still_read_only_and_namespace_scoped(self):
        prod_server = self._fresh_import()
        calls = []

        def fake_run_readonly(ssh, command, tag, sanitizer=None):
            calls.append(command)
            return f"[{tag}]\nfake"

        with patch.object(prod_server, "run_readonly", side_effect=fake_run_readonly):
            prod_server.get_pods(namespace="commerce")
        self.assertIn("-n commerce", calls[0])
        self.assertRegex(calls[0], _READONLY_VERB_PATTERN)
        self.assertNotRegex(calls[0], _FORBIDDEN_VERB_PATTERN)

    def test_workload_tools_use_custom_columns_not_json(self):
        prod_server = self._fresh_import()
        for tool_name in self._EXPECTED_WORKLOAD_PARSERS:
            with self.subTest(tool=tool_name):
                calls = []

                def fake_run_readonly(ssh, command, tag, sanitizer=None):
                    calls.append(command)
                    return f"[{tag}]\nfake"

                with patch.object(prod_server, "run_readonly", side_effect=fake_run_readonly):
                    getattr(prod_server, tool_name)()

                self.assertEqual(len(calls), 1)
                self.assertIn("custom-columns=", calls[0])
                self.assertIn("--no-headers", calls[0])
                self.assertNotIn("-o json", calls[0])

    def test_workload_tools_command_includes_the_correct_fixed_column_spec(self):
        import prod_workload_columns as pwc

        expected_spec_by_tool = {
            "get_deployments": pwc.DEPLOYMENT_COLUMNS_SPEC,
            "get_replicasets": pwc.REPLICASET_COLUMNS_SPEC,
            "get_statefulsets": pwc.STATEFULSET_COLUMNS_SPEC,
            "get_daemonsets": pwc.DAEMONSET_COLUMNS_SPEC,
        }
        prod_server = self._fresh_import()
        for tool_name, expected_spec in expected_spec_by_tool.items():
            with self.subTest(tool=tool_name):
                calls = []

                def fake_run_readonly(ssh, command, tag, sanitizer=None):
                    calls.append(command)
                    return f"[{tag}]\nfake"

                with patch.object(prod_server, "run_readonly", side_effect=fake_run_readonly):
                    getattr(prod_server, tool_name)()

                self.assertIn(expected_spec, calls[0])

    def test_workload_tools_still_read_only_and_namespace_scoped(self):
        prod_server = self._fresh_import()
        for tool_name in self._EXPECTED_WORKLOAD_PARSERS:
            with self.subTest(tool=tool_name):
                calls = []

                def fake_run_readonly(ssh, command, tag, sanitizer=None):
                    calls.append(command)
                    return f"[{tag}]\nfake"

                with patch.object(prod_server, "run_readonly", side_effect=fake_run_readonly):
                    getattr(prod_server, tool_name)(namespace="commerce")
                self.assertIn("-n commerce", calls[0])
                self.assertRegex(calls[0], _READONLY_VERB_PATTERN)
                self.assertNotRegex(calls[0], _FORBIDDEN_VERB_PATTERN)


class GetPodsCustomColumnsWiringTests(ProdServerTestCase):
    """Column-spec-level security checks specific to P10.3K's get_pods
    change - static assertions that the fixed spec never references a
    sensitive field PATH, independent of any particular parser output.

    P10.3L.1 correction: the original version of this test checked the
    bare substring "data", which false-positived against the legitimate,
    required `.metadata.name`/`.metadata.namespace` paths (both contain
    "data" as part of "meta-data"). See test_prod_pod_columns.py's
    SecurityStaticTests for the authoritative, more thoroughly-tested
    version of this check - this copy is kept for wiring-context
    completeness within this file."""

    _FORBIDDEN_DOTTED_PATHS = (".env", ".envFrom", ".data", ".stringData")
    _FORBIDDEN_BARE_SUBSTRINGS = (
        "secretKeyRef",
        "configMapKeyRef",
        "secretRef",
        "configMapRef",
        "serviceAccount",
        "labels",
        "annotations",
    )

    def test_column_spec_excludes_sensitive_field_paths(self):
        import prod_pod_columns

        spec = prod_pod_columns.POD_COLUMNS_SPEC
        for forbidden in self._FORBIDDEN_DOTTED_PATHS:
            self.assertNotIn(forbidden, spec, f"PROD get_pods column spec references sensitive path {forbidden!r}")
        for forbidden in self._FORBIDDEN_BARE_SUBSTRINGS:
            self.assertNotIn(forbidden, spec, f"PROD get_pods column spec references {forbidden!r}")

    def test_metadata_paths_present_without_false_positive(self):
        import prod_pod_columns

        spec = prod_pod_columns.POD_COLUMNS_SPEC
        self.assertIn(".metadata.name", spec)
        self.assertIn(".metadata.namespace", spec)
        for forbidden in self._FORBIDDEN_DOTTED_PATHS:
            self.assertNotIn(forbidden, spec)


class WorkloadCustomColumnsWiringTests(ProdServerTestCase):
    """P11B: column-spec-level security checks for the four workload
    tools' fixed custom-columns specs - path-aware, per the P10.3L.1
    corrected methodology (never a naive substring check for tokens like
    bare "data" that collide with legitimate ".metadata" paths)."""

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

    def _all_specs(self):
        import prod_workload_columns as pwc

        return {
            "Deployment": pwc.DEPLOYMENT_COLUMNS_SPEC,
            "ReplicaSet": pwc.REPLICASET_COLUMNS_SPEC,
            "StatefulSet": pwc.STATEFULSET_COLUMNS_SPEC,
            "DaemonSet": pwc.DAEMONSET_COLUMNS_SPEC,
        }

    def test_column_specs_exclude_sensitive_field_paths(self):
        for resource, spec in self._all_specs().items():
            with self.subTest(resource=resource):
                for forbidden in self._FORBIDDEN_DOTTED_PATHS:
                    self.assertNotIn(forbidden, spec, f"{resource} column spec references sensitive path {forbidden!r}")
                for forbidden in self._FORBIDDEN_BARE_SUBSTRINGS:
                    self.assertNotIn(forbidden, spec, f"{resource} column spec references {forbidden!r}")

    def test_metadata_paths_present_without_false_positive(self):
        for resource, spec in self._all_specs().items():
            with self.subTest(resource=resource):
                self.assertIn(".metadata.name", spec)
                self.assertIn(".metadata.namespace", spec)
                for forbidden in self._FORBIDDEN_DOTTED_PATHS:
                    self.assertNotIn(forbidden, spec)


class PodDataRedactionEndToEndTests(ProdServerTestCase):
    """Exercises get_pods() through the real run_readonly()/parser
    pipeline (P10.3K), mocking only the SSH layer's run_kubectl() - proves
    the prevention-based design end to end, not just that the right
    function object was wired up. Fake stdout is custom-columns TEXT, not
    JSON, matching what the real kubectl command now produces."""

    @staticmethod
    def _fake_columns_row(
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

    def _mock_ssh_returning_fake_columns(self, prod_server, stdout):
        from ssh_client import CommandResult

        result = CommandResult(
            command="kubectl get pods -A -o custom-columns=... --no-headers",
            stdout=stdout,
            stderr="",
            exit_code=0,
        )
        return patch.object(prod_server._prod_ssh, "run_kubectl", return_value=result)

    def test_get_pods_end_to_end_preserves_operational_fields_no_env_ever_requested(self):
        import json

        prod_server = self._fresh_import()
        with self._mock_ssh_returning_fake_columns(prod_server, self._fake_columns_row()):
            out = prod_server.get_pods()

        # There is no env/envFrom/secret data anywhere in this pipeline at
        # all (prevention, not redaction) - these sentinels stand in for
        # "anything that must never appear", proving absence structurally
        # rather than by having first been present and then stripped.
        for sentinel in ("SUPER_SECRET_TEST_VALUE_12345", "hvs.FAKE0000EXAMPLE0000NOTREAL", "checkout-db-creds", "DB_PASSWORD", "VAULT_TOKEN"):
            self.assertNotIn(sentinel, out)

        self.assertIn("checkout-7d9", out)
        self.assertIn("commerce", out)
        self.assertIn("Running", out)
        self.assertIn("10.13.4.55", out)
        self.assertIn("ip-10-13-1-20.ec2.internal", out)
        self.assertIn("registry.internal/checkout:1.4.2", out)

        body = out.split("\n", 1)[1]
        data = json.loads(body)
        self.assertEqual(len(data["pods"]), 1)
        self.assertEqual(data["pods"][0]["ready"], {"ready_count": 1, "total_count": 1})
        self.assertEqual(data["pods"][0]["restarts"], {"max": 0})

    def test_get_pods_fails_closed_on_malformed_ssh_output_end_to_end(self):
        prod_server = self._fresh_import()
        with self._mock_ssh_returning_fake_columns(prod_server, "not a valid custom-columns row"):
            out = prod_server.get_pods()
        self.assertIn("withheld", out)
        self.assertNotIn("not a valid custom-columns row", out)

    def test_parser_cannot_be_bypassed_by_namespace_choice(self):
        prod_server = self._fresh_import()
        for ns in (None, "all", "commerce", "kube-system", "default"):
            with self._mock_ssh_returning_fake_columns(prod_server, self._fake_columns_row(namespace=ns or "commerce")):
                out = prod_server.get_pods(namespace=ns)
            self.assertNotIn("SUPER_SECRET_TEST_VALUE_12345", out, f"failed for namespace={ns!r}")
            self.assertIn("checkout-7d9", out, f"failed for namespace={ns!r}")


class WorkloadDataRedactionEndToEndTests(ProdServerTestCase):
    """P11B: exercises get_deployments/get_replicasets/get_statefulsets/
    get_daemonsets through the real run_readonly()/parser pipeline,
    mocking only the SSH layer's run_kubectl() - proves the prevention-based
    design end to end for each of the four workload tools, not just that
    the right function object was wired up. Fake stdout is custom-columns
    TEXT, not JSON, matching what the real kubectl command now produces."""

    _TOOL_TO_JSON_KEY = {
        "get_deployments": "deployments",
        "get_replicasets": "replicasets",
        "get_statefulsets": "statefulsets",
        "get_daemonsets": "daemonsets",
    }
    _TOOL_HAS_UPDATED = {
        "get_deployments": True,
        "get_replicasets": False,
        "get_statefulsets": True,
        "get_daemonsets": True,
    }

    @classmethod
    def _fake_columns_row(
        cls,
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

    def _mock_ssh_returning_fake_columns(self, prod_server, stdout):
        from ssh_client import CommandResult

        result = CommandResult(
            command="kubectl get <resource> -A -o custom-columns=... --no-headers",
            stdout=stdout,
            stderr="",
            exit_code=0,
        )
        return patch.object(prod_server._prod_ssh, "run_kubectl", return_value=result)

    def test_each_workload_tool_end_to_end_preserves_operational_fields_no_env_ever_requested(self):
        import json

        prod_server = self._fresh_import()
        for tool_name, json_key in self._TOOL_TO_JSON_KEY.items():
            has_updated = self._TOOL_HAS_UPDATED[tool_name]
            with self.subTest(tool=tool_name):
                fn = getattr(prod_server, tool_name)
                row = self._fake_columns_row(has_updated)
                with self._mock_ssh_returning_fake_columns(prod_server, row):
                    out = fn()

                # There is no env/envFrom/secret data anywhere in this
                # pipeline at all (prevention, not redaction) - these
                # sentinels stand in for "anything that must never
                # appear", proving absence structurally rather than by
                # having first been present and then stripped.
                for sentinel in (
                    "SUPER_SECRET_TEST_VALUE_12345",
                    "FAKE_VAULT_TOKEN_12345",
                    "checkout-db-creds",
                    "DB_PASSWORD",
                    "VAULT_TOKEN",
                ):
                    self.assertNotIn(sentinel, out)

                self.assertIn("checkout", out)
                self.assertIn("commerce", out)
                self.assertIn("registry.internal/checkout:1.4.2", out)

                body = out.split("\n", 1)[1]
                data = json.loads(body)
                self.assertEqual(len(data[json_key]), 1)
                item = data[json_key][0]
                self.assertEqual(item["desired"], 3)
                self.assertEqual(item["ready"], 3)
                self.assertEqual(item["available"], 3)
                if has_updated:
                    self.assertEqual(item["updated"], 3)
                else:
                    self.assertIsNone(item["updated"])

    def test_workload_tool_fails_closed_on_malformed_ssh_output_end_to_end(self):
        prod_server = self._fresh_import()
        for tool_name in self._TOOL_TO_JSON_KEY:
            with self.subTest(tool=tool_name):
                fn = getattr(prod_server, tool_name)
                sentinel = "SUPER_SECRET_TEST_VALUE_12345"
                with self._mock_ssh_returning_fake_columns(prod_server, f"not a valid row {sentinel}"):
                    out = fn()
                self.assertIn("withheld", out)
                self.assertNotIn(sentinel, out)

    def test_parser_cannot_be_bypassed_by_namespace_choice_for_any_workload_tool(self):
        prod_server = self._fresh_import()
        for tool_name in self._TOOL_TO_JSON_KEY:
            has_updated = self._TOOL_HAS_UPDATED[tool_name]
            fn = getattr(prod_server, tool_name)
            for ns in (None, "all", "commerce", "kube-system", "default"):
                with self.subTest(tool=tool_name, namespace=ns):
                    row = self._fake_columns_row(has_updated, namespace=ns or "commerce")
                    with self._mock_ssh_returning_fake_columns(prod_server, row):
                        out = fn(namespace=ns)
                    self.assertNotIn("SUPER_SECRET_TEST_VALUE_12345", out, f"failed for namespace={ns!r}")
                    self.assertIn("checkout", out, f"failed for namespace={ns!r}")


if __name__ == "__main__":
    unittest.main()
