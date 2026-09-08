"""Tests for prod_commerce_server.py: the eks-prod-commerce MCP server
(P12A discovery/health + P12B safe logs).

No real SSH connection, no real kubectl, no PROD contact of any kind - same
synthetic PROD_BASTION_* + temp-key-file + paramiko.connect-patch setup as
test_prod_commerce_config.py/test_prod_commerce_tools.py. Also cross-checks
that the three PRE-EXISTING, FROZEN MCP servers (eks-readonly = 31 tools,
eks-commerce = 7 tools, eks-prod-readonly = 12 tools) are unaffected by
this phase's additions.
"""
from __future__ import annotations

import importlib
import inspect
import os
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

_MODULE_NAME = "prod_commerce_server"

_EXPECTED_PROD_COMMERCE_TOOLS = {
    "list_prod_commerce_components", "get_prod_commerce_health", "get_prod_commerce_logs",
}

_FORBIDDEN_VERB_PATTERN = re.compile(
    r"\b(delete|apply|create|patch|edit|replace|scale|rollout|exec|port-forward|cp|"
    r"cordon|drain|uncordon|label|annotate|taint|expose|attach|debug|proxy|"
    r"set\s+(image|env)|auth\s+can-i)\b",
    re.IGNORECASE,
)


class ProdCommerceServerTestCase(unittest.TestCase):
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

    def tearDown(self):
        self._env_patcher.stop()

    def _fresh_import(self, module_name=_MODULE_NAME, extra_pop=()):
        pop_set = {
            module_name, "prod_commerce_tools", "prod_commerce_log_tools",
            "prod_commerce_log_sanitizer", "prod_commerce_config", "readonly_exec", "prod_config",
        }
        pop_set.update(extra_pop)
        saved = {mod: sys.modules.pop(mod, None) for mod in pop_set}
        try:
            return importlib.import_module(module_name)
        finally:
            for mod, prior in saved.items():
                if mod not in sys.modules and prior is not None:
                    sys.modules[mod] = prior


class ServerIdentityTests(ProdCommerceServerTestCase):
    def test_server_name_is_eks_prod_commerce(self):
        srv = self._fresh_import()
        self.assertEqual(srv.mcp.name, "eks-prod-commerce")

    def test_server_name_is_distinct_from_other_prod_and_commerce_servers(self):
        srv = self._fresh_import()
        self.assertNotEqual(srv.mcp.name, "eks-commerce")
        self.assertNotEqual(srv.mcp.name, "eks-prod-readonly")
        self.assertNotEqual(srv.mcp.name, "eks-readonly")


class ToolRegistryTests(ProdCommerceServerTestCase):
    def test_exactly_3_tools_registered_with_exact_names(self):
        srv = self._fresh_import()
        names = {t.name for t in srv.mcp._tool_manager.list_tools()}
        self.assertEqual(len(names), 3)
        self.assertEqual(names, _EXPECTED_PROD_COMMERCE_TOOLS)

    def test_no_error_analysis_correlation_diagnosis_or_recommendation_tools(self):
        # "log" is deliberately no longer in this forbidden list - P12B
        # explicitly adds get_prod_commerce_logs as an approved,
        # structured-evidence-only capability. Analysis/correlation/
        # diagnosis/recommendation remain out of scope.
        srv = self._fresh_import()
        names = {t.name for t in srv.mcp._tool_manager.list_tools()}
        forbidden_substrings = ("analyze", "correlate", "diagnose", "recommend", "timeline")
        for name in names:
            for forbidden in forbidden_substrings:
                self.assertNotIn(forbidden, name.lower())

    def _tool_module_for(self, name: str):
        import prod_commerce_log_tools as plt
        import prod_commerce_tools as pct
        return plt if name == "get_prod_commerce_logs" else pct

    def test_no_tool_exposes_environment_parameter(self):
        self._fresh_import()
        for name in _EXPECTED_PROD_COMMERCE_TOOLS:
            fn = getattr(self._tool_module_for(name), name)
            params = set(inspect.signature(fn).parameters)
            self.assertNotIn("env", params, f"{name} must not accept env")
            self.assertNotIn("environment", params, f"{name} must not accept environment")

    def test_calling_a_tool_with_env_kwarg_raises_type_error(self):
        self._fresh_import()
        import prod_commerce_log_tools as plt
        import prod_commerce_tools as pct
        with self.assertRaises(TypeError):
            pct.list_prod_commerce_components(env="dev")
        with self.assertRaises(TypeError):
            pct.get_prod_commerce_health(environment="prod")
        with self.assertRaises(TypeError):
            plt.get_prod_commerce_logs(component="ts-app", env="dev")


class NoWriteCapabilityTests(ProdCommerceServerTestCase):
    def test_no_write_verb_in_any_kubectl_command_line(self):
        # Scoped to lines that actually construct/mention a kubectl command,
        # not the whole file - plain English prose elsewhere in these files
        # legitimately uses words like "label"/"labels" (e.g. describing the
        # release/group pod labels this module reads), which would
        # otherwise false-positive against the write-verb pattern.
        for filename in (
            "prod_commerce_config.py", "prod_commerce_tools.py", "prod_commerce_server.py",
            "prod_commerce_log_tools.py", "prod_commerce_log_sanitizer.py",
        ):
            with open(filename, encoding="utf-8") as f:
                lines = f.readlines()
            for lineno, line in enumerate(lines, start=1):
                if "kubectl" not in line:
                    continue
                match = _FORBIDDEN_VERB_PATTERN.search(line)
                self.assertIsNone(
                    match, f"forbidden write verb found in {filename}:{lineno}: {line!r}"
                )

    def test_only_kubectl_get_and_logs_are_issued(self):
        self._fresh_import()
        import prod_commerce_log_tools as plt
        import prod_commerce_tools as pct
        for source in (inspect.getsource(pct), inspect.getsource(plt)):
            self.assertNotIn("kubectl delete", source)
            self.assertNotIn("kubectl apply", source)
            self.assertNotIn("kubectl exec", source)
        self.assertIn("kubectl get pods", inspect.getsource(pct))
        self.assertIn("kubectl logs", inspect.getsource(plt))

    def test_no_arbitrary_command_or_pipe_construction_in_log_tools(self):
        # Word-boundary matching, not bare substring - "sed" is a substring
        # of the ordinary English word "used" (as in "the sanitizer is
        # used..."), which a naive `in` check would false-positive on.
        # Deliberately excludes bare "<"/">"/"|" as whole-file scans: "->"
        # return-type arrows and this module's own internal f-string field
        # separator (e.g. f"category|exception_class|message", used only
        # as an in-memory hash-fingerprint seed, never part of a kubectl
        # command string) both use these characters legitimately. The
        # property that actually matters - the kubectl command STRING
        # itself never contains a pipe/redirect - is verified functionally
        # in test_prod_commerce_log_tools.py, where every issued command is
        # captured and asserted to be exactly the fixed
        # `kubectl logs ... --tail=N [-c ...] [--previous]` shape.
        self._fresh_import()
        import prod_commerce_log_tools as plt
        source = inspect.getsource(plt)
        for forbidden in (r"\bgrep\b", r"\bawk\b", r"\bsed\b"):
            self.assertIsNone(re.search(forbidden, source), f"forbidden token {forbidden!r} found")


class P12BWiringTests(ProdCommerceServerTestCase):
    """P12B item 19: the new log tool must not introduce DEV/UAT coupling
    or a second credential source."""

    def test_log_tool_module_does_not_import_commerce_tools(self):
        self._fresh_import()
        import prod_commerce_log_tools as plt
        source = inspect.getsource(plt)
        self.assertNotIn("import commerce_tools", source)

    def test_log_tool_module_does_not_import_kube_core(self):
        self._fresh_import()
        import prod_commerce_log_tools as plt
        source = inspect.getsource(plt)
        self.assertNotIn("import kube_core", source)

    def test_log_tool_uses_prod_commerce_configs_readonly_wrapper(self):
        self._fresh_import()
        import prod_commerce_log_tools as plt
        source = inspect.getsource(plt)
        self.assertIn("from prod_commerce_config import run_prod_commerce_readonly", source)

    def test_importing_log_tools_never_loads_kube_core_module(self):
        # Structural proxy: kube_core.py's own module-level
        # `_configs = load_configs()` call means its mere PRESENCE in
        # sys.modules would indicate DEV/UAT config was loaded. Confirm a
        # fresh import of prod_commerce_log_tools never puts it there.
        sys.modules.pop("kube_core", None)
        self._fresh_import()
        import prod_commerce_log_tools  # noqa: F401
        self.assertNotIn("kube_core", sys.modules)

    def test_server_registers_get_prod_commerce_logs(self):
        srv = self._fresh_import()
        names = {t.name for t in srv.mcp._tool_manager.list_tools()}
        self.assertIn("get_prod_commerce_logs", names)


class ExistingServersUnaffectedRegressionTests(unittest.TestCase):
    """P12A must not change the tool counts of the three pre-existing,
    frozen MCP servers. These are cross-checks co-located with the new
    server's own tests; the authoritative regression run is still each
    server's own existing test suite (test_server_split.py,
    test_commerce_tools.py, test_prod_server.py). Self-contained synthetic
    DEV env vars are supplied here (legacy unprefixed BASTION_*) so this
    check does not depend on the ambient shell/.env already having real
    DEV configuration - server.py/commerce_server.py import kube_core.py,
    which loads DEV config at import time."""

    def setUp(self):
        self._env_patcher = patch.dict(os.environ, {}, clear=False)
        self._env_patcher.start()

        fd, self._tmp_key_path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(b"not a real private key - existence check only")
        self.addCleanup(os.unlink, self._tmp_key_path)

        os.environ.update(
            {
                "BASTION_HOST": "10.0.0.1",
                "BASTION_PORT": "22",
                "BASTION_USER": "ubuntu",
                "BASTION_KEY_PATH": self._tmp_key_path,
                "KUBERNETES_USER": "solveda",
            }
        )

        self._connect_patcher = patch(
            "paramiko.SSHClient.connect",
            side_effect=AssertionError("must never open a real SSH connection in tests"),
        )
        self._connect_patcher.start()
        self.addCleanup(self._connect_patcher.stop)

    def tearDown(self):
        self._env_patcher.stop()

    def _fresh_import(self, module_name):
        saved = {mod: sys.modules.pop(mod, None) for mod in (module_name, "kube_core", "config")}
        try:
            return importlib.import_module(module_name)
        finally:
            for mod, prior in saved.items():
                if mod not in sys.modules and prior is not None:
                    sys.modules[mod] = prior

    def test_eks_readonly_still_has_31_tools(self):
        server = self._fresh_import("server")
        names = {t.name for t in server.mcp._tool_manager.list_tools()}
        self.assertEqual(len(names), 31)

    def test_eks_commerce_still_has_7_tools(self):
        commerce_server = self._fresh_import("commerce_server")
        names = {t.name for t in commerce_server.mcp._tool_manager.list_tools()}
        self.assertEqual(len(names), 7)


class ExistingProdReadonlyUnaffectedRegressionTests(ProdCommerceServerTestCase):
    def test_eks_prod_readonly_still_has_12_tools(self):
        prod_server = self._fresh_import(module_name="prod_server", extra_pop={"prod_server"})
        names = {t.name for t in prod_server.mcp._tool_manager.list_tools()}
        self.assertEqual(len(names), 12)


if __name__ == "__main__":
    unittest.main()
