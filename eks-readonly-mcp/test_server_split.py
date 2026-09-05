"""Tests for the eks-readonly / eks-commerce MCP server split.

These do a fresh, isolated import of server.py and commerce_server.py (each
import evicts the split modules from sys.modules first, so a module cached
by an earlier test in the same process can't hide a registration bug) and
then inspect the real MCP SDK tool registry (MCPServer._tool_manager) -
never source-text grep - to confirm the tool counts and names actually
registered with the SDK.

No SSH connection is opened by importing these modules: constructing a
BastionSSHClient only stores its Config; the socket is opened lazily
inside run_kubectl(), which these tests never call.
"""
from __future__ import annotations

import ast
import importlib
import inspect
import sys
import unittest

_SPLIT_MODULES = ("server", "commerce_server", "commerce_tools", "kube_core")

_EXPECTED_COMMERCE_TOOLS = {
    "list_commerce_components",
    "get_commerce_component_logs",
    "analyze_commerce_component_errors",
    "correlate_commerce_errors",
    "diagnose_commerce_issue",
    "get_commerce_health",
    "correlate_commerce_timeline",
}

_EXPECTED_STANDARD_TOOLS = {
    "get_cluster_info",
    "get_namespaces",
    "get_nodes",
    "get_pods",
    "get_deployments",
    "get_services",
    "get_ingress",
    "get_hpa",
    "get_events",
    "get_version",
    "get_api_resources",
    "get_replicasets",
    "get_statefulsets",
    "get_daemonsets",
    "get_jobs",
    "get_cronjobs",
    "get_endpoints",
    "get_endpointslices",
    "get_networkpolicies",
    "get_pdb",
    "get_configmaps",
    "get_secrets_metadata",
    "get_persistentvolumes",
    "get_persistentvolumeclaims",
    "get_storageclasses",
    "get_serviceaccounts",
    "get_roles",
    "get_rolebindings",
    "get_clusterroles",
    "get_clusterrolebindings",
    "get_pod_logs",
}


def _fresh_import(name: str):
    """Import `name` after evicting the split modules from sys.modules, so
    this observes a real first-import registration rather than a module
    cached by an earlier test/import in this process."""
    saved = {mod: sys.modules.pop(mod, None) for mod in _SPLIT_MODULES}
    try:
        return importlib.import_module(name)
    finally:
        for mod, prior in saved.items():
            if mod not in sys.modules and prior is not None:
                sys.modules[mod] = prior


def _module_imports(filename: str) -> set[str]:
    """Top-level and nested import targets of a .py file, via AST (not
    grep), so a reference inside a comment/docstring can't produce a false
    positive or a false negative."""
    with open(filename, encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=filename)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    return imported


class TestReadonlyServerToolRegistry(unittest.TestCase):
    def test_exactly_31_standard_tools_registered(self):
        server = _fresh_import("server")
        names = {t.name for t in server.mcp._tool_manager.list_tools()}
        self.assertEqual(len(names), 31)
        self.assertEqual(names, _EXPECTED_STANDARD_TOOLS)

    def test_commerce_tool_names_absent(self):
        server = _fresh_import("server")
        names = {t.name for t in server.mcp._tool_manager.list_tools()}
        self.assertTrue(names.isdisjoint(_EXPECTED_COMMERCE_TOOLS), names & _EXPECTED_COMMERCE_TOOLS)

    def test_get_pod_logs_signature_unchanged(self):
        server = _fresh_import("server")
        sig = inspect.signature(server.get_pod_logs)
        params = list(sig.parameters.values())
        self.assertEqual(
            [(p.name, p.default) for p in params],
            [
                ("namespace", inspect.Parameter.empty),
                ("pod", inspect.Parameter.empty),
                ("container", None),
                ("tail_lines", 100),
                ("previous", False),
                ("since", None),
                ("env", "dev"),
            ],
        )


class TestCommerceServerToolRegistry(unittest.TestCase):
    def test_exactly_7_commerce_tools_registered(self):
        commerce_server = _fresh_import("commerce_server")
        names = {t.name for t in commerce_server.mcp._tool_manager.list_tools()}
        self.assertEqual(len(names), 7)
        self.assertEqual(names, _EXPECTED_COMMERCE_TOOLS)

    def test_standard_tool_names_absent(self):
        commerce_server = _fresh_import("commerce_server")
        names = {t.name for t in commerce_server.mcp._tool_manager.list_tools()}
        self.assertTrue(names.isdisjoint(_EXPECTED_STANDARD_TOOLS), names & _EXPECTED_STANDARD_TOOLS)


class TestNoImportCycle(unittest.TestCase):
    def test_server_does_not_import_commerce_tools(self):
        self.assertNotIn("commerce_tools", _module_imports("server.py"))

    def test_commerce_tools_does_not_import_server(self):
        self.assertNotIn("server", _module_imports("commerce_tools.py"))

    def test_commerce_server_does_not_import_server(self):
        self.assertNotIn("server", _module_imports("commerce_server.py"))


if __name__ == "__main__":
    unittest.main()
