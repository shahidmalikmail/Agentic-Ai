"""Tests for prod_commerce_config.py: PROD-only credential isolation for
the eks-prod-commerce MCP server (P12A).

No real SSH connection, no real kubectl, no PROD contact of any kind. A
throwaway temp file stands in for the PROD private key (existence-checked
only, matching prod_config.py's contract) so load_prod_config() succeeds
during import, and paramiko.SSHClient.connect is patched to raise if
anything in this test file ever tries to actually open a socket.
"""
from __future__ import annotations

import ast
import importlib
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

_MODULE_NAME = "prod_commerce_config"


class ProdCommerceConfigTestCase(unittest.TestCase):
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

    def _fresh_import(self):
        saved = {mod: sys.modules.pop(mod, None) for mod in (_MODULE_NAME, "readonly_exec", "prod_config")}
        try:
            return importlib.import_module(_MODULE_NAME)
        finally:
            for mod, prior in saved.items():
                if mod not in sys.modules and prior is not None:
                    sys.modules[mod] = prior

    def _source(self) -> str:
        with open("prod_commerce_config.py", encoding="utf-8") as f:
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


class CredentialIsolationTests(ProdCommerceConfigTestCase):
    def test_import_does_not_open_a_socket(self):
        # setUp's paramiko.SSHClient.connect patcher raises if called; a
        # clean fresh import proves BastionSSHClient(...) at module scope
        # only stored config, exactly as ssh_client.py's __init__ does.
        mod = self._fresh_import()
        self.assertIsNotNone(mod._prod_commerce_ssh)

    def test_does_not_import_dev_uat_or_server_modules(self):
        imports = self._imports()
        self.assertNotIn("kube_core", imports)
        self.assertNotIn("commerce_tools", imports)
        self.assertNotIn("commerce_server", imports)
        self.assertNotIn("server", imports)
        self.assertNotIn("prod_server", imports)

    def test_does_not_call_dev_uat_load_configs(self):
        # AST-based, not a raw substring search: this module's docstring
        # legitimately mentions kube_core.py's `config.load_configs()` call
        # in prose (to document *why* kube_core.py is never imported), so a
        # naive substring check on the whole file text would false-positive
        # on that documentation. What actually matters is that no Call node
        # in the executable code targets load_configs.
        tree = ast.parse(self._source())
        call_names = {
            node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
        }
        self.assertNotIn("load_configs", call_names)

    def test_uses_prod_only_config_loader(self):
        source = self._source()
        self.assertIn("from prod_config import load_prod_config", source)

    def test_missing_prod_config_raises_configerror(self):
        os.environ.pop("PROD_BASTION_HOST", None)
        from config import ConfigError
        with self.assertRaises(ConfigError):
            self._fresh_import()

    def test_dev_uat_style_env_vars_have_no_effect(self):
        # Even with DEV/UAT-shaped vars present in the environment, this
        # module must still resolve exclusively from PROD_BASTION_* -
        # proving there is no fallback path that could cross-load a
        # DEV/UAT credential into this PROD-only process.
        os.environ["BASTION_HOST"] = "should-never-be-used"
        os.environ["UAT_BASTION_HOST"] = "should-never-be-used"
        mod = self._fresh_import()
        self.assertEqual(mod._prod_commerce_config.bastion_host, "10.13.96.105")

    def test_tag_is_distinct_from_eks_prod_readonly(self):
        mod = self._fresh_import()
        self.assertEqual(mod.TAG, "prod-commerce")
        self.assertNotEqual(mod.TAG, "prod")


class ReadonlyExecutionWrapperTests(ProdCommerceConfigTestCase):
    def test_run_prod_commerce_readonly_blocks_write_verbs(self):
        mod = self._fresh_import()
        from ssh_client import ReadOnlyViolation
        with self.assertRaises(ReadOnlyViolation):
            mod._prod_commerce_ssh.run_kubectl("kubectl delete pod foo -n commerce")

    def test_run_prod_commerce_readonly_is_a_thin_wrapper_over_existing_readonly_exec(self):
        # Confirm this is a pass-through to the existing, unmodified
        # readonly_exec.run_readonly() - not a reimplementation of SSH/
        # kubectl execution.
        source = self._source()
        self.assertIn("from readonly_exec import run_readonly", source)
        self.assertIn("run_readonly(_prod_commerce_ssh", source)


if __name__ == "__main__":
    unittest.main()
