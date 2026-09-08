"""Tests for prod_config.py's PROD-only configuration loader.

No network access, no SSH, no real PROD key. The "key file" used in these
tests is a throwaway temp file created solely so os.path.isfile() succeeds -
its contents are never meaningful and load_prod_config() must never read
them (see test_key_file_only_existence_checked_not_read).
"""
from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from config import ConfigError
import prod_config

_MANAGED_KEYS = (
    "PROD_BASTION_HOST",
    "PROD_BASTION_PORT",
    "PROD_BASTION_USER",
    "PROD_BASTION_KEY_PATH",
    "KUBERNETES_USER",
    "SSH_TIMEOUT",
    "COMMAND_TIMEOUT",
    "BASTION_HOST",
    "BASTION_PORT",
    "BASTION_USER",
    "BASTION_KEY_PATH",
    "DEV_BASTION_HOST",
    "DEV_BASTION_PORT",
    "DEV_BASTION_USER",
    "DEV_BASTION_KEY_PATH",
    "UAT_BASTION_HOST",
    "UAT_BASTION_PORT",
    "UAT_BASTION_USER",
    "UAT_BASTION_KEY_PATH",
)


class ProdConfigTestCase(unittest.TestCase):
    """Snapshots os.environ around every test and creates a throwaway,
    existing key file so tests only need to opt in to the variables they
    care about."""

    def setUp(self):
        self._patcher = patch.dict(os.environ, {}, clear=False)
        self._patcher.start()
        for key in _MANAGED_KEYS:
            os.environ.pop(key, None)

        fd, self._tmp_key_path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(b"not a real private key - existence check only")
        self.addCleanup(os.unlink, self._tmp_key_path)

    def tearDown(self):
        self._patcher.stop()

    def _set(self, **overrides):
        os.environ.update(overrides)

    def _set_valid_prod(self, **overrides):
        base = {
            "PROD_BASTION_HOST": "10.13.96.105",
            "PROD_BASTION_USER": "ubuntu",
            "PROD_BASTION_KEY_PATH": self._tmp_key_path,
            "KUBERNETES_USER": "solveda",
        }
        base.update(overrides)
        self._set(**base)


class ValidConfigurationTests(ProdConfigTestCase):
    def test_valid_configuration_loads(self):
        self._set_valid_prod()
        cfg = prod_config.load_prod_config()
        self.assertEqual(cfg.bastion_host, "10.13.96.105")
        self.assertEqual(cfg.bastion_user, "ubuntu")
        self.assertEqual(cfg.bastion_key_path, self._tmp_key_path)
        self.assertEqual(cfg.kubernetes_user, "solveda")
        self.assertEqual(cfg.bastion_port, 22)
        self.assertEqual(cfg.ssh_timeout, 15)
        self.assertEqual(cfg.command_timeout, 30)

    def test_explicit_port_and_timeouts_respected(self):
        self._set_valid_prod(
            PROD_BASTION_PORT="2222",
            SSH_TIMEOUT="45",
            COMMAND_TIMEOUT="90",
        )
        cfg = prod_config.load_prod_config()
        self.assertEqual(cfg.bastion_port, 2222)
        self.assertEqual(cfg.ssh_timeout, 45)
        self.assertEqual(cfg.command_timeout, 90)


class MissingRequiredValueTests(ProdConfigTestCase):
    def test_missing_host_raises(self):
        self._set_valid_prod()
        os.environ.pop("PROD_BASTION_HOST")
        with self.assertRaises(ConfigError):
            prod_config.load_prod_config()

    def test_missing_user_raises(self):
        self._set_valid_prod()
        os.environ.pop("PROD_BASTION_USER")
        with self.assertRaises(ConfigError):
            prod_config.load_prod_config()

    def test_missing_key_path_raises(self):
        self._set_valid_prod()
        os.environ.pop("PROD_BASTION_KEY_PATH")
        with self.assertRaises(ConfigError):
            prod_config.load_prod_config()

    def test_missing_kubernetes_user_raises(self):
        self._set_valid_prod()
        os.environ.pop("KUBERNETES_USER")
        with self.assertRaises(ConfigError):
            prod_config.load_prod_config()

    def test_empty_string_host_treated_as_missing(self):
        self._set_valid_prod(PROD_BASTION_HOST="   ")
        with self.assertRaises(ConfigError):
            prod_config.load_prod_config()

    def test_nothing_configured_raises(self):
        with self.assertRaises(ConfigError):
            prod_config.load_prod_config()


class InvalidValueTests(ProdConfigTestCase):
    def test_invalid_port_raises(self):
        self._set_valid_prod(PROD_BASTION_PORT="not-a-port")
        with self.assertRaises(ConfigError):
            prod_config.load_prod_config()

    def test_invalid_ssh_timeout_raises(self):
        self._set_valid_prod(SSH_TIMEOUT="soon")
        with self.assertRaises(ConfigError):
            prod_config.load_prod_config()

    def test_invalid_command_timeout_raises(self):
        self._set_valid_prod(COMMAND_TIMEOUT="never")
        with self.assertRaises(ConfigError):
            prod_config.load_prod_config()

    def test_nonexistent_key_path_raises(self):
        self._set_valid_prod(PROD_BASTION_KEY_PATH=r"C:\definitely\not\a\real\path.pem")
        with self.assertRaises(ConfigError):
            prod_config.load_prod_config()


class NoFallbackTests(ProdConfigTestCase):
    def test_legacy_unprefixed_bastion_vars_do_not_satisfy_prod(self):
        self._set(
            BASTION_HOST="10.11.80.131",
            BASTION_USER="ubuntu",
            BASTION_KEY_PATH=self._tmp_key_path,
            KUBERNETES_USER="solveda",
        )
        with self.assertRaises(ConfigError):
            prod_config.load_prod_config()

    def test_dev_variables_do_not_satisfy_prod(self):
        self._set(
            DEV_BASTION_HOST="10.11.80.131",
            DEV_BASTION_USER="ubuntu",
            DEV_BASTION_KEY_PATH=self._tmp_key_path,
            KUBERNETES_USER="solveda",
        )
        with self.assertRaises(ConfigError):
            prod_config.load_prod_config()

    def test_dev_variables_ignored_even_when_prod_also_configured(self):
        self._set_valid_prod()
        self._set(
            DEV_BASTION_HOST="10.11.80.131",
            DEV_BASTION_USER="dev-ubuntu",
            DEV_BASTION_KEY_PATH=self._tmp_key_path,
        )
        cfg = prod_config.load_prod_config()
        self.assertEqual(cfg.bastion_host, "10.13.96.105")
        self.assertEqual(cfg.bastion_user, "ubuntu")

    def test_uat_variables_do_not_satisfy_prod(self):
        self._set(
            UAT_BASTION_HOST="10.12.80.197",
            UAT_BASTION_USER="ubuntu",
            UAT_BASTION_KEY_PATH=self._tmp_key_path,
            KUBERNETES_USER="solveda",
        )
        with self.assertRaises(ConfigError):
            prod_config.load_prod_config()

    def test_uat_variables_ignored_even_when_prod_also_configured(self):
        self._set_valid_prod()
        self._set(
            UAT_BASTION_HOST="10.12.80.197",
            UAT_BASTION_USER="uat-ubuntu",
            UAT_BASTION_KEY_PATH=self._tmp_key_path,
        )
        cfg = prod_config.load_prod_config()
        self.assertEqual(cfg.bastion_host, "10.13.96.105")
        self.assertEqual(cfg.bastion_user, "ubuntu")


class KeyFileNotReadTests(ProdConfigTestCase):
    def test_key_file_only_existence_checked_not_read(self):
        self._set_valid_prod()
        real_open = open
        opened_paths = []

        def tracking_open(file, *args, **kwargs):
            opened_paths.append(file)
            return real_open(file, *args, **kwargs)

        with patch("builtins.open", side_effect=tracking_open):
            cfg = prod_config.load_prod_config()

        self.assertEqual(cfg.bastion_key_path, self._tmp_key_path)
        self.assertNotIn(self._tmp_key_path, opened_paths)


if __name__ == "__main__":
    unittest.main()
