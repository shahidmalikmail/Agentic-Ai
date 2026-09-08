"""PROD-only configuration loader.

Reads ONLY `PROD_BASTION_HOST`, `PROD_BASTION_PORT`, `PROD_BASTION_USER`,
`PROD_BASTION_KEY_PATH`, `KUBERNETES_USER`, `SSH_TIMEOUT`, and
`COMMAND_TIMEOUT` from the process environment. It never reads
`DEV_BASTION_*`, `UAT_BASTION_*`, or the legacy unprefixed `BASTION_*`
variables that config.py's dev fallback uses - there is no fallback of any
kind here. This module is intentionally separate from config.py (which
stays DEV/UAT-only and unmodified) so that a PROD credential can never end
up loaded into the same process as a DEV/UAT credential, and vice versa.

Only the `Config` dataclass and `ConfigError` exception are reused from
config.py; config.py's loading functions (`load_config`/`load_configs`) are
never called from here.
"""
from __future__ import annotations

import os
from typing import Optional

from config import Config, ConfigError

_REQUIRED = ("PROD_BASTION_HOST", "PROD_BASTION_USER", "PROD_BASTION_KEY_PATH", "KUBERNETES_USER")


def _env(name: str) -> Optional[str]:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return None
    return value


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got: {raw!r}") from exc


def load_prod_config() -> Config:
    """Load the PROD Config from PROD_BASTION_* environment variables only.

    Raises ConfigError if any required variable (PROD_BASTION_HOST,
    PROD_BASTION_USER, PROD_BASTION_KEY_PATH, KUBERNETES_USER) is
    missing/empty, if PROD_BASTION_PORT/SSH_TIMEOUT/COMMAND_TIMEOUT are set
    but not valid integers, or if PROD_BASTION_KEY_PATH does not point to an
    existing file. The key file's contents are never read by this
    function - only os.path.isfile() is used to check it exists."""
    values = {name: _env(name) for name in _REQUIRED}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise ConfigError(
            "Missing required PROD configuration: " + ", ".join(missing)
        )

    host = values["PROD_BASTION_HOST"]
    user = values["PROD_BASTION_USER"]
    key_path = values["PROD_BASTION_KEY_PATH"]
    kubernetes_user = values["KUBERNETES_USER"]

    if not os.path.isfile(key_path):
        raise ConfigError(
            f"PROD_BASTION_KEY_PATH does not point to an existing file: {key_path}"
        )

    return Config(
        bastion_host=host,
        bastion_port=_env_int("PROD_BASTION_PORT", 22),
        bastion_user=user,
        bastion_key_path=key_path,
        kubernetes_user=kubernetes_user,
        ssh_timeout=_env_int("SSH_TIMEOUT", 15),
        command_timeout=_env_int("COMMAND_TIMEOUT", 30),
    )
