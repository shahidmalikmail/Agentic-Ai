"""Configuration loaded from environment variables only.

No secrets are hardcoded. Values come from the process environment,
optionally populated from a local .env file (python-dotenv) for manual
testing. Claude Desktop normally supplies these via the "env" block in
claude_desktop_config.json.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv

# Loading .env here (not in server.py) keeps server.py free of any stdout
# side effects; load_dotenv() itself never prints to stdout/stderr.
load_dotenv()


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class Config:
    bastion_host: str
    bastion_port: int
    bastion_user: str
    bastion_key_path: str
    kubernetes_user: str
    ssh_timeout: int
    command_timeout: int


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got: {raw!r}") from exc


def load_config() -> Config:
    bastion_host = _env("BASTION_HOST")
    bastion_user = _env("BASTION_USER")
    kubernetes_user = _env("KUBERNETES_USER")
    key_path = _env("BASTION_KEY_PATH")

    if not bastion_host:
        raise ConfigError("BASTION_HOST is required (set it in your environment or .env file)")
    if not bastion_user:
        raise ConfigError("BASTION_USER is required (set it in your environment or .env file)")
    if not kubernetes_user:
        raise ConfigError("KUBERNETES_USER is required (set it in your environment or .env file)")
    if not key_path:
        raise ConfigError("BASTION_KEY_PATH is required (set it in your environment or .env file)")
    if not os.path.isfile(key_path):
        raise ConfigError(
            f"BASTION_KEY_PATH does not point to an existing file: {key_path}"
        )

    return Config(
        bastion_host=bastion_host,
        bastion_port=_env_int("BASTION_PORT", 22),
        bastion_user=bastion_user,
        bastion_key_path=key_path,
        kubernetes_user=kubernetes_user,
        ssh_timeout=_env_int("SSH_TIMEOUT", 15),
        command_timeout=_env_int("COMMAND_TIMEOUT", 30),
    )


# Environments this server can route to. Deliberately excludes "prod" for
# now - add it here only in a separate, explicitly approved change.
_ENV_PREFIXES = {"dev": "DEV", "uat": "UAT"}


def _load_env_config(prefix: str, allow_legacy_fallback: bool) -> Optional[Config]:
    """Load one environment's Config from <PREFIX>_BASTION_* variables.

    Returns None if none of that environment's variables are set (the
    environment is simply not configured yet - not an error). Raises
    ConfigError if some but not all of HOST/USER/KEY_PATH are set, since
    that is almost always a typo, not an intentional partial setup.
    """
    host = _env(f"{prefix}_BASTION_HOST")
    user = _env(f"{prefix}_BASTION_USER")
    key_path = _env(f"{prefix}_BASTION_KEY_PATH")
    port_raw = _env(f"{prefix}_BASTION_PORT")

    if allow_legacy_fallback and not any((host, user, key_path)):
        host, user, key_path, port_raw = (
            _env("BASTION_HOST"),
            _env("BASTION_USER"),
            _env("BASTION_KEY_PATH"),
            _env("BASTION_PORT"),
        )

    fields = {"HOST": host, "USER": user, "KEY_PATH": key_path}
    if not any(fields.values()):
        return None
    missing = [name for name, value in fields.items() if not value]
    if missing:
        raise ConfigError(
            f"{prefix}_BASTION_* is partially configured - missing "
            f"{', '.join(f'{prefix}_BASTION_{name}' for name in missing)}."
        )
    if not os.path.isfile(key_path):
        raise ConfigError(
            f"{prefix}_BASTION_KEY_PATH does not point to an existing file: {key_path}"
        )

    kubernetes_user = _env("KUBERNETES_USER")
    if not kubernetes_user:
        raise ConfigError("KUBERNETES_USER is required (set it in your environment or .env file)")

    port = 22
    if port_raw:
        try:
            port = int(port_raw)
        except ValueError as exc:
            raise ConfigError(
                f"{prefix}_BASTION_PORT must be an integer, got: {port_raw!r}"
            ) from exc

    return Config(
        bastion_host=host,
        bastion_port=port,
        bastion_user=user,
        bastion_key_path=key_path,
        kubernetes_user=kubernetes_user,
        ssh_timeout=_env_int("SSH_TIMEOUT", 15),
        command_timeout=_env_int("COMMAND_TIMEOUT", 30),
    )


def load_configs() -> dict[str, Config]:
    """Load one Config per supported environment (currently: dev, uat).

    'dev' falls back to the legacy unprefixed BASTION_* variables if
    DEV_BASTION_* are not set, so existing single-environment setups keep
    working unchanged. 'uat' has no such fallback - it must use UAT_BASTION_*.
    """
    configs: dict[str, Config] = {}
    for env_name, prefix in _ENV_PREFIXES.items():
        cfg = _load_env_config(prefix, allow_legacy_fallback=(env_name == "dev"))
        if cfg is not None:
            configs[env_name] = cfg
    if "dev" not in configs:
        raise ConfigError(
            "No usable configuration found for 'dev' (checked DEV_BASTION_* and "
            "legacy BASTION_* variables)."
        )
    return configs
