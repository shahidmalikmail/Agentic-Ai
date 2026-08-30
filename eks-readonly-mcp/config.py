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
