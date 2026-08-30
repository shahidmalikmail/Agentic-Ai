"""Central configuration, loaded from environment variables only.

No secrets are ever hardcoded here. Values come from the process
environment, optionally populated from a local .env file by the
entrypoint scripts (worker.py / start_monitor.py) via python-dotenv.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


@dataclass(frozen=True)
class TemporalConfig:
    host: str
    namespace: str
    task_queue: str


@dataclass(frozen=True)
class BastionConfig:
    host: str
    port: int
    username: str
    key_path: Optional[str]
    password: Optional[str]
    connect_timeout: int
    command_timeout: int


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    model: str
    api_key: Optional[str]


@dataclass(frozen=True)
class MonitorConfig:
    interval_seconds: int
    kubectl_timeout: int


@dataclass(frozen=True)
class AppConfig:
    temporal: TemporalConfig
    bastion: BastionConfig
    llm: LLMConfig
    monitor: MonitorConfig


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got: {raw!r}") from exc


def load_config() -> AppConfig:
    temporal = TemporalConfig(
        host=_env("TEMPORAL_HOST", "localhost:7233"),
        namespace=_env("TEMPORAL_NAMESPACE", "default"),
        task_queue=_env("TEMPORAL_TASK_QUEUE", "eks-monitor-task-queue"),
    )

    bastion_host = _env("BASTION_HOST")
    bastion_username = _env("BASTION_USERNAME")
    if not bastion_host:
        raise ConfigError("BASTION_HOST is required (set it in your .env file)")
    if not bastion_username:
        raise ConfigError("BASTION_USERNAME is required (set it in your .env file)")

    key_path = _env("BASTION_KEY_PATH")
    password = _env("BASTION_PASSWORD")
    if not key_path and not password:
        raise ConfigError(
            "Either BASTION_KEY_PATH or BASTION_PASSWORD must be set. "
            "Key-based auth is strongly recommended; password auth is opt-in only."
        )

    bastion = BastionConfig(
        host=bastion_host,
        port=_env_int("BASTION_PORT", 22),
        username=bastion_username,
        key_path=key_path,
        password=password,
        connect_timeout=_env_int("BASTION_CONNECT_TIMEOUT_SECONDS", 15),
        command_timeout=_env_int("BASTION_COMMAND_TIMEOUT_SECONDS", 30),
    )

    llm = LLMConfig(
        provider=_env("LLM_PROVIDER", "anthropic"),
        model=_env("ANTHROPIC_MODEL", "claude-opus-5"),
        api_key=_env("ANTHROPIC_API_KEY"),
    )

    monitor = MonitorConfig(
        interval_seconds=_env_int("MONITOR_INTERVAL_SECONDS", 300),
        kubectl_timeout=_env_int("KUBECTL_TIMEOUT_SECONDS", 30),
    )

    return AppConfig(temporal=temporal, bastion=bastion, llm=llm, monitor=monitor)
