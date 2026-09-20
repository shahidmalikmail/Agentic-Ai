"""Environment-driven configuration. Holds no secrets: AWS credentials always
come from the standard boto3 credential provider chain, in the local deployment
via a named AWS CLI profile (AWS_PROFILE). Keys are never read from config."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional


class ConfigError(Exception):
    """Invalid or missing configuration."""


# Absolute ceilings: even a misconfigured .env cannot lift limits past these.
_HARD_CEILINGS = {
    "max_log_results": 2000,
    "max_query_results": 5000,
    "max_log_time_range_hours": 24 * 7,
    "max_metric_time_range_hours": 24 * 90,
    "max_log_groups_per_query": 20,
    "max_metric_queries": 20,
    "max_pages": 50,
    "max_datapoints_returned": 1000,
    "max_message_chars": 4000,
    "max_response_chars": 200_000,
}


@dataclass(frozen=True)
class Config:
    aws_region: str
    aws_profile: Optional[str] = None
    aws_account_id: Optional[str] = None
    log_group_allowlist: tuple = ()
    default_lookback_minutes: int = 60
    max_log_results: int = 200
    max_query_results: int = 1000
    max_log_time_range_hours: int = 24
    max_metric_time_range_hours: int = 720
    max_log_groups_per_query: int = 5
    max_metric_queries: int = 10
    max_pages: int = 10
    max_datapoints_returned: int = 200
    max_message_chars: int = 800
    max_response_chars: int = 60_000
    cache_ttl_seconds: int = 60
    api_connect_timeout: int = 5
    api_read_timeout: int = 30
    api_max_attempts: int = 5
    log_level: str = "INFO"


def _int(env: Mapping[str, str], name: str, default: int, *, minimum: int = 1,
         ceiling: Optional[int] = None) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        value = default
    else:
        try:
            value = int(raw.strip())
        except ValueError:
            raise ConfigError(f"{name} must be an integer, got {raw!r}") from None
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    if ceiling is not None and value > ceiling:
        raise ConfigError(f"{name} must be <= {ceiling} (hard safety ceiling), got {value}")
    return value


def load_dotenv_file(env_file: Optional[str] = None) -> None:
    """Load a .env file into os.environ without overriding existing variables."""
    try:
        from dotenv import load_dotenv
    except ImportError:  # python-dotenv is optional at runtime
        return
    path = env_file or os.environ.get("AWS_CW_MCP_ENV_FILE")
    if path:
        load_dotenv(path, override=False)
        return
    default = Path(__file__).resolve().parents[2] / ".env"
    if default.is_file():
        load_dotenv(default, override=False)


def load_config(env: Optional[Mapping[str, str]] = None, *, require_account_id: bool = False) -> Config:
    """Build the config. Real execution (server startup) passes require_account_id=True so the
    server can never run without an account pin; unit tests may omit it."""
    env = os.environ if env is None else env

    region = (env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION") or "").strip()
    if not region:
        raise ConfigError("AWS_REGION is not set (example: AWS_REGION=us-east-1)")
    if not re.fullmatch(r"[a-z]{2}(-[a-z]+)+-\d", region):
        raise ConfigError(f"AWS_REGION does not look like a region name: {region!r}")

    account = (env.get("AWS_ACCOUNT_ID") or "").strip() or None
    if require_account_id and not account:
        raise ConfigError("AWS_ACCOUNT_ID is required (12-digit account the profile must resolve to); "
                          "the server refuses to run AWS operations without it")
    if account and not re.fullmatch(r"\d{12}", account):
        raise ConfigError("AWS_ACCOUNT_ID must be a 12-digit account id")

    allow = tuple(p.strip() for p in (env.get("LOG_GROUP_ALLOWLIST") or "").split(",") if p.strip())

    level = (env.get("LOG_LEVEL") or "INFO").strip().upper()
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        raise ConfigError(f"LOG_LEVEL must be DEBUG/INFO/WARNING/ERROR, got {level!r}")

    c = _HARD_CEILINGS
    return Config(
        aws_region=region,
        aws_profile=(env.get("AWS_PROFILE") or "").strip() or None,
        aws_account_id=account,
        log_group_allowlist=allow,
        default_lookback_minutes=_int(env, "DEFAULT_LOOKBACK_MINUTES", 60, ceiling=24 * 60),
        max_log_results=_int(env, "MAX_LOG_RESULTS", 200, ceiling=c["max_log_results"]),
        max_query_results=_int(env, "MAX_QUERY_RESULTS", 1000, ceiling=c["max_query_results"]),
        max_log_time_range_hours=_int(env, "MAX_LOG_TIME_RANGE_HOURS", 24,
                                      ceiling=c["max_log_time_range_hours"]),
        max_metric_time_range_hours=_int(env, "MAX_METRIC_TIME_RANGE_HOURS", 720,
                                         ceiling=c["max_metric_time_range_hours"]),
        max_log_groups_per_query=_int(env, "MAX_LOG_GROUPS_PER_QUERY", 5,
                                      ceiling=c["max_log_groups_per_query"]),
        max_metric_queries=_int(env, "MAX_METRIC_QUERIES", 10, ceiling=c["max_metric_queries"]),
        max_pages=_int(env, "MAX_PAGES", 10, ceiling=c["max_pages"]),
        max_datapoints_returned=_int(env, "MAX_DATAPOINTS_RETURNED", 200,
                                     ceiling=c["max_datapoints_returned"]),
        max_message_chars=_int(env, "MAX_MESSAGE_CHARS", 800, ceiling=c["max_message_chars"]),
        max_response_chars=_int(env, "MAX_RESPONSE_CHARS", 60_000, ceiling=c["max_response_chars"]),
        cache_ttl_seconds=_int(env, "CACHE_TTL_SECONDS", 60, minimum=0, ceiling=3600),
        api_connect_timeout=_int(env, "AWS_API_CONNECT_TIMEOUT", 5, ceiling=60),
        api_read_timeout=_int(env, "AWS_API_READ_TIMEOUT", 30, ceiling=120),
        api_max_attempts=_int(env, "AWS_API_MAX_ATTEMPTS", 5, ceiling=10),
        log_level=level,
    )
