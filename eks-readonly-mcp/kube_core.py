"""Shared, non-MCP Kubernetes execution/helper layer.

This module holds ONLY the read-only kubectl execution plumbing that both
MCP servers need:

- eks-readonly (server.py, 31 standard Kubernetes tools)
- eks-commerce (commerce_server.py + commerce_tools.py, 7 HCL Commerce
  diagnostic tools)

It contains no MCPServer instance, no @mcp.tool() registrations, and no
mcp.run() call - it is a plain, importable Python module, usable exactly
like any other helper module. The read-only allow-list enforcement itself
still lives entirely in ssh_client.py; this module never bypasses it, it
only ever calls BastionSSHClient.run_kubectl().

Transport-sensitive processes that import this module must still keep
stdout reserved for MCP protocol frames - this module itself never writes
to stdout, only to stderr via the logging module.
"""
from __future__ import annotations

import logging
import re
import sys
from typing import Optional

from config import ConfigError, load_configs
from ssh_client import (
    BastionConnectionError,
    BastionSSHClient,
    CommandTimeoutError,
    ReadOnlyViolation,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("kube-core")

_NAMESPACE_PATTERN = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
_POD_NAME_PATTERN = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
_CONTAINER_NAME_PATTERN = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
_DURATION_PATTERN = re.compile(r"^[1-9][0-9]*[smh]$")
_MAX_OUTPUT_CHARS = 120_000
_MAX_LOG_TAIL_LINES = 1000
_DEFAULT_LOG_TAIL_LINES = 100

# Raises ConfigError on failure - callers (server.py / commerce_server.py)
# catch it around their import of this module to fail fast with their own
# process-specific message.
_configs = load_configs()

_ssh_clients = {env_name: BastionSSHClient(cfg) for env_name, cfg in _configs.items()}

# Environments this server can route to. Deliberately excludes "prod" for
# now - it will be added here only in a separate, explicitly approved change.
_ALLOWED_ENVS = ("dev", "uat")


def _resolve_ssh(env: str) -> BastionSSHClient:
    """Look up the SSH client for a validated environment name.

    Raises ValueError for anything not in _ALLOWED_ENVS, or for an allowed
    name that has no configuration loaded (e.g. 'uat' before its env vars
    are set). Never falls back to a different environment.
    """
    key = (env or "").strip().lower()
    if key not in _ALLOWED_ENVS:
        raise ValueError(f"Invalid env {env!r}: must be one of {', '.join(_ALLOWED_ENVS)}.")
    client = _ssh_clients.get(key)
    if client is None:
        raise ValueError(
            f"Environment {key!r} is not configured on this server "
            f"(no {key.upper()}_BASTION_* variables set)."
        )
    return client


def _validate_namespace(namespace: Optional[str]) -> Optional[str]:
    """Return None for "all namespaces", or a validated namespace string.

    Raises ValueError for anything that isn't a syntactically valid
    Kubernetes namespace name (RFC 1123 DNS label).
    """
    if namespace is None:
        return None
    ns = namespace.strip()
    if ns == "" or ns.lower() == "all":
        return None
    if not _NAMESPACE_PATTERN.match(ns):
        raise ValueError(
            f"Invalid namespace {namespace!r}: must be a valid Kubernetes namespace "
            "name (lowercase alphanumeric and '-', max 63 chars), or omitted/'all'."
        )
    return ns


def _scope_args(namespace: Optional[str]) -> str:
    validated = _validate_namespace(namespace)
    return "-A" if validated is None else f"-n {validated}"


def _validate_required_namespace(namespace: str) -> str:
    ns = _validate_namespace(namespace)
    if ns is None:
        raise ValueError("a specific namespace is required (not 'all').")
    return ns


def _validate_name(value: str, pattern: re.Pattern, label: str) -> str:
    v = (value or "").strip()
    if not v or not pattern.match(v):
        raise ValueError(f"Invalid {label} {value!r}: must be a valid Kubernetes name.")
    return v


def _run(kubectl_command: str, env: str = "dev") -> str:
    try:
        ssh = _resolve_ssh(env)
    except ValueError as exc:
        return f"[env={env}] Error: {exc}"

    try:
        result = ssh.run_kubectl(kubectl_command)
    except ReadOnlyViolation as exc:
        logger.error("Blocked non-read-only command: %s", exc)
        return f"[env={env}] Error: this request was blocked by the read-only guard ({exc})."
    except BastionConnectionError as exc:
        logger.error("Bastion connection failed: %s", exc)
        return (
            f"[env={env}] Error: could not connect to the bastion. Check that the VPN is "
            f"connected and the bastion is reachable. Details: {exc}"
        )
    except CommandTimeoutError as exc:
        logger.error("Command timed out: %s", exc)
        return f"[env={env}] Error: {exc}"

    if not result.ok:
        logger.warning("kubectl exited %s for: %s", result.exit_code, result.command)
        stderr = result.stderr.strip() or "(no stderr output)"
        return f"[env={env}] Error: kubectl failed (exit {result.exit_code}): {stderr}"

    output = result.stdout
    if len(output) > _MAX_OUTPUT_CHARS:
        output = output[:_MAX_OUTPUT_CHARS] + "\n...(output truncated)"
    body = output or "(empty result - no matching resources)"
    return f"[env={env}]\n{body}"


def get_pod_logs_impl(
    namespace: str,
    pod: str,
    container: Optional[str] = None,
    tail_lines: int = _DEFAULT_LOG_TAIL_LINES,
    previous: bool = False,
    since: Optional[str] = None,
    env: str = "dev",
) -> str:
    """Get logs for a pod in a specific namespace (namespace and pod are required).
    tail_lines defaults to 100, max 1000. previous=True gets the last terminated
    container's logs (e.g. after a crash). since accepts a duration like '10m'/'2h'.
    If the pod has multiple containers, kubectl will report the valid container
    names in the error - pass one via `container`.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        ns = _validate_required_namespace(namespace)
        pod = _validate_name(pod, _POD_NAME_PATTERN, "pod name")
        if container is not None:
            container = _validate_name(container, _CONTAINER_NAME_PATTERN, "container name")
        if since is not None and since.strip() and not _DURATION_PATTERN.match(since.strip()):
            raise ValueError(f"invalid since {since!r}; use a duration like '10m', '2h', '30s'.")
    except ValueError as exc:
        return f"Error: {exc}"

    try:
        tail = max(1, min(int(tail_lines), _MAX_LOG_TAIL_LINES))
    except (TypeError, ValueError):
        return f"Error: tail_lines must be an integer, got {tail_lines!r}."

    cmd = f"kubectl logs {pod} -n {ns} --tail={tail}"
    if container:
        cmd += f" -c {container}"
    if previous:
        cmd += " --previous"
    if since and since.strip():
        cmd += f" --since={since.strip()}"
    return _run(cmd, env=env)
