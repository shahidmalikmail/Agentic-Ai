"""Local MCP server: Claude Desktop -> SSH to bastion -> read-only kubectl -> EKS.

Exposes a fixed set of read-only Kubernetes inspection tools. There is no
generic "run a command" tool, and no tool accepts a raw kubectl command from
the model - every kubectl invocation is assembled here from a hardcoded
resource name and a validated namespace, then re-checked against a
read-only allow-list in ssh_client.py before it is ever sent over SSH.

Transport is stdio (Claude Desktop launches this process and talks MCP over
stdin/stdout), so nothing but MCP protocol frames may ever go to stdout.
All diagnostics go to stderr via the logging module.
"""
from __future__ import annotations

import logging
import re
import sys
from typing import Optional

from mcp.server.mcpserver import MCPServer

from config import ConfigError, load_config
from ssh_client import (
    BastionConnectionError,
    BastionSSHClient,
    CommandTimeoutError,
    ReadOnlyViolation,
)

# Never touch stdout: it is reserved for MCP protocol frames.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("eks-readonly-mcp")

_NAMESPACE_PATTERN = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
_MAX_OUTPUT_CHARS = 120_000

try:
    _config = load_config()
except ConfigError as exc:
    logger.error("Configuration error: %s", exc)
    sys.exit(f"eks-readonly-mcp: configuration error: {exc}")

_ssh = BastionSSHClient(_config)

mcp = MCPServer("eks-readonly")


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


def _run(kubectl_command: str) -> str:
    try:
        result = _ssh.run_kubectl(kubectl_command)
    except ReadOnlyViolation as exc:
        logger.error("Blocked non-read-only command: %s", exc)
        return f"Error: this request was blocked by the read-only guard ({exc})."
    except BastionConnectionError as exc:
        logger.error("Bastion connection failed: %s", exc)
        return (
            "Error: could not connect to the bastion. Check that the VPN is "
            f"connected and the bastion is reachable. Details: {exc}"
        )
    except CommandTimeoutError as exc:
        logger.error("Command timed out: %s", exc)
        return f"Error: {exc}"

    if not result.ok:
        logger.warning("kubectl exited %s for: %s", result.exit_code, result.command)
        stderr = result.stderr.strip() or "(no stderr output)"
        return f"Error: kubectl failed (exit {result.exit_code}): {stderr}"

    output = result.stdout
    if len(output) > _MAX_OUTPUT_CHARS:
        output = output[:_MAX_OUTPUT_CHARS] + "\n...(output truncated)"
    return output or "(empty result - no matching resources)"


@mcp.tool()
def get_cluster_info() -> str:
    """Show EKS cluster endpoint and core service info (kubectl cluster-info)."""
    return _run("kubectl cluster-info")


@mcp.tool()
def get_namespaces() -> str:
    """List all Kubernetes namespaces in the EKS cluster."""
    return _run("kubectl get namespaces -o json")


@mcp.tool()
def get_nodes() -> str:
    """List all EKS worker nodes and their status/capacity."""
    return _run("kubectl get nodes -o json")


@mcp.tool()
def get_pods(namespace: Optional[str] = None) -> str:
    """List pods. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get pods {scope} -o json")


@mcp.tool()
def get_deployments(namespace: Optional[str] = None) -> str:
    """List deployments. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get deployments {scope} -o json")


@mcp.tool()
def get_services(namespace: Optional[str] = None) -> str:
    """List services. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get services {scope} -o json")


@mcp.tool()
def get_ingress(namespace: Optional[str] = None) -> str:
    """List ingress resources. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get ingress {scope} -o json")


@mcp.tool()
def get_hpa(namespace: Optional[str] = None) -> str:
    """List HorizontalPodAutoscalers. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get hpa {scope} -o json")


@mcp.tool()
def get_events(namespace: Optional[str] = None) -> str:
    """List recent Kubernetes events. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get events {scope} -o json")


if __name__ == "__main__":
    logger.info("Starting eks-readonly-mcp (bastion=%s, k8s user=%s)", _config.bastion_host, _config.kubernetes_user)
    mcp.run(transport="stdio")
