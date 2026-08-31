"""Local MCP server: Claude Desktop -> SSH to bastion -> read-only kubectl -> EKS.

Exposes a fixed set of read-only Kubernetes inspection tools. There is no
generic "run a command" tool, and no tool accepts a raw kubectl command from
the model - every kubectl invocation is assembled here from a hardcoded
resource name and a validated namespace, then re-checked against a
read-only allow-list in ssh_client.py before it is ever sent over SSH.

Every tool takes an explicit env parameter ("dev" default, or "uat") that
selects which pre-built SSH client handles the call - see _resolve_ssh().
There is no global "current environment" state and no environment-switching
tool; each call is self-contained and states its own target.

Transport is stdio (Claude Desktop launches this process and talks MCP over
stdin/stdout), so nothing but MCP protocol frames may ever go to stdout.
All diagnostics go to stderr via the logging module.
"""
from __future__ import annotations

import json
import logging
import re
import sys
from typing import Optional

from mcp.server.mcpserver import MCPServer

from config import ConfigError, load_configs
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
_POD_NAME_PATTERN = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
_CONTAINER_NAME_PATTERN = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
_DURATION_PATTERN = re.compile(r"^[1-9][0-9]*[smh]$")
_MAX_OUTPUT_CHARS = 120_000
_MAX_LOG_TAIL_LINES = 1000
_DEFAULT_LOG_TAIL_LINES = 100

try:
    _configs = load_configs()
except ConfigError as exc:
    logger.error("Configuration error: %s", exc)
    sys.exit(f"eks-readonly-mcp: configuration error: {exc}")

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


def _redact_secret(obj: dict) -> dict:
    obj = dict(obj)
    for field in ("data", "stringData"):
        if field in obj:
            obj[field] = {k: "<redacted>" for k in obj[field]}
    return obj


def _strip_secrets(raw: str, env: str) -> str:
    text = raw.split("\n", 1)[1] if raw.startswith("[env=") else raw
    payload = json.loads(text)
    if isinstance(payload, dict) and payload.get("kind") == "SecretList":
        payload["items"] = [_redact_secret(i) for i in payload.get("items", [])]
    elif isinstance(payload, dict) and payload.get("kind") == "Secret":
        payload = _redact_secret(payload)
    return f"[env={env}]\n" + json.dumps(payload, indent=2)


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


@mcp.tool()
def get_cluster_info(env: str = "dev") -> str:
    """Show EKS cluster endpoint and core service info (kubectl cluster-info).
    env selects the target cluster: 'dev' (default) or 'uat'."""
    return _run("kubectl cluster-info", env=env)


@mcp.tool()
def get_namespaces(env: str = "dev") -> str:
    """List all Kubernetes namespaces in the EKS cluster.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    return _run("kubectl get namespaces -o json", env=env)


@mcp.tool()
def get_nodes(env: str = "dev") -> str:
    """List all EKS worker nodes and their status/capacity.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    return _run("kubectl get nodes -o json", env=env)


@mcp.tool()
def get_pods(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List pods. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get pods {scope} -o json", env=env)


@mcp.tool()
def get_deployments(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List deployments. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get deployments {scope} -o json", env=env)


@mcp.tool()
def get_services(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List services. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get services {scope} -o json", env=env)


@mcp.tool()
def get_ingress(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List ingress resources. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get ingress {scope} -o json", env=env)


@mcp.tool()
def get_hpa(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List HorizontalPodAutoscalers. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get hpa {scope} -o json", env=env)


@mcp.tool()
def get_events(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List recent Kubernetes events. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get events {scope} -o json", env=env)


@mcp.tool()
def get_version(env: str = "dev") -> str:
    """Show kubectl client/server version info.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    return _run("kubectl version -o json", env=env)


@mcp.tool()
def get_api_resources(env: str = "dev") -> str:
    """List available Kubernetes API resource types on this cluster.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    return _run("kubectl api-resources -o wide", env=env)


@mcp.tool()
def get_replicasets(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List ReplicaSets. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get replicasets {scope} -o json", env=env)


@mcp.tool()
def get_statefulsets(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List StatefulSets. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get statefulsets {scope} -o json", env=env)


@mcp.tool()
def get_daemonsets(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List DaemonSets. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get daemonsets {scope} -o json", env=env)


@mcp.tool()
def get_jobs(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List Jobs. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get jobs {scope} -o json", env=env)


@mcp.tool()
def get_cronjobs(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List CronJobs. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get cronjobs {scope} -o json", env=env)


@mcp.tool()
def get_endpoints(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List Endpoints. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get endpoints {scope} -o json", env=env)


@mcp.tool()
def get_endpointslices(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List EndpointSlices. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get endpointslices {scope} -o json", env=env)


@mcp.tool()
def get_networkpolicies(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List NetworkPolicies. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get networkpolicies {scope} -o json", env=env)


@mcp.tool()
def get_pdb(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List PodDisruptionBudgets. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get poddisruptionbudgets {scope} -o json", env=env)


@mcp.tool()
def get_configmaps(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List ConfigMaps. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get configmaps {scope} -o json", env=env)


@mcp.tool()
def get_secrets_metadata(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List Secrets with metadata only. Values in data/stringData are always redacted, never returned.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    result = _run(f"kubectl get secrets {scope} -o json", env=env)
    if "Error:" in result:
        return result
    return _strip_secrets(result, env)


@mcp.tool()
def get_persistentvolumes(env: str = "dev") -> str:
    """List PersistentVolumes (cluster-scoped).
    env selects the target cluster: 'dev' (default) or 'uat'."""
    return _run("kubectl get persistentvolumes -o json", env=env)


@mcp.tool()
def get_persistentvolumeclaims(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List PersistentVolumeClaims. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get persistentvolumeclaims {scope} -o json", env=env)


@mcp.tool()
def get_storageclasses(env: str = "dev") -> str:
    """List StorageClasses (cluster-scoped).
    env selects the target cluster: 'dev' (default) or 'uat'."""
    return _run("kubectl get storageclasses -o json", env=env)


@mcp.tool()
def get_serviceaccounts(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List ServiceAccounts. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get serviceaccounts {scope} -o json", env=env)


@mcp.tool()
def get_roles(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List RBAC Roles. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get roles {scope} -o json", env=env)


@mcp.tool()
def get_rolebindings(namespace: Optional[str] = None, env: str = "dev") -> str:
    """List RBAC RoleBindings. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name.
    env selects the target cluster: 'dev' (default) or 'uat'."""
    try:
        scope = _scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return _run(f"kubectl get rolebindings {scope} -o json", env=env)


@mcp.tool()
def get_clusterroles(env: str = "dev") -> str:
    """List RBAC ClusterRoles (cluster-scoped).
    env selects the target cluster: 'dev' (default) or 'uat'."""
    return _run("kubectl get clusterroles -o json", env=env)


@mcp.tool()
def get_clusterrolebindings(env: str = "dev") -> str:
    """List RBAC ClusterRoleBindings (cluster-scoped).
    env selects the target cluster: 'dev' (default) or 'uat'."""
    return _run("kubectl get clusterrolebindings -o json", env=env)


@mcp.tool()
def get_pod_logs(
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


if __name__ == "__main__":
    logger.info(
        "Starting eks-readonly-mcp (environments configured: %s, k8s user=%s)",
        ", ".join(sorted(_configs)),
        next(iter(_configs.values())).kubernetes_user,
    )
    mcp.run(transport="stdio")
