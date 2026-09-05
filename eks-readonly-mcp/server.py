"""Local MCP server: Claude Desktop -> SSH to bastion -> read-only kubectl -> EKS.

Exposes a fixed set of read-only Kubernetes inspection tools. There is no
generic "run a command" tool, and no tool accepts a raw kubectl command from
the model - every kubectl invocation is assembled here from a hardcoded
resource name and a validated namespace, then re-checked against a
read-only allow-list in ssh_client.py before it is ever sent over SSH.

Every tool takes an explicit env parameter ("dev" default, or "uat") that
selects which pre-built SSH client handles the call - see kube_core._resolve_ssh().
There is no global "current environment" state and no environment-switching
tool; each call is self-contained and states its own target.

Transport is stdio (Claude Desktop launches this process and talks MCP over
stdin/stdout), so nothing but MCP protocol frames may ever go to stdout.
All diagnostics go to stderr via the logging module.

This server registers ONLY the 31 standard Kubernetes read-only tools. The
7 HCL Commerce diagnostic tools live on their own MCP surface - see
commerce_server.py - and are not imported or registered here.
"""
from __future__ import annotations

import json
import logging
import sys
from typing import Optional

from mcp.server.mcpserver import MCPServer

from config import ConfigError

try:
    from kube_core import (
        _DEFAULT_LOG_TAIL_LINES,
        _run,
        _scope_args,
        get_pod_logs_impl,
    )
except ConfigError as exc:
    sys.exit(f"eks-readonly-mcp: configuration error: {exc}")

logger = logging.getLogger("eks-readonly-mcp")

mcp = MCPServer("eks-readonly")


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
    return get_pod_logs_impl(
        namespace=namespace,
        pod=pod,
        container=container,
        tail_lines=tail_lines,
        previous=previous,
        since=since,
        env=env,
    )


if __name__ == "__main__":
    from kube_core import _configs

    logger.info(
        "Starting eks-readonly-mcp (environments configured: %s, k8s user=%s)",
        ", ".join(sorted(_configs)),
        next(iter(_configs.values())).kubernetes_user,
    )
    mcp.run(transport="stdio")
