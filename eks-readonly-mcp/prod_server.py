"""Local MCP server: Claude Desktop -> SSH to the PROD bastion -> read-only
kubectl -> PROD EKS. This is the only MCP surface with PROD credentials.

Exposes exactly 12 read-only Kubernetes inspection tools, chosen for least
privilege from the 31 standard tools in server.py (see the eks-prod-readonly
P1 design report). No tool accepts an `env`/environment parameter of any
kind - the target cluster is fixed to PROD by construction: exactly one
BastionSSHClient (`_prod_ssh`) is built once at import time from
prod_config.load_prod_config(), held in a single module-level name, and
every tool reaches it only through readonly_exec.run_readonly(). There is
no environment dictionary, no environment resolver, and no fallback -
"choose an environment" is not an operation this module's code is capable
of, not merely one it validates against.

This process never imports config.py's DEV/UAT loader (`load_configs`),
kube_core.py, server.py, commerce_server.py, or commerce_tools.py, so it
never has DEV/UAT credentials in memory, and eks-readonly/eks-commerce
never have PROD credentials in memory (they never import prod_config.py).

Transport is stdio (Claude Desktop launches this process and talks MCP over
stdin/stdout), so nothing but MCP protocol frames may ever go to stdout.
All diagnostics go to stderr via the logging module.

get_pod_logs is deliberately NOT registered here: the standard
implementation (server.py) returns raw, unredacted log text, which is not
yet approved for PROD (see the P0 security report). Redacted PROD log
access, if ever added, is a separate future phase (P-LOG) - this file is
not to be extended with it without that explicit approval.

get_pods() uses a prevention-based control (P10.3J/P10.3K, see
prod_pod_columns.py): `kubectl get pods -o custom-columns=<fixed spec>`
instead of `-o json`, so env/envFrom/secret/configMap/service-account
token fields/labels/annotations are never requested from the API server
in the first place - there is no redaction step to get wrong. This
replaced the original P10.1 approach (`sanitize_pod_list_json()`, still
retained and tested in prod_pod_sanitizer.py but no longer used by any
PROD tool) after P10.3's live-PROD investigation found the raw `-o json`
response's top-level Kubernetes `kind` did not match this project's
narrow, intentional Pod/PodList allow-list (see the P10.3-P10.3J
investigation chain).

get_deployments()/get_replicasets()/get_statefulsets()/get_daemonsets()
now use the same prevention-based approach (P11/P11A/P11B, see
prod_workload_columns.py): a fixed `kubectl get <resource> -o
custom-columns=<fixed spec>` per resource type, replacing the original
P10.2 approach (`sanitize_workload_list_json()`, still retained and
tested in prod_pod_sanitizer.py but no longer used by any PROD tool)
after P11 found it left `spec.template.spec.volumes`, `imagePullSecrets`,
and container `command`/`args` completely unredacted - fields outside its
`env`/`envFrom`-only blacklist. No other PROD tool returns container
specs, so no other tool needs either treatment.

Constructing BastionSSHClient only stores its Config (see ssh_client.py);
no socket is opened by importing this module. The actual SSH connection
happens lazily, only when a tool is called and run_kubectl() executes.
"""
from __future__ import annotations

import logging
import sys
from typing import Optional

from mcp.server.mcpserver import MCPServer

from config import ConfigError
from prod_config import load_prod_config
from prod_pod_columns import POD_COLUMNS_SPEC, parse_get_pods_columns
from prod_workload_columns import (
    DAEMONSET_COLUMNS_SPEC,
    DEPLOYMENT_COLUMNS_SPEC,
    REPLICASET_COLUMNS_SPEC,
    STATEFULSET_COLUMNS_SPEC,
    parse_get_daemonsets_columns,
    parse_get_deployments_columns,
    parse_get_replicasets_columns,
    parse_get_statefulsets_columns,
)
from readonly_exec import run_readonly, scope_args
from ssh_client import BastionSSHClient

try:
    _prod_config = load_prod_config()
except ConfigError as exc:
    sys.exit(f"eks-prod-readonly-mcp: configuration error: {exc}")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("eks-prod-readonly-mcp")

# Exactly one PROD SSH client, built once at import time. There is no dict
# keyed by environment name and no second client of any kind in this
# process - this is what makes environment selection structurally
# impossible here, rather than merely validated away as it is for DEV/UAT
# in kube_core._resolve_ssh().
_prod_ssh = BastionSSHClient(_prod_config)

# Hardcoded literal, used only to label responses (e.g. "[prod]\n...").
# Never derived from tool input and never used to select a cluster.
_TAG = "prod"

mcp = MCPServer("eks-prod-readonly")


@mcp.tool()
def get_cluster_info() -> str:
    """Show EKS cluster endpoint and core service info (kubectl cluster-info). PROD only - this server has no other target."""
    return run_readonly(_prod_ssh, "kubectl cluster-info", tag=_TAG)


@mcp.tool()
def get_namespaces() -> str:
    """List all Kubernetes namespaces in the PROD EKS cluster."""
    return run_readonly(_prod_ssh, "kubectl get namespaces -o json", tag=_TAG)


@mcp.tool()
def get_nodes() -> str:
    """List all EKS worker nodes and their status/capacity in PROD."""
    return run_readonly(_prod_ssh, "kubectl get nodes -o json", tag=_TAG)


@mcp.tool()
def get_pods(namespace: Optional[str] = None) -> str:
    """List pods in PROD (P10.3K: prevention-based, via `kubectl -o
    custom-columns` - see prod_pod_columns.py). Returns name, namespace,
    phase, pod IP, node, and per-container name/image, plus pod-level
    readiness (ready_count/total_count) and restart (max) aggregates.
    Container `state` and pod `conditions` are not included - kubectl is
    never asked for env/envFrom/secret/configMap/serviceAccount-token
    fields/labels/annotations in the first place, so there is nothing to
    redact after the fact. Omit namespace (or pass 'all') for every
    namespace, or pass a specific namespace name."""
    try:
        scope = scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return run_readonly(
        _prod_ssh,
        f"kubectl get pods {scope} -o custom-columns={POD_COLUMNS_SPEC} --no-headers",
        tag=_TAG,
        sanitizer=parse_get_pods_columns,
    )


@mcp.tool()
def get_deployments(namespace: Optional[str] = None) -> str:
    """List deployments in PROD (P11B: prevention-based, via `kubectl -o
    custom-columns` - see prod_workload_columns.py). Returns name,
    namespace, desired/ready/available/updated replica counts, and
    per-container name/image. env/envFrom/volumes/imagePullSecrets/
    command/args/labels/annotations are never requested from the API
    server in the first place. Omit namespace (or pass 'all') for every
    namespace, or pass a specific namespace name."""
    try:
        scope = scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return run_readonly(
        _prod_ssh,
        f"kubectl get deployments {scope} -o custom-columns={DEPLOYMENT_COLUMNS_SPEC} --no-headers",
        tag=_TAG,
        sanitizer=parse_get_deployments_columns,
    )


@mcp.tool()
def get_services(namespace: Optional[str] = None) -> str:
    """List services in PROD. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name."""
    try:
        scope = scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return run_readonly(_prod_ssh, f"kubectl get services {scope} -o json", tag=_TAG)


@mcp.tool()
def get_events(namespace: Optional[str] = None) -> str:
    """List recent Kubernetes events in PROD. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name."""
    try:
        scope = scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return run_readonly(_prod_ssh, f"kubectl get events {scope} -o json", tag=_TAG)


@mcp.tool()
def get_version() -> str:
    """Show kubectl client/server version info for PROD."""
    return run_readonly(_prod_ssh, "kubectl version -o json", tag=_TAG)


@mcp.tool()
def get_hpa(namespace: Optional[str] = None) -> str:
    """List HorizontalPodAutoscalers in PROD. Omit namespace (or pass 'all') for every namespace, or pass a specific namespace name."""
    try:
        scope = scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return run_readonly(_prod_ssh, f"kubectl get hpa {scope} -o json", tag=_TAG)


@mcp.tool()
def get_replicasets(namespace: Optional[str] = None) -> str:
    """List ReplicaSets in PROD (P11B: prevention-based, via `kubectl -o
    custom-columns` - see prod_workload_columns.py). Returns name,
    namespace, desired/ready/available replica counts (`updated` is
    always null - ReplicaSets have no rolling-update concept), and
    per-container name/image. env/envFrom/volumes/imagePullSecrets/
    command/args/labels/annotations are never requested from the API
    server in the first place. Omit namespace (or pass 'all') for every
    namespace, or pass a specific namespace name."""
    try:
        scope = scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return run_readonly(
        _prod_ssh,
        f"kubectl get replicasets {scope} -o custom-columns={REPLICASET_COLUMNS_SPEC} --no-headers",
        tag=_TAG,
        sanitizer=parse_get_replicasets_columns,
    )


@mcp.tool()
def get_statefulsets(namespace: Optional[str] = None) -> str:
    """List StatefulSets in PROD (P11B: prevention-based, via `kubectl -o
    custom-columns` - see prod_workload_columns.py). Returns name,
    namespace, desired/ready/available/updated replica counts, and
    per-container name/image. env/envFrom/volumes/imagePullSecrets/
    command/args/labels/annotations are never requested from the API
    server in the first place. Omit namespace (or pass 'all') for every
    namespace, or pass a specific namespace name."""
    try:
        scope = scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return run_readonly(
        _prod_ssh,
        f"kubectl get statefulsets {scope} -o custom-columns={STATEFULSET_COLUMNS_SPEC} --no-headers",
        tag=_TAG,
        sanitizer=parse_get_statefulsets_columns,
    )


@mcp.tool()
def get_daemonsets(namespace: Optional[str] = None) -> str:
    """List DaemonSets in PROD (P11B: prevention-based, via `kubectl -o
    custom-columns` - see prod_workload_columns.py). Returns name,
    namespace, desired/ready/available/updated node-scheduling counts
    (DaemonSets have no replica concept - these map to
    desiredNumberScheduled/numberReady/numberAvailable/
    updatedNumberScheduled), and per-container name/image.
    env/envFrom/volumes/imagePullSecrets/command/args/labels/annotations
    are never requested from the API server in the first place. Omit
    namespace (or pass 'all') for every namespace, or pass a specific
    namespace name."""
    try:
        scope = scope_args(namespace)
    except ValueError as exc:
        return f"Error: {exc}"
    return run_readonly(
        _prod_ssh,
        f"kubectl get daemonsets {scope} -o custom-columns={DAEMONSET_COLUMNS_SPEC} --no-headers",
        tag=_TAG,
        sanitizer=parse_get_daemonsets_columns,
    )


if __name__ == "__main__":
    logger.info(
        "Starting eks-prod-readonly-mcp (PROD only, k8s user=%s)",
        _prod_config.kubernetes_user,
    )
    mcp.run(transport="stdio")
