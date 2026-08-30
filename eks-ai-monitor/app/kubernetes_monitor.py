"""Read-only Kubernetes/EKS data collection, run through the bastion SSH client.

Every kubectl invocation here uses `-o json` so output is parsed
structurally instead of scraped from table text. All commands issued
are read-only (get/describe/top/version/cluster-info) - the SSH layer
independently enforces this via an allow-list.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.config import MonitorConfig
from app.models import ClusterSnapshot, NamespaceHealth, NodeSummary
from app.ssh_client import BastionSSHClient, RemoteCommandError

logger = logging.getLogger(__name__)

_CRASH_REASONS = {"CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError"}
_RESTART_WARNING_THRESHOLD = 5
_HPA_NEAR_MAX_RATIO = 0.9


class MalformedOutputError(Exception):
    """Raised when kubectl output cannot be parsed as JSON."""


def _kubectl_json(
    ssh: BastionSSHClient,
    resource: str,
    timeout: int,
    namespace: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    ns_flag = f"-n {namespace}" if namespace else "-A"
    command = f"kubectl get {resource} {ns_flag} -o json"
    result = ssh.run(command, timeout=timeout)
    if not result.ok:
        raise RemoteCommandError(f"kubectl get {resource} failed: {result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise MalformedOutputError(f"Could not parse JSON for '{command}': {exc}") from exc


def verify_connectivity(ssh: BastionSSHClient, timeout: int) -> Dict[str, str]:
    version = ssh.run_or_raise("kubectl version --output=json", timeout=timeout)
    cluster_info = ssh.run_or_raise("kubectl cluster-info", timeout=timeout)
    identity = ssh.run_or_raise("aws sts get-caller-identity", timeout=timeout)
    logger.info("[EKS] Connectivity OK")
    return {
        "kubectl_client_version": version.stdout.strip(),
        "cluster_info": cluster_info.stdout.strip(),
        "aws_identity": identity.stdout.strip(),
    }


def discover_namespaces(ssh: BastionSSHClient, timeout: int) -> List[str]:
    data = _kubectl_json(ssh, "namespaces", timeout)
    names = [item["metadata"]["name"] for item in (data or {}).get("items", [])]
    logger.info(f"[EKS] Namespaces discovered: {len(names)}")
    return names


def collect_nodes(ssh: BastionSSHClient, timeout: int) -> NodeSummary:
    logger.info("[EKS] Collecting nodes...")
    summary = NodeSummary()
    try:
        data = _kubectl_json(ssh, "nodes", timeout)
    except (RemoteCommandError, MalformedOutputError) as exc:
        logger.error(f"[EKS] Failed to collect nodes: {exc}")
        return summary

    for node in (data or {}).get("items", []):
        name = node.get("metadata", {}).get("name", "unknown")
        conditions = node.get("status", {}).get("conditions", [])
        ready = False
        for cond in conditions:
            if cond.get("type") == "Ready" and cond.get("status") == "True":
                ready = True
            if cond.get("type") in {"MemoryPressure", "DiskPressure", "PIDPressure"} and cond.get("status") == "True":
                summary.node_conditions.append({"node": name, "condition": cond.get("type")})
        if ready:
            summary.ready_count += 1
        else:
            summary.not_ready_count += 1
            summary.node_conditions.append({"node": name, "condition": "NotReady"})

    return summary


def _analyze_pods(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    issues: List[str] = []
    warnings: List[str] = []
    pending = 0
    failed = 0
    crashloop = 0
    not_ready = 0

    for pod in items:
        name = pod.get("metadata", {}).get("name", "unknown")
        phase = pod.get("status", {}).get("phase", "Unknown")

        if phase == "Pending":
            pending += 1
            issues.append(f"pod {name} Pending")
        elif phase == "Failed":
            failed += 1
            issues.append(f"pod {name} Failed")

        container_statuses = pod.get("status", {}).get("containerStatuses", []) or []
        for cs in container_statuses:
            restart_count = cs.get("restartCount", 0)
            if restart_count > _RESTART_WARNING_THRESHOLD:
                warnings.append(f"pod {name} container {cs.get('name')} restarted {restart_count} times")

            waiting = cs.get("state", {}).get("waiting")
            if waiting and waiting.get("reason") in _CRASH_REASONS:
                crashloop += 1
                issues.append(f"pod {name} container {cs.get('name')} {waiting.get('reason')}")

            if not cs.get("ready", True) and phase == "Running":
                not_ready += 1

    return {
        "issues": issues,
        "warnings": warnings,
        "pending": pending,
        "failed": failed,
        "crashloop": crashloop,
        "not_ready": not_ready,
        "count": len(items),
    }


def _analyze_replica_owning(items: List[Dict[str, Any]], kind: str) -> List[str]:
    issues: List[str] = []
    for item in items:
        name = item.get("metadata", {}).get("name", "unknown")
        status = item.get("status", {})
        desired = item.get("spec", {}).get("replicas", status.get("desiredNumberScheduled", 0))
        available = status.get("availableReplicas", status.get("numberAvailable", status.get("readyReplicas", 0))) or 0
        if desired and available < desired:
            issues.append(f"{kind} {name} desired={desired} available={available}")
    return issues


def _analyze_hpa(items: List[Dict[str, Any]]) -> List[str]:
    warnings: List[str] = []
    for hpa in items:
        name = hpa.get("metadata", {}).get("name", "unknown")
        status = hpa.get("status", {})
        current = status.get("currentReplicas", 0)
        max_replicas = hpa.get("spec", {}).get("maxReplicas", 0)
        if max_replicas and current >= max_replicas * _HPA_NEAR_MAX_RATIO:
            warnings.append(f"hpa {name} near max replicas ({current}/{max_replicas})")
    return warnings


def _analyze_ingress(items: List[Dict[str, Any]]) -> bool:
    for ing in items:
        lb = ing.get("status", {}).get("loadBalancer", {})
        if not lb.get("ingress"):
            return False
    return True


def collect_namespace_health(
    ssh: BastionSSHClient,
    namespace: str,
    timeout: int,
    collection_errors: List[str],
) -> NamespaceHealth:
    health = NamespaceHealth(name=namespace)

    def safe_get(resource: str) -> List[Dict[str, Any]]:
        try:
            data = _kubectl_json(ssh, resource, timeout, namespace=namespace)
            return (data or {}).get("items", [])
        except (RemoteCommandError, MalformedOutputError) as exc:
            collection_errors.append(f"{namespace}/{resource}: {exc}")
            return []

    pods = safe_get("pods")
    pod_analysis = _analyze_pods(pods)
    health.pod_count = pod_analysis["count"]
    health.issues.extend(pod_analysis["issues"])

    deployments = safe_get("deployments")
    health.issues.extend(_analyze_replica_owning(deployments, "deployment"))

    statefulsets = safe_get("statefulsets")
    health.issues.extend(_analyze_replica_owning(statefulsets, "statefulset"))

    daemonsets = safe_get("daemonsets")
    health.issues.extend(_analyze_replica_owning(daemonsets, "daemonset"))

    hpas = safe_get("hpa")
    hpa_warnings = _analyze_hpa(hpas)

    if pod_analysis["issues"] or pod_analysis["crashloop"] or pod_analysis["failed"]:
        health.status = "CRITICAL"
    elif health.issues or hpa_warnings or pod_analysis["warnings"]:
        health.status = "WARNING"
    else:
        health.status = "HEALTHY"

    health.issues.extend(hpa_warnings)
    health.issues.extend(pod_analysis["warnings"])

    return health


def collect_cluster_snapshot(ssh: BastionSSHClient, config: MonitorConfig) -> ClusterSnapshot:
    timeout = config.kubectl_timeout
    snapshot = ClusterSnapshot(collected_at=datetime.now(timezone.utc).isoformat())

    try:
        namespaces = discover_namespaces(ssh, timeout)
    except (RemoteCommandError, MalformedOutputError) as exc:
        snapshot.cluster_reachable = False
        snapshot.collection_errors.append(f"namespace discovery failed: {exc}")
        return snapshot

    snapshot.namespaces = namespaces
    snapshot.nodes = collect_nodes(ssh, timeout)
    if snapshot.nodes.not_ready_count > 0:
        snapshot.warnings.append(f"{snapshot.nodes.not_ready_count} node(s) NotReady")

    logger.info("[EKS] Collecting pods...")
    for ns in namespaces:
        ns_health = collect_namespace_health(ssh, ns, timeout, snapshot.collection_errors)
        snapshot.namespace_health[ns] = ns_health
        if ns_health.status == "CRITICAL":
            snapshot.critical_issues.extend(f"[{ns}] {issue}" for issue in ns_health.issues)
        elif ns_health.status == "WARNING":
            snapshot.warnings.extend(f"[{ns}] {issue}" for issue in ns_health.issues)
        else:
            snapshot.healthy_components.append(ns)

    logger.info("[EKS] Collecting HPA...")
    try:
        ingress_data = _kubectl_json(ssh, "ingress", timeout)
        snapshot.ingress_healthy = _analyze_ingress((ingress_data or {}).get("items", []))
    except (RemoteCommandError, MalformedOutputError) as exc:
        snapshot.collection_errors.append(f"ingress check failed: {exc}")

    try:
        services_data = _kubectl_json(ssh, "services", timeout)
        snapshot.services_healthy = len((services_data or {}).get("items", [])) > 0
    except (RemoteCommandError, MalformedOutputError) as exc:
        snapshot.collection_errors.append(f"services check failed: {exc}")

    return snapshot
