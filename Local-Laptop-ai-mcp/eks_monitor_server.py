from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import boto3
from kubernetes import client, config

try:
    from fastmcp import FastMCP
except ImportError:  # pragma: no cover - compatibility for older MCP setups
    from mcp.server.fastmcp import FastMCP

mcp = FastMCP("EKS Monitor Server")


def _get_kube_api() -> Dict[str, Any]:
    """Load kubeconfig and return Kubernetes API clients."""
    kubeconfig_path = os.getenv("KUBECONFIG")
    context = os.getenv("EKS_CONTEXT")

    try:
        if kubeconfig_path:
            config.load_kube_config(context=context, config_file=kubeconfig_path)
        else:
            config.load_kube_config(context=context)
    except Exception as exc:  # pragma: no cover - runtime environment issue
        raise RuntimeError(
            "Unable to load Kubernetes config. Set KUBECONFIG or ~/.kube/config and ensure your cluster context is valid. "
            f"Details: {exc}"
        ) from exc

    return {
        "core": client.CoreV1Api(),
        "apps": client.AppsV1Api(),
        "networking": client.NetworkingV1Api(),
        "autoscaling": client.AutoscalingV2Api(),
    }


def _safe_json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def _get_namespace_target(namespace: str) -> str:
    return namespace.strip() if namespace and namespace.lower() != "all" else "all"


@mcp.tool()
def describe_eks_cluster(cluster_name: Optional[str] = None) -> str:
    """Return AWS EKS cluster metadata for the configured cluster or the given name."""
    cluster_name = cluster_name or os.getenv("EKS_CLUSTER_NAME")
    if not cluster_name:
        return _safe_json({"error": "EKS_CLUSTER_NAME is not set. Pass cluster_name or export it in your environment."})

    region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"

    try:
        eks = boto3.client("eks", region_name=region)
        response = eks.describe_cluster(name=cluster_name)
        return _safe_json(response.get("cluster", {}))
    except Exception as exc:  # pragma: no cover - AWS call may fail at runtime
        return _safe_json({"error": f"Failed to describe EKS cluster '{cluster_name}' in region '{region}': {exc}"})


@mcp.tool()
def get_nodes() -> str:
    """List EKS node status, labels, capacity, and conditions."""
    try:
        core = _get_kube_api()["core"]
        nodes = core.list_node().items
        items: List[Dict[str, Any]] = []

        for node in nodes:
            ready = False
            conditions: Dict[str, Any] = {}
            labels = node.metadata.labels or {}
            for condition in (node.status.conditions or []):
                conditions[condition.type] = condition.status
                if condition.type == "Ready" and condition.status == "True":
                    ready = True

            items.append(
                {
                    "name": node.metadata.name,
                    "status": "Ready" if ready else "NotReady",
                    "version": getattr(node.status.node_info, "kubelet_version", None),
                    "instance_type": labels.get("beta.kubernetes.io/instance-type")
                        or labels.get("node.kubernetes.io/instance-type"),
                    "zone": labels.get("topology.kubernetes.io/zone"),
                    "cpu": getattr(node.status.capacity, "cpu", None),
                    "memory": getattr(node.status.capacity, "memory", None),
                    "conditions": conditions,
                }
            )

        return _safe_json({"count": len(items), "items": items})
    except Exception as exc:
        return _safe_json({"error": str(exc)})


@mcp.tool()
def get_pods(namespace: str = "all", status: Optional[str] = None) -> str:
    """List workloads and pod health for a namespace or all namespaces."""
    try:
        core = _get_kube_api()["core"]
        ns = _get_namespace_target(namespace)

        if ns == "all":
            pod_list = core.list_pod_for_all_namespaces()
        else:
            pod_list = core.list_namespaced_pod(namespace=ns)

        items: List[Dict[str, Any]] = []
        for item in pod_list.items:
            phase = item.status.phase or "Unknown"
            if status and phase.lower() != status.lower():
                continue

            container_statuses = []
            for container in (item.status.container_statuses or []):
                container_statuses.append(
                    {
                        "name": container.name,
                        "ready": container.ready,
                        "restart_count": container.restart_count,
                        "state": getattr(container.state, "waiting", None).reason if getattr(container.state, "waiting", None) else (
                            getattr(container.state, "terminated", None).reason if getattr(container.state, "terminated", None) else "Running"
                        ),
                    }
                )

            items.append(
                {
                    "namespace": item.metadata.namespace,
                    "name": item.metadata.name,
                    "phase": phase,
                    "ready": item.status.container_statuses and sum(1 for cs in item.status.container_statuses if cs.ready),
                    "total_containers": len(item.spec.containers),
                    "node": item.spec.node_name,
                    "restart_count": sum(cs.restart_count for cs in item.status.container_statuses or []),
                    "containers": container_statuses,
                    "owner_kind": (item.metadata.owner_references[0].kind if item.metadata.owner_references else None),
                    "owner_name": (item.metadata.owner_references[0].name if item.metadata.owner_references else None),
                }
            )

        return _safe_json({"namespace": ns, "count": len(items), "items": items})
    except Exception as exc:
        return _safe_json({"error": str(exc)})


@mcp.tool()
def get_services(namespace: str = "all") -> str:
    """List service exposure, type, ports, selectors, and endpoints."""
    try:
        core = _get_kube_api()["core"]
        ns = _get_namespace_target(namespace)

        if ns == "all":
            service_list = core.list_service_for_all_namespaces()
        else:
            service_list = core.list_namespaced_service(namespace=ns)

        items: List[Dict[str, Any]] = []
        for service in service_list.items:
            ports = [
                {"name": port.name, "port": port.port, "target_port": str(port.target_port), "protocol": port.protocol}
                for port in (service.spec.ports or [])
            ]
            items.append(
                {
                    "namespace": service.metadata.namespace,
                    "name": service.metadata.name,
                    "type": service.spec.type,
                    "cluster_ip": service.spec.cluster_ip,
                    "external_ips": service.spec.external_ips,
                    "selector": service.spec.selector,
                    "ports": ports,
                    "created_at": service.metadata.creation_timestamp,
                }
            )

        return _safe_json({"namespace": ns, "count": len(items), "items": items})
    except Exception as exc:
        return _safe_json({"error": str(exc)})


@mcp.tool()
def get_ingresses(namespace: str = "all") -> str:
    """List ingress rules, hosts, and backend services."""
    try:
        networking = _get_kube_api()["networking"]
        ns = _get_namespace_target(namespace)

        if ns == "all":
            ingress_list = networking.list_ingress_for_all_namespaces()
        else:
            ingress_list = networking.list_namespaced_ingress(namespace=ns)

        items: List[Dict[str, Any]] = []
        for ingress in ingress_list.items:
            rules: List[Dict[str, Any]] = []
            for rule in (ingress.spec.rules or []):
                rules.append(
                    {
                        "host": rule.host,
                        "http_paths": [
                            {
                                "path": path.path,
                                "path_type": path.path_type,
                                "backend_service": path.backend.service.name if path.backend and path.backend.service else None,
                            }
                            for path in (rule.http.paths if rule.http else [])
                        ],
                    }
                )

            items.append(
                {
                    "namespace": ingress.metadata.namespace,
                    "name": ingress.metadata.name,
                    "class": ingress.spec.ingress_class_name,
                    "hosts": [rule.host for rule in (ingress.spec.rules or [])],
                    "rules": rules,
                    "load_balancer": getattr(ingress.status.load_balancer, "ingress", None),
                }
            )

        return _safe_json({"namespace": ns, "count": len(items), "items": items})
    except Exception as exc:
        return _safe_json({"error": str(exc)})


@mcp.tool()
def get_hpas(namespace: str = "all") -> str:
    """List HorizontalPodAutoscalers and their current and desired replica targets."""
    try:
        autoscaling = _get_kube_api()["autoscaling"]
        ns = _get_namespace_target(namespace)

        if ns == "all":
            hpa_list = autoscaling.list_horizontal_pod_autoscaler_for_all_namespaces()
        else:
            hpa_list = autoscaling.list_namespaced_horizontal_pod_autoscaler(namespace=ns)

        items: List[Dict[str, Any]] = []
        for hpa in hpa_list.items:
            items.append(
                {
                    "namespace": hpa.metadata.namespace,
                    "name": hpa.metadata.name,
                    "target": {
                        "kind": hpa.spec.scale_target_ref.kind,
                        "name": hpa.spec.scale_target_ref.name,
                    },
                    "min_replicas": hpa.spec.min_replicas,
                    "max_replicas": hpa.spec.max_replicas,
                    "current_replicas": hpa.status.current_replicas,
                    "desired_replicas": hpa.status.desired_replicas,
                    "conditions": [
                        {"type": c.type, "status": c.status, "message": c.message}
                        for c in (hpa.status.conditions or [])
                    ],
                }
            )

        return _safe_json({"namespace": ns, "count": len(items), "items": items})
    except Exception as exc:
        return _safe_json({"error": str(exc)})


@mcp.tool()
def get_events(namespace: str = "all", limit: int = 50) -> str:
    """Return recent cluster events to diagnose failures, restarts, or scheduling issues."""
    try:
        core = _get_kube_api()["core"]
        ns = _get_namespace_target(namespace)

        if ns == "all":
            event_list = core.list_event_for_all_namespaces(limit=limit)
        else:
            event_list = core.list_namespaced_event(namespace=ns, limit=limit)

        events = []
        for event in event_list.items:
            events.append(
                {
                    "namespace": event.metadata.namespace,
                    "involved_object": {
                        "kind": event.involved_object.kind,
                        "name": event.involved_object.name,
                    },
                    "reason": event.reason,
                    "message": event.message,
                    "type": event.type,
                    "count": event.count,
                    "last_timestamp": str(event.last_timestamp),
                }
            )

        return _safe_json({"namespace": ns, "count": len(events), "items": events})
    except Exception as exc:
        return _safe_json({"error": str(exc)})


@mcp.tool()
def get_cluster_health_summary() -> str:
    """Return a single cluster-level summary with counts and warnings for key EKS resources."""
    try:
        apis = _get_kube_api()
        core = apis["core"]
        networking = apis["networking"]
        autoscaling = apis["autoscaling"]

        nodes = json.loads(get_nodes())
        pods = json.loads(get_pods(namespace="all"))
        services = json.loads(get_services(namespace="all"))
        ingresses = json.loads(get_ingresses(namespace="all"))
        hpas = json.loads(get_hpas(namespace="all"))
        events = json.loads(get_events(namespace="all", limit=20))

        node_ready = len([n for n in (nodes.get("items") or []) if n.get("status") == "Ready"])
        phases = {}
        for pod in (pods.get("items") or []):
            phases[pod.get("phase", "Unknown")] = phases.get(pod.get("phase", "Unknown"), 0) + 1

        warnings: List[str] = []
        critical: List[str] = []

        if nodes.get("count", 0) == 0:
            warnings.append("No Kubernetes nodes were found.")
        elif node_ready < nodes.get("count", 0):
            warnings.append(f"{nodes.get('count', 0) - node_ready} node(s) are not Ready.")

        failed_pods = [p for p in (pods.get("items") or []) if p.get("phase") not in {"Running", "Succeeded", "Completed"}]
        if failed_pods:
            critical.append(f"{len(failed_pods)} pod(s) are not in a healthy state.")

        if services.get("count", 0) == 0:
            warnings.append("No Services were found in the cluster.")

        if ingresses.get("count", 0) == 0:
            warnings.append("No Ingresses were found in the cluster.")

        if hpas.get("count", 0) == 0:
            warnings.append("No HorizontalPodAutoscalers were found.")

        if events.get("count", 0) > 0:
            recent_error_events = [e for e in events.get("items", []) if e.get("type") == "Warning"]
            if recent_error_events:
                warnings.append(f"{len(recent_error_events)} warning event(s) are recent.")

        summary = {
            "cluster": {
                "nodes_total": nodes.get("count", 0),
                "nodes_ready": node_ready,
                "pods_total": pods.get("count", 0),
                "pod_phase_distribution": phases,
                "services_total": services.get("count", 0),
                "ingresses_total": ingresses.get("count", 0),
                "hpas_total": hpas.get("count", 0),
            },
            "warnings": warnings,
            "critical": critical,
            "status": "Healthy" if not critical else "Degraded",
        }

        return _safe_json(summary)
    except Exception as exc:
        return _safe_json({"error": str(exc)})


if __name__ == "__main__":
    mcp.run()
