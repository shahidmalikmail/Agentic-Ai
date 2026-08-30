"""Data models shared across activities and workflows.

Plain dataclasses only (no methods that do I/O) so Temporal's default
data converter can serialize/deserialize them across the workflow/activity
boundary, and so workflow code can safely call the pure formatting helper
below without breaking determinism.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class BastionConnectionResult:
    connected: bool
    message: str
    kubectl_client_version: str = ""
    cluster_info: str = ""
    aws_identity: str = ""


@dataclass
class NamespaceHealth:
    name: str
    status: str = "HEALTHY"  # HEALTHY | WARNING | CRITICAL
    pod_count: int = 0
    issues: List[str] = field(default_factory=list)


@dataclass
class NodeSummary:
    ready_count: int = 0
    not_ready_count: int = 0
    node_conditions: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ClusterSnapshot:
    collected_at: str
    cluster_reachable: bool = True
    namespaces: List[str] = field(default_factory=list)
    nodes: NodeSummary = field(default_factory=NodeSummary)
    namespace_health: Dict[str, NamespaceHealth] = field(default_factory=dict)
    ingress_healthy: bool = True
    services_healthy: bool = True
    critical_issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    healthy_components: List[str] = field(default_factory=list)
    collection_errors: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    overall_health: str = "UNKNOWN"  # HEALTHY | WARNING | CRITICAL | UNKNOWN
    critical_issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    healthy_components: List[str] = field(default_factory=list)
    affected_namespace: str = ""
    affected_resource: str = ""
    likely_reason: str = ""
    recommended_investigation: List[str] = field(default_factory=list)
    ai_summary: str = ""
    raw_response: str = ""


def format_health_report(
    bastion: Optional[BastionConnectionResult],
    snapshot: Optional[ClusterSnapshot],
    analysis: Optional[AnalysisResult],
    error: str = "",
) -> str:
    """Pure, deterministic formatting - safe to call from workflow code."""
    lines: List[str] = []
    lines.append("EKS CLUSTER HEALTH")

    if error:
        lines.append("Status: ERROR")
        lines.append("")
        lines.append(f"Error: {error}")
        return "\n".join(lines)

    overall = analysis.overall_health if analysis else "UNKNOWN"
    lines.append(f"Status: {overall}")
    lines.append("")

    if snapshot and snapshot.namespace_health:
        lines.append("Namespaces:")
        for ns_name in sorted(snapshot.namespace_health):
            lines.append(f"{ns_name}: {snapshot.namespace_health[ns_name].status}")
        lines.append("")

    critical = analysis.critical_issues if analysis else (snapshot.critical_issues if snapshot else [])
    if critical:
        lines.append("Critical Issues:")
        for item in critical:
            lines.append(f"* {item}")
        lines.append("")

    warnings = analysis.warnings if analysis else (snapshot.warnings if snapshot else [])
    if warnings:
        lines.append("Warnings:")
        for item in warnings:
            lines.append(f"* {item}")
        lines.append("")

    if snapshot:
        lines.append("Nodes:")
        lines.append(f"{snapshot.nodes.ready_count} Ready")
        lines.append(f"{snapshot.nodes.not_ready_count} NotReady")
        lines.append("")
        lines.append("Ingress:")
        lines.append("Healthy" if snapshot.ingress_healthy else "Issues detected")
        lines.append("")
        lines.append("Services:")
        lines.append("Healthy" if snapshot.services_healthy else "Issues detected")
        lines.append("")

    if analysis:
        lines.append(f"AI Analysis: {analysis.ai_summary}")
        lines.append("")
        if analysis.affected_namespace or analysis.affected_resource:
            lines.append(f"Affected Namespace: {analysis.affected_namespace or 'n/a'}")
            lines.append(f"Affected Resource: {analysis.affected_resource or 'n/a'}")
            lines.append("")
        if analysis.likely_reason:
            lines.append(f"Likely Reason: {analysis.likely_reason}")
            lines.append("")
        if analysis.recommended_investigation:
            lines.append("Recommended Investigation:")
            for cmd in analysis.recommended_investigation:
                lines.append(f"* {cmd}")

    return "\n".join(lines)
