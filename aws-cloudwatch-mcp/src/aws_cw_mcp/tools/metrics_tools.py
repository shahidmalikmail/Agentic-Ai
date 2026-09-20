"""MCP tools: CloudWatch metrics. Read-only."""
from __future__ import annotations

from typing import Optional

from aws_cw_mcp.runtime import Runtime
from aws_cw_mcp.tools.base import guarded
from aws_cw_mcp.utils.timerange import resolve_range


def build_tools(rt: Runtime) -> dict:
    cfg = rt.config

    def aws_list_metrics(namespace: Optional[str] = None, metric_name: Optional[str] = None,
                         dimensions: Optional[dict[str, str]] = None, limit: int = 100) -> str:
        """List available CloudWatch metrics (read-only). Requires at least one of namespace
        (e.g. 'AWS/ApplicationELB', 'AWS/EC2', 'CWAgent', 'ContainerInsights'), metric_name or
        dimensions (exact name->value filter). Use it to check whether a metric is actually being
        published before drawing conclusions."""
        return rt.metrics.list_metrics(namespace=namespace, metric_name=metric_name,
                                       dimensions=dimensions, limit=limit)

    def aws_get_metrics(metrics: list[dict], lookback: Optional[str] = None,
                        start: Optional[str] = None, end: Optional[str] = None,
                        period: Optional[int] = None, include_datapoints: bool = True) -> str:
        """Fetch CloudWatch metric statistics (read-only, no Metric Math). metrics: list of
        {"namespace": "AWS/EC2", "metric_name": "CPUUtilization", "stat": "Average"|"Sum"|"Maximum"|
        "p99"..., "dimensions": {"InstanceId": "i-..."}}. Time: lookback ('1h','24h','7d') or ISO
        start/end. period (seconds, multiple of 60) is auto-chosen if omitted. Returns
        datapoints plus calculated min/avg/p50/p90/p95/p99/max over the returned datapoints."""
        tr = resolve_range(lookback=lookback, start=start, end=end,
                           default_minutes=cfg.default_lookback_minutes,
                           max_hours=cfg.max_metric_time_range_hours)
        return rt.metrics.get_metrics(metrics, tr, period=period, include_datapoints=include_datapoints)

    raw = {f.__name__: f for f in (aws_list_metrics, aws_get_metrics)}
    return {name: guarded(name, fn) for name, fn in raw.items()}
