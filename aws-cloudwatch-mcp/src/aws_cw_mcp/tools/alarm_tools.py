"""MCP tools: CloudWatch alarms. Read-only."""
from __future__ import annotations

from typing import Optional

from aws_cw_mcp.runtime import Runtime
from aws_cw_mcp.tools.base import guarded
from aws_cw_mcp.utils.timerange import resolve_range


def build_tools(rt: Runtime) -> dict:
    cfg = rt.config

    def aws_get_alarms(state: Optional[str] = None, name_prefix: Optional[str] = None,
                       include_composite: bool = True, limit: int = 100) -> str:
        """List CloudWatch alarms and their current state (read-only). state: OK, ALARM or
        INSUFFICIENT_DATA. Alarm actions/ARNs are not returned."""
        return rt.alarms.get_alarms(state=state, name_prefix=name_prefix,
                                    include_composite=include_composite, limit=limit)

    def aws_get_alarm_history(alarm_name: str, lookback: Optional[str] = "24h",
                              start: Optional[str] = None, end: Optional[str] = None,
                              history_type: Optional[str] = None, limit: int = 100) -> str:
        """State-change / action / configuration history of ONE alarm (read-only).
        history_type: StateUpdate, Action or ConfigurationUpdate. Default window: 24h."""
        tr = resolve_range(lookback=None if start else lookback, start=start, end=end,
                           default_minutes=cfg.default_lookback_minutes,
                           max_hours=cfg.max_metric_time_range_hours)
        return rt.alarms.get_history(alarm_name, tr, history_type=history_type, limit=limit)

    raw = {f.__name__: f for f in (aws_get_alarms, aws_get_alarm_history)}
    return {name: guarded(name, fn) for name, fn in raw.items()}
