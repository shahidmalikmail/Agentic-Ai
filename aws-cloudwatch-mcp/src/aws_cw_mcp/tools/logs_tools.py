"""MCP tools: CloudWatch Logs (discovery, search, streams, events). Read-only."""
from __future__ import annotations

from typing import Optional

from aws_cw_mcp.runtime import Runtime
from aws_cw_mcp.tools.base import guarded
from aws_cw_mcp.utils.timerange import resolve_range


def build_tools(rt: Runtime) -> dict:
    cfg = rt.config

    def _range(lookback, start, end):
        return resolve_range(lookback=lookback, start=start, end=end,
                             default_minutes=cfg.default_lookback_minutes,
                             max_hours=cfg.max_log_time_range_hours)

    def aws_discover_log_groups(keyword: Optional[str] = None, category: Optional[str] = None,
                                name_prefix: Optional[str] = None, limit: int = 100) -> str:
        """Discover CloudWatch log groups (read-only). Filter by a name keyword and/or a category
        (hcl_commerce, solr, redis, nginx, eks, ec2, alb_nlb, cloudfront, waf, lambda, rds,
        vpc_flow, route53, sns_ses), or an exact name_prefix. Matching is by log-group name only
        (heuristic). Honors the LOG_GROUP_ALLOWLIST."""
        return rt.logs.discover(keyword=keyword, category=category, name_prefix=name_prefix, limit=limit)

    def aws_search_logs(log_groups: list[str], filter_pattern: str = "", lookback: Optional[str] = None,
                        start: Optional[str] = None, end: Optional[str] = None,
                        limit: Optional[int] = None, stream_prefix: Optional[str] = None) -> str:
        """Search CloudWatch log events (read-only, sanitized, capped). log_groups: exact names
        (max per call is configured). filter_pattern: CloudWatch filter syntax, e.g. 'ERROR' or
        '?timeout ?refused'. Time: lookback like '15m','1h','6h','24h' OR ISO start/end.
        Results are a capped sample; the response says when more events exist."""
        return rt.logs.search(log_groups, _range(lookback, start, end), filter_pattern=filter_pattern,
                              limit=limit, stream_prefix=stream_prefix)

    def aws_list_log_streams(log_group: str, prefix: Optional[str] = None, limit: int = 25) -> str:
        """List log streams of one log group (read-only), most recently active first unless a
        name prefix is given."""
        return rt.logs.list_streams(log_group, prefix=prefix, limit=limit)

    def aws_get_log_events(log_group: str, log_stream: str, lookback: Optional[str] = None,
                           start: Optional[str] = None, end: Optional[str] = None,
                           limit: Optional[int] = None, start_from_head: bool = False) -> str:
        """Read events from ONE log stream (read-only, sanitized, capped). Use
        aws_list_log_streams to find stream names. start_from_head=False returns the newest
        events in the window."""
        return rt.logs.get_events(log_group, log_stream, _range(lookback, start, end), limit=limit,
                                  start_from_head=start_from_head)

    raw = {f.__name__: f for f in (aws_discover_log_groups, aws_search_logs,
                                   aws_list_log_streams, aws_get_log_events)}
    return {name: guarded(name, fn) for name, fn in raw.items()}
