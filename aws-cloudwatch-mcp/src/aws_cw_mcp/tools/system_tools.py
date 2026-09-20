"""MCP tools: server/AWS connectivity health check. Read-only."""
from __future__ import annotations

from aws_cw_mcp import __version__
from aws_cw_mcp.aws.client import READ_ONLY_OPERATIONS, principal_type
from aws_cw_mcp.models.results import OK, ToolResult
from aws_cw_mcp.runtime import Runtime
from aws_cw_mcp.tools.base import guarded


def build_tools(rt: Runtime) -> dict:
    cfg = rt.config

    def aws_health_check() -> str:
        """Verify the MCP server can authenticate to AWS (sts:GetCallerIdentity) and report its
        effective read-only configuration and limits. Never returns credentials."""
        ident = rt.clients.verify_account()  # sts:GetCallerIdentity + pinned-account check
        facts = {
            "server_version": __version__,
            "aws_account": ident.get("account"),
            "aws_principal_arn": ident.get("arn"),
            "principal_type": principal_type(ident.get("arn")),
            "account_verified_against_pin": True,
            "region": cfg.aws_region,
            "profile": cfg.aws_profile,
            "pinned_account": cfg.aws_account_id,
            "log_group_allowlist": list(cfg.log_group_allowlist),
            "allowed_aws_operations": sorted(READ_ONLY_OPERATIONS),
            "limits": {
                "default_lookback_minutes": cfg.default_lookback_minutes,
                "max_log_results": cfg.max_log_results,
                "max_query_results": cfg.max_query_results,
                "max_log_time_range_hours": cfg.max_log_time_range_hours,
                "max_metric_time_range_hours": cfg.max_metric_time_range_hours,
                "max_log_groups_per_query": cfg.max_log_groups_per_query,
                "max_metric_queries": cfg.max_metric_queries,
                "max_pages": cfg.max_pages,
            },
        }
        return ToolResult("aws_health_check", OK,
                          f"Authenticated to AWS account {ident.get('account')} in {cfg.aws_region}.",
                          facts=facts,
                          analysis=["Credentials came from the standard AWS provider chain (named profile); values are never shown. This server "
                                    "can only call the read-only operations listed above."])

    return {"aws_health_check": guarded("aws_health_check", aws_health_check)}
