"""Local MCP server: Claude Desktop -> SSH to the PROD bastion -> read-only
kubectl -> PROD EKS, HCL Commerce discovery/health/safe-logs (P12A + P12B).

Exposes exactly 3 read-only tools: list_prod_commerce_components and
get_prod_commerce_health (P12A, see prod_commerce_tools.py), plus
get_prod_commerce_logs (P12B, see prod_commerce_log_tools.py - returns
structured log EVIDENCE only, never a raw log line/body). No error
analysis, correlation, timeline, diagnosis, or recommendation capability
exists in this phase - those are explicitly deferred to a later,
separately-approved phase.

This process never imports config.py's DEV/UAT loader (`load_configs`),
kube_core.py, server.py, commerce_server.py, or commerce_tools.py, so it
never has DEV/UAT credentials in memory - the same isolation guarantee
prod_server.py already provides for eks-prod-readonly. It is a fully
separate MCP server/process from both eks-commerce and eks-prod-readonly.

Transport is stdio (Claude Desktop launches this process and talks MCP
over stdin/stdout), so nothing but MCP protocol frames may ever go to
stdout. All diagnostics go to stderr via the logging module.

This phase does NOT register this server with Claude Desktop - no
claude_desktop_config.json entry is added here or anywhere in P12A. That
is an explicitly separate, future, additive-only approval step.
"""
from __future__ import annotations

import logging
import sys

from mcp.server.mcpserver import MCPServer

from config import ConfigError

try:
    from prod_commerce_tools import register
    from prod_commerce_log_tools import register as register_logs
except ConfigError as exc:
    sys.exit(f"eks-prod-commerce-mcp: configuration error: {exc}")

logger = logging.getLogger("eks-prod-commerce-mcp")

mcp = MCPServer("eks-prod-commerce")
register(mcp)
register_logs(mcp)


if __name__ == "__main__":
    logger.info("Starting eks-prod-commerce-mcp (PROD only, Commerce discovery/health/safe-logs)")
    mcp.run(transport="stdio")
