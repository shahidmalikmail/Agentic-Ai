"""Local MCP server: Claude Desktop -> SSH to bastion -> read-only kubectl -> EKS.

Exposes ONLY the 7 HCL Commerce diagnostic tools (see commerce_tools.py for
their implementation and docstrings). The 31 standard Kubernetes read-only
tools live on a separate MCP surface - see server.py - and are not
imported or registered here.

Transport is stdio (Claude Desktop launches this process and talks MCP over
stdin/stdout), so nothing but MCP protocol frames may ever go to stdout.
All diagnostics go to stderr via the logging module.

This process shares the same read-only kubectl execution plumbing as
server.py (see kube_core.py) - it does not open any new kind of connection,
does not add any new kubectl verb, and does not add any write/remediation
capability.
"""
from __future__ import annotations

import logging
import sys

from mcp.server.mcpserver import MCPServer

from config import ConfigError

try:
    import kube_core
    from commerce_tools import register
except ConfigError as exc:
    sys.exit(f"eks-commerce-mcp: configuration error: {exc}")

logger = logging.getLogger("eks-commerce-mcp")

mcp = MCPServer("eks-commerce")
register(mcp)


if __name__ == "__main__":
    logger.info(
        "Starting eks-commerce-mcp (environments configured: %s, k8s user=%s)",
        ", ".join(sorted(kube_core._configs)),
        next(iter(kube_core._configs.values())).kubernetes_user,
    )
    mcp.run(transport="stdio")
