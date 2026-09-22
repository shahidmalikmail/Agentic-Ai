"""Shared tool plumbing: error-to-result conversion and MCP registration."""
from __future__ import annotations

import functools
import logging
import time
from typing import Callable

from aws_cw_mcp.models.results import ToolResult, error_result
from aws_cw_mcp.utils.errors import describe_exception

logger = logging.getLogger("aws-cloudwatch-mcp")


def guarded(name: str, fn: Callable) -> Callable:
    """Wrap a tool so it always returns JSON text and never raises or leaks a traceback."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs) -> str:
        started = time.monotonic()
        try:
            result = fn(*args, **kwargs)
            if not isinstance(result, ToolResult):
                raise TypeError("tool returned a non-ToolResult")
            logger.info("tool=%s status=%s ms=%d", name, result.status,
                        int((time.monotonic() - started) * 1000))
            return result.to_json()
        except Exception as exc:  # noqa: BLE001 - converted to a structured error result
            info = describe_exception(exc)
            if info.kind == "internal_error":
                logger.exception("tool=%s internal error", name)
            else:
                logger.warning("tool=%s failed kind=%s code=%s", name, info.kind, info.code)
            return error_result(name, info).to_json()

    return wrapper


def register(mcp, tools: dict, *, idempotent: bool = True) -> None:
    """Register plain tool functions on an MCPServer with read-only annotations."""
    from mcp.types import ToolAnnotations

    ann = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=idempotent,
                          openWorldHint=False)
    for name, fn in tools.items():
        mcp.tool(name=name, annotations=ann)(fn)
