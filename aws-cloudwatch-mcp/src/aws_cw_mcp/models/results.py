"""Structured result envelope.

Every tool returns the same shape so the model can always separate:
  FACT            - values read directly from AWS
  ANALYSIS        - values/notes derived (calculated) from those facts
  RECOMMENDATION  - suggestions for a human engineer; NEVER executed by this server
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

RECOMMENDATION_PREFIX = "RECOMMENDATION (human decision required; nothing was executed): "
READ_ONLY_NOTICE = ("This server is strictly read-only. It never changes AWS or Kubernetes "
                    "resources; recommendations are suggestions only.")

OK, EMPTY, PARTIAL, ERROR = "ok", "empty", "partial", "error"


@dataclass
class ToolResult:
    tool: str
    status: str
    summary: str
    facts: Any = field(default_factory=dict)
    analysis: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    error: Optional[dict] = None
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d: dict = {
            "tool": self.tool,
            "status": self.status,
            "read_only": True,
            "summary": self.summary,
            "FACT": self.facts,
            "ANALYSIS": self.analysis,
            "RECOMMENDATION": [
                r if r.startswith("RECOMMENDATION") else RECOMMENDATION_PREFIX + r
                for r in self.recommendations
            ],
            "warnings": self.warnings,
            "meta": self.meta,
            "notice": READ_ONLY_NOTICE,
        }
        if self.error:
            d["error"] = self.error
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


def error_result(tool: str, info, meta: Optional[dict] = None) -> ToolResult:
    """Build an error result from an ErrorInfo. Never fabricates data."""
    unavailable = info.kind in {"access_denied", "not_found"}
    prefix = ("No CloudWatch data is currently available for this request "
              f"({info.kind}). " if unavailable else f"The request failed ({info.kind}). ")
    return ToolResult(tool=tool, status=ERROR, summary=prefix + info.message, facts={},
                      error=info.as_dict(), meta=meta or {})
