"""Log-group existence/retention lookup for Insights, using the Phase 1 identity (never the Insights one)."""
from __future__ import annotations

from aws_cw_mcp.utils.errors import NotFoundError


class LogsGroupCatalog:
    """Adapter over Phase 1's LogsService (DescribeLogGroups). The Insights IAM identity deliberately has
    no DescribeLogGroups permission, so discovery/existence/retention always come through Phase 1.

    Takes a zero-argument PROVIDER (not the service) so nothing is created, and no AWS call is made, until
    a group is actually checked: aws_insights_budget_status must stay purely local."""

    def __init__(self, logs_provider):
        self._provider = logs_provider

    def check(self, names) -> dict:
        """Return {group: retention_days|None}; NotFoundError if any group does not exist."""
        logs = self._provider()
        found: dict = {}
        missing = []
        for name in names:
            records = logs.list_group_records(name)            # prefix lookup, cached
            match = next((r for r in records if r.get("name") == name), None)
            if match is None:
                missing.append(name)
            else:
                found[name] = match.get("retention_days")
        if missing:
            raise NotFoundError("Log group(s) not found or not visible: " + ", ".join(missing[:5])
                                + ". Use aws_discover_log_groups to list valid names.")
        return found
