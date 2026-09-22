"""Runtime container: config + lazily-built AWS clients and services.

Phase 2+ services (Logs Insights, WAF, CloudFront, ...) plug in here as new
lazy properties and new modules under aws_cw_mcp/tools/.
"""
from __future__ import annotations

import atexit
import dataclasses
from typing import Optional

from aws_cw_mcp.aws.client import AwsClients
from aws_cw_mcp.aws.cloudwatch import AlarmsService, MetricsService
from aws_cw_mcp.aws.logs import LogsService
from aws_cw_mcp.config import Config
from aws_cw_mcp.utils.cache import TTLCache
from aws_cw_mcp.utils.errors import InsightsDisabled


class Runtime:
    def __init__(self, config: Config, clients: Optional[AwsClients] = None, *,
                 insights_clients=None, insights_executor=None):
        self.config = config
        self.clients = clients or AwsClients(config)
        self._insights_clients = insights_clients
        self._insights_logs: Optional[LogsService] = None
        self._insights = insights_executor
        self._cache = TTLCache(config.cache_ttl_seconds)
        self._logs: Optional[LogsService] = None
        self._metrics: Optional[MetricsService] = None
        self._alarms: Optional[AlarmsService] = None

    @property
    def logs(self) -> LogsService:
        if self._logs is None:
            self._logs = LogsService(self.clients.logs(), self.config, self._cache)
        return self._logs

    @property
    def metrics(self) -> MetricsService:
        if self._metrics is None:
            self._metrics = MetricsService(self.clients.cloudwatch(), self.config, self._cache)
        return self._metrics

    @property
    def alarms(self) -> AlarmsService:
        if self._alarms is None:
            self._alarms = AlarmsService(self.clients.cloudwatch(), self.config)
        return self._alarms

    # ---- Phase 2A: Logs Insights (only built when INSIGHTS_ENABLED=true; nothing is created otherwise) ----
    @property
    def insights_clients(self):
        if not self.config.insights_enabled:
            raise InsightsDisabled("CloudWatch Logs Insights is disabled (INSIGHTS_ENABLED=false).")
        if self._insights_clients is None:
            from aws_cw_mcp.aws.insights_client import InsightsClients
            self._insights_clients = InsightsClients(self.config, self.clients.identity)
        return self._insights_clients

    @property
    def insights_logs(self) -> LogsService:
        """DescribeLogGroups for the INSIGHTS region, using the Phase 1 identity/profile (the Insights IAM
        identity has no DescribeLogGroups). Separate from `self.logs`, which stays in AWS_REGION."""
        if self._insights_logs is None:
            cfg = self.config
            region = cfg.insights_effective_region
            if region == cfg.aws_region:
                self._insights_logs = self.logs
            else:
                regional = dataclasses.replace(cfg, aws_region=region)
                self._insights_logs = LogsService(AwsClients(regional).logs(), regional, TTLCache(regional.cache_ttl_seconds))
        return self._insights_logs

    @property
    def insights(self):
        if not self.config.insights_enabled:
            raise InsightsDisabled("CloudWatch Logs Insights is disabled (INSIGHTS_ENABLED=false).")
        if self._insights is None:
            from aws_cw_mcp.aws.insights_client import InsightsApi
            from aws_cw_mcp.insights.executor import InsightsExecutor
            from aws_cw_mcp.insights.scope import LogsGroupCatalog
            from aws_cw_mcp.insights.validator import Validator
            clients = self.insights_clients
            executor = InsightsExecutor(self.config, InsightsApi(clients), LogsGroupCatalog(lambda: self.insights_logs),
                                        Validator(self.config, clients.approved))
            executor.launch_reaper()
            atexit.register(executor.shutdown)      # stop any still-running queries we started
            self._insights = executor
        return self._insights
