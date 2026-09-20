"""Runtime container: config + lazily-built AWS clients and services.

Phase 2+ services (Logs Insights, WAF, CloudFront, ...) plug in here as new
lazy properties and new modules under aws_cw_mcp/tools/.
"""
from __future__ import annotations

from typing import Optional

from aws_cw_mcp.aws.client import AwsClients
from aws_cw_mcp.aws.cloudwatch import AlarmsService, MetricsService
from aws_cw_mcp.aws.logs import LogsService
from aws_cw_mcp.config import Config
from aws_cw_mcp.utils.cache import TTLCache


class Runtime:
    def __init__(self, config: Config, clients: Optional[AwsClients] = None):
        self.config = config
        self.clients = clients or AwsClients(config)
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
