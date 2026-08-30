"""Temporal workflow definition.

EKSMonitoringWorkflow runs a single monitoring cycle: verify bastion/EKS
connectivity, collect a cluster snapshot, ask the LLM to analyze it, and
return a human-readable health report as the workflow result (visible in
the Temporal Web UI). Recurrence is handled by a Temporal Schedule
(see start_monitor.py) rather than an internal sleep loop, so every run
is a separate, independently-inspectable execution with its own result.

No SSH or external network calls happen here - only activity invocations.
"""
from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError

with workflow.unsafe.imports_passed_through():
    from app.activities import analyze_cluster_data, check_bastion_connection, collect_cluster_data
    from app.models import format_health_report

_CONNECTION_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=5),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=60),
    maximum_attempts=3,
)

_ANALYSIS_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=5),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=3,
)


@workflow.defn
class EKSMonitoringWorkflow:
    @workflow.run
    async def run(self) -> str:
        try:
            bastion_result = await workflow.execute_activity(
                check_bastion_connection,
                start_to_close_timeout=timedelta(seconds=60),
                retry_policy=_CONNECTION_RETRY,
            )
        except ActivityError as exc:
            workflow.logger.error(f"[TEMPORAL] Bastion connection failed: {exc}")
            return format_health_report(None, None, None, error=f"Bastion/SSH connection failed: {exc}")

        try:
            snapshot = await workflow.execute_activity(
                collect_cluster_data,
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_CONNECTION_RETRY,
            )
        except ActivityError as exc:
            workflow.logger.error(f"[TEMPORAL] Cluster data collection failed: {exc}")
            return format_health_report(bastion_result, None, None, error=f"Cluster data collection failed: {exc}")

        try:
            analysis = await workflow.execute_activity(
                analyze_cluster_data,
                snapshot,
                start_to_close_timeout=timedelta(minutes=3),
                retry_policy=_ANALYSIS_RETRY,
            )
        except ActivityError as exc:
            workflow.logger.error(f"[TEMPORAL] AI analysis failed: {exc}")
            report = format_health_report(bastion_result, snapshot, None)
            workflow.logger.info("[TEMPORAL] Workflow completed (AI analysis unavailable)")
            return report + f"\n\nAI Analysis: unavailable ({exc})"

        report = format_health_report(bastion_result, snapshot, analysis)
        workflow.logger.info("[TEMPORAL] Workflow completed")
        return report
