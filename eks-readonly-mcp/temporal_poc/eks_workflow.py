"""Temporal Workflow for the EKS read-only proof (Phase T3).

Executes exactly two read-only Activities in sequence against UAT:
collect_cluster_info, then collect_pod_state. No remediation, no
schedules, no signals, no child workflows.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from temporal_poc.eks_activities import collect_cluster_info, collect_pod_state

_ACTIVITY_TIMEOUT = timedelta(seconds=30)
_RETRY_POLICY = RetryPolicy(
    maximum_attempts=3,
    initial_interval=timedelta(seconds=1),
    backoff_coefficient=2.0,
    non_retryable_error_types=["ValueError"],
)


@workflow.defn
class EKSReadOnlyHealthWorkflow:
    @workflow.run
    async def run(self, environment: str) -> dict[str, Any]:
        cluster_info = await workflow.execute_activity(
            collect_cluster_info,
            environment,
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
            retry_policy=_RETRY_POLICY,
        )

        pod_state = await workflow.execute_activity(
            collect_pod_state,
            environment,
            start_to_close_timeout=_ACTIVITY_TIMEOUT,
            retry_policy=_RETRY_POLICY,
        )

        return {
            "environment": environment,
            "cluster_info": cluster_info,
            "pod_state": pod_state,
        }
