"""Temporal activities.

All SSH and external-network I/O (bastion connections, kubectl calls, LLM
calls) live here, never in workflows.py. Activities are plain synchronous
functions - the worker runs them on a ThreadPoolExecutor
(see worker.py's `activity_executor`).
"""
from __future__ import annotations

import logging

import anthropic
from temporalio import activity
from temporalio.exceptions import ApplicationError

from app import ai_analyzer, kubernetes_monitor
from app.config import load_config
from app.models import AnalysisResult, BastionConnectionResult, ClusterSnapshot
from app.ssh_client import (
    BastionConnectionError,
    BastionSSHClient,
    CommandTimeoutError,
    ReadOnlyViolation,
    RemoteCommandError,
)

logger = logging.getLogger(__name__)


@activity.defn
def check_bastion_connection() -> BastionConnectionResult:
    config = load_config()
    try:
        with BastionSSHClient(config.bastion) as ssh:
            info = kubernetes_monitor.verify_connectivity(ssh, config.monitor.kubectl_timeout)
            return BastionConnectionResult(
                connected=True,
                message="Bastion reachable, kubectl and AWS CLI responded",
                kubectl_client_version=info["kubectl_client_version"],
                cluster_info=info["cluster_info"],
                aws_identity=info["aws_identity"],
            )
    except ReadOnlyViolation as exc:
        # Only ever raised by a programming error - never worth retrying.
        raise ApplicationError(str(exc), non_retryable=True) from exc
    except BastionConnectionError as exc:
        logger.error(f"[SSH] Connection failed: {exc}")
        # Transient (VPN down, bastion unreachable) - allow Temporal to retry.
        raise
    except (RemoteCommandError, CommandTimeoutError) as exc:
        logger.error(f"[EKS] Connectivity check failed: {exc}")
        raise


@activity.defn
def collect_cluster_data() -> ClusterSnapshot:
    config = load_config()
    try:
        with BastionSSHClient(config.bastion) as ssh:
            return kubernetes_monitor.collect_cluster_snapshot(ssh, config.monitor)
    except ReadOnlyViolation as exc:
        raise ApplicationError(str(exc), non_retryable=True) from exc
    except BastionConnectionError as exc:
        logger.error(f"[SSH] Connection failed: {exc}")
        raise
    except (RemoteCommandError, CommandTimeoutError) as exc:
        logger.error(f"[EKS] Data collection failed: {exc}")
        raise


@activity.defn
def analyze_cluster_data(snapshot: ClusterSnapshot) -> AnalysisResult:
    config = load_config()
    logger.info("[AI] Analyzing cluster")
    try:
        return ai_analyzer.analyze_cluster_data(snapshot, config.llm)
    except anthropic.AuthenticationError as exc:
        raise ApplicationError(f"Anthropic API key is invalid: {exc}", non_retryable=True) from exc
    except anthropic.PermissionDeniedError as exc:
        raise ApplicationError(f"Anthropic API key lacks permission: {exc}", non_retryable=True) from exc
    except anthropic.BadRequestError as exc:
        raise ApplicationError(f"Malformed request to LLM: {exc}", non_retryable=True) from exc
    except anthropic.RateLimitError as exc:
        logger.error(f"[AI] Rate limited: {exc}")
        raise
    except anthropic.APIStatusError as exc:
        logger.error(f"[AI] LLM server error: {exc}")
        raise
    except anthropic.APIConnectionError as exc:
        logger.error(f"[AI] Could not reach Anthropic API: {exc}")
        raise
