"""Temporal Activities for the EKS read-only proof (Phase T3).

These activities perform NO SSH, NO kubectl execution, and NO allow-list
logic of their own. They call the existing, unmodified
kube_core._run() - the same shared function server.py's get_cluster_info()
and get_pods() tools call, and the same one commerce_tools.py reuses - so
every command still passes through ssh_client.py's read-only allow-list
before it ever reaches the bastion. This module only shapes _run()'s
output into a small, bounded, structured result suitable for Temporal
workflow history.

This proof is deliberately restricted to "uat" only; "dev" and "prod" are
out of scope for Phase T3 regardless of what a caller passes in.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from temporalio import activity

from kube_core import _run

_ALLOWED_ENVIRONMENTS = ("uat",)
_MAX_PODS_RETURNED = 50
_MAX_CLUSTER_INFO_LINES = 20
_MAX_ERROR_CHARS = 2000


def _validate_environment(environment: str) -> str:
    env = (environment or "").strip().lower()
    if env not in _ALLOWED_ENVIRONMENTS:
        raise ValueError(
            f"Invalid environment {environment!r} for this proof: only "
            f"{', '.join(_ALLOWED_ENVIRONMENTS)} is permitted."
        )
    return env


def _split_run_result(raw: str) -> tuple[bool, str]:
    """Split kube_core._run()'s output into (ok, body_or_error).

    _run() always returns a single line "[env=...] Error: ..." on failure,
    and "[env=...]\\n<body>" (a newline-separated body, possibly empty) on
    success - see kube_core._run(). No other module re-parses this format;
    duplicating that one-line check here is far cheaper than changing the
    shared function's return type.
    """
    if "\n" in raw:
        _, body = raw.split("\n", 1)
        return True, body
    return False, raw[:_MAX_ERROR_CHARS]


@activity.defn
async def collect_cluster_info(environment: str) -> dict[str, Any]:
    env = _validate_environment(environment)
    raw = _run("kubectl cluster-info", env=env)
    ok, body = _split_run_result(raw)

    if not ok:
        return {
            "environment": env,
            "ok": False,
            "cluster_info_lines": [],
            "error": body,
        }

    lines = [line for line in body.splitlines() if line.strip()][:_MAX_CLUSTER_INFO_LINES]
    return {
        "environment": env,
        "ok": True,
        "cluster_info_lines": lines,
        "error": None,
    }


@activity.defn
async def collect_pod_state(environment: str) -> dict[str, Any]:
    env = _validate_environment(environment)
    raw = _run("kubectl get pods -A -o json", env=env)
    ok, body = _split_run_result(raw)

    if not ok:
        return {
            "environment": env,
            "ok": False,
            "total_pods": 0,
            "pods_returned": 0,
            "truncated": False,
            "pods": [],
            "error": body,
        }

    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, ValueError) as exc:
        return {
            "environment": env,
            "ok": False,
            "total_pods": 0,
            "pods_returned": 0,
            "truncated": False,
            "pods": [],
            "error": f"Could not parse pod list JSON: {exc}"[:_MAX_ERROR_CHARS],
        }

    items = payload.get("items", []) if isinstance(payload, dict) else []
    total = len(items)
    bounded_items = items[:_MAX_PODS_RETURNED]

    pods = [_summarize_pod(item) for item in bounded_items]

    return {
        "environment": env,
        "ok": True,
        "total_pods": total,
        "pods_returned": len(pods),
        "truncated": total > len(pods),
        "pods": pods,
        "error": None,
    }


def _summarize_pod(pod: dict) -> dict[str, Optional[str]]:
    metadata = pod.get("metadata", {}) or {}
    status = pod.get("status", {}) or {}
    container_statuses = status.get("containerStatuses", []) or []

    ready_count = sum(1 for c in container_statuses if c.get("ready"))
    restart_count = max((c.get("restartCount", 0) for c in container_statuses), default=0)

    waiting_reason = None
    for c in container_statuses:
        reason = (c.get("state", {}) or {}).get("waiting", {}).get("reason")
        if reason:
            waiting_reason = reason
            break

    return {
        "namespace": metadata.get("namespace"),
        "name": metadata.get("name"),
        "phase": status.get("phase"),
        "ready": f"{ready_count}/{len(container_statuses)}",
        "restart_count": restart_count,
        "waiting_reason": waiting_reason,
    }
