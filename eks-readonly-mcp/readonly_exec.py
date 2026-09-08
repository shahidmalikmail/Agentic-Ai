"""Environment-neutral read-only kubectl execution plumbing.

This module exists solely to be imported by prod_server.py. It has no
concept of "dev"/"uat"/"prod" as selectable environments, loads no
configuration, holds no credentials, and never constructs or chooses
between SSH clients - the caller must build a BastionSSHClient itself
(from whatever Config it likes) and inject it into run_readonly().

It intentionally duplicates a small amount of kube_core.py's
validation/formatting logic (namespace validation, output truncation,
error-string shape) rather than importing kube_core.py, so that
kube_core.py - and the DEV/UAT `_ALLOWED_ENVS` guarantee it enforces -
never has to change to support PROD. See the eks-prod-readonly P1 design
report for the rationale.

The read-only allow-list/forbidden-verb/shell-metacharacter guard itself is
NOT duplicated here: every command still passes through the existing,
unmodified BastionSSHClient.run_kubectl() -> _validate_read_only() in
ssh_client.py, which remains the sole trust boundary.
"""
from __future__ import annotations

import logging
import re
from typing import Callable, Optional

from ssh_client import (
    BastionConnectionError,
    BastionSSHClient,
    CommandTimeoutError,
    ReadOnlyViolation,
)

logger = logging.getLogger("readonly-exec")

_NAMESPACE_PATTERN = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
_MAX_OUTPUT_CHARS = 120_000


def validate_namespace(namespace: Optional[str]) -> Optional[str]:
    """Return None for "all namespaces", or a validated namespace string.

    Raises ValueError for anything that isn't a syntactically valid
    Kubernetes namespace name (RFC 1123 DNS label)."""
    if namespace is None:
        return None
    ns = namespace.strip()
    if ns == "" or ns.lower() == "all":
        return None
    if not _NAMESPACE_PATTERN.match(ns):
        raise ValueError(
            f"Invalid namespace {namespace!r}: must be a valid Kubernetes namespace "
            "name (lowercase alphanumeric and '-', max 63 chars), or omitted/'all'."
        )
    return ns


def scope_args(namespace: Optional[str]) -> str:
    """Return the kubectl scope flag for a namespace argument: "-A" for
    every namespace (namespace is None/""/"all"), or "-n <namespace>" for a
    validated specific namespace. Raises ValueError via validate_namespace()
    for anything else."""
    validated = validate_namespace(namespace)
    return "-A" if validated is None else f"-n {validated}"


def run_readonly(
    ssh: BastionSSHClient,
    kubectl_command: str,
    tag: str,
    sanitizer: Optional[Callable[[str], str]] = None,
) -> str:
    """Run one read-only kubectl command through an already-constructed
    BastionSSHClient and return a bounded, tagged result string.

    `ssh` is injected by the caller - this function never constructs, looks
    up, or chooses between SSH clients. `tag` is used only to label the
    response (e.g. "[tag]\\n...") for human/AI readability; it has no effect
    on which cluster is contacted, since that is entirely determined by the
    `ssh` object the caller already built.

    `sanitizer`, when given, is applied to a successful command's raw stdout
    BEFORE the output-size truncation below - a caller with sensitive output
    (e.g. prod_server.get_pods(), which passes
    prod_pod_sanitizer.sanitize_pod_list_json) can redact known-sensitive
    substructures without any other caller paying for it, and without ever
    truncating raw text ahead of sanitizing it (truncating first could cut a
    JSON document mid-object and leave an unredacted fragment behind).
    Never applied on any error path - an error message never carries
    kubectl's stdout in the first place."""
    try:
        result = ssh.run_kubectl(kubectl_command)
    except ReadOnlyViolation as exc:
        logger.error("Blocked non-read-only command: %s", exc)
        return f"[{tag}] Error: this request was blocked by the read-only guard ({exc})."
    except BastionConnectionError as exc:
        logger.error("Bastion connection failed: %s", exc)
        return (
            f"[{tag}] Error: could not connect to the bastion. Check that the VPN is "
            f"connected and the bastion is reachable. Details: {exc}"
        )
    except CommandTimeoutError as exc:
        logger.error("Command timed out: %s", exc)
        return f"[{tag}] Error: {exc}"

    if not result.ok:
        logger.warning("kubectl exited %s for: %s", result.exit_code, result.command)
        stderr = result.stderr.strip() or "(no stderr output)"
        return f"[{tag}] Error: kubectl failed (exit {result.exit_code}): {stderr}"

    output = result.stdout
    if sanitizer is not None:
        output = sanitizer(output)
    if len(output) > _MAX_OUTPUT_CHARS:
        output = output[:_MAX_OUTPUT_CHARS] + "\n...(output truncated)"
    body = output or "(empty result - no matching resources)"
    return f"[{tag}]\n{body}"
