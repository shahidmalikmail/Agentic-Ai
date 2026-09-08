"""PROD-only parser for `kubectl get pods -o custom-columns=... --no-headers`
output (P10.3K, implementing the P10.3J design).

Pure, deterministic text-to-JSON transformation - no I/O, no SSH, no
Kubernetes access, no filesystem, no network, no environment access, no
dependency on ssh_client.py/kube_core.py/config.py/prod_pod_sanitizer.py.
Never logs or persists raw input.

This is a PREVENTION-based control, not a redaction-based one:
prod_pod_sanitizer.sanitize_pod_list_json() (still retained, still used by
no tool other than its own tests after this change - see its own module
for why it is kept) works by fetching the FULL pod JSON and then stripping
`env`/`envFrom` after the fact. This module instead uses a fixed kubectl
`-o custom-columns` specification (POD_COLUMNS_SPEC below) that NEVER asks
the API server for `env`, `envFrom`, `data`, `stringData`, any
secret/configMap reference path, service account token fields, labels, or
annotations in the first place - there is no redaction step to get wrong,
because the sensitive data is never fetched at all.

POD_COLUMNS_SPEC is a fixed, hardcoded module-level constant. It is never
built from caller input, never influenced by the `namespace` argument
prod_server.get_pods() accepts, and never varies at runtime.

Fails CLOSED, all-or-nothing: any row that does not split into exactly the
expected column count, any required field that is unexpectedly `<none>`,
any unparseable boolean/integer token, any container/image count mismatch,
or any unexpected internal error causes the ENTIRE response to be withheld
via the fixed placeholder below - never a partial pod list, never a
silently-skipped row, and never a fallback to the raw kubectl output.
"""
from __future__ import annotations

import json
from typing import Optional

_NONE = "<none>"

# Fixed, hardcoded - never caller-controlled, never derived from the
# `namespace` argument. Deliberately excludes env/envFrom/data/stringData/
# secretKeyRef/configMapKeyRef/secretRef/configMapRef/service-account
# token fields/labels/annotations - see module docstring.
POD_COLUMNS_SPEC = (
    "NAME:.metadata.name,"
    "NAMESPACE:.metadata.namespace,"
    "PHASE:.status.phase,"
    "POD_IP:.status.podIP,"
    "NODE:.spec.nodeName,"
    "CONTAINERS:.spec.containers[*].name,"
    "IMAGES:.spec.containers[*].image,"
    "READY:.status.containerStatuses[*].ready,"
    "RESTARTS:.status.containerStatuses[*].restartCount"
)

_EXPECTED_COLUMN_COUNT = 9

# kubectl's own message for zero matching resources with --no-headers.
_NO_RESOURCES_PREFIX = "No resources found"

_WITHHELD_FAIL_CLOSED = json.dumps(
    {"error": "PROD pod data could not be safely parsed and was withheld before being returned."}
)


def _parse_bool_tokens(raw: str) -> Optional[list[bool]]:
    """Parse a comma-joined READY column value into a list of bools.
    Returns None (never raises, never guesses) if any token is not exactly
    "true" or "false" - kubectl's own Go-bool string rendering, matched
    case-sensitively; anything else is unparseable."""
    if raw == _NONE:
        return []
    tokens = raw.split(",")
    result: list[bool] = []
    for token in tokens:
        if token == "true":
            result.append(True)
        elif token == "false":
            result.append(False)
        else:
            return None
    return result


def _parse_int_tokens(raw: str) -> Optional[list[int]]:
    """Parse a comma-joined RESTARTS column value into a list of ints.
    Returns None for any unparseable token - never silently defaults to 0
    the way the (unrelated) commerce_tools.py discovery parser does; PROD
    fails closed instead."""
    if raw == _NONE:
        return []
    tokens = raw.split(",")
    result: list[int] = []
    for token in tokens:
        try:
            result.append(int(token))
        except ValueError:
            return None
    return result


def _parse_line(line: str) -> Optional[dict]:
    """Parse one `-o custom-columns` row into a controlled dict, or None
    if the row is malformed/ambiguous in any way. None from this function
    always means "fail the entire response closed" in the caller - it is
    never used to silently skip just this one row."""
    parts = line.split()
    if len(parts) != _EXPECTED_COLUMN_COUNT:
        return None

    (
        name,
        namespace,
        phase,
        pod_ip_raw,
        node_raw,
        containers_raw,
        images_raw,
        ready_raw,
        restarts_raw,
    ) = parts

    # Required fields: an unexpected <none> or empty value is not a value
    # this parser will ever guess a default for.
    for required in (name, namespace, phase, containers_raw, images_raw):
        if not required or required == _NONE:
            return None

    pod_ip = None if pod_ip_raw == _NONE else pod_ip_raw
    node = None if node_raw == _NONE else node_raw

    container_names = containers_raw.split(",")
    image_names = images_raw.split(",")
    if not container_names or not image_names:
        return None
    if any(not c for c in container_names) or any(not i for i in image_names):
        return None
    # CONTAINERS and IMAGES are selected from the identical spec.containers[*]
    # array; both `name` and `image` are required, always-present fields on
    # every container in the Kubernetes API schema, so a length mismatch
    # here means the data cannot be safely aligned - fail closed rather
    # than guess a pairing.
    if len(container_names) != len(image_names):
        return None

    ready_bools = _parse_bool_tokens(ready_raw)
    if ready_bools is None:
        return None
    restart_ints = _parse_int_tokens(restarts_raw)
    if restart_ints is None:
        return None
    # READY and RESTARTS are both required, always-present fields on every
    # entry of the SAME containerStatuses[*] array (unlike e.g. a
    # conditionally-absent state.waiting.reason) - if kubectl reported a
    # different count for each, something is wrong with the data, not
    # merely "fewer containerStatuses than containers" (which is a normal,
    # expected, NOT-failing condition for a Pending pod).
    if len(ready_bools) != len(restart_ints):
        return None

    containers = [{"name": c, "image": i} for c, i in zip(container_names, image_names)]

    # Deliberately self-consistent: both ready_count and total_count are
    # derived from the SAME containerStatuses-sourced list, never mixed
    # with the (possibly different-length) spec.containers count - see
    # module docstring and the P10.3J design's multi-container analysis.
    ready_count = sum(1 for b in ready_bools if b)
    total_count = len(ready_bools)
    max_restarts = max(restart_ints) if restart_ints else 0

    return {
        "name": name,
        "namespace": namespace,
        "phase": phase,
        "pod_ip": pod_ip,
        "node": node,
        "containers": containers,
        "ready": {"ready_count": ready_count, "total_count": total_count},
        "restarts": {"max": max_restarts},
    }


def parse_get_pods_columns(raw_output: str) -> str:
    """Parse `kubectl get pods -o custom-columns={POD_COLUMNS_SPEC}
    --no-headers` stdout into a small, controlled JSON representation
    (`{"pods": [...]}`), fitting readonly_exec.run_readonly()'s generic
    `sanitizer: Callable[[str], str]` hook exactly like
    prod_pod_sanitizer.sanitize_pod_list_json() does for other tools.

    Container `state` and pod `conditions` are intentionally OMITTED - an
    explicit, disclosed contract reduction (P10.3J), not a silent one:
    Kubernetes' container state is a union type (running/waiting/
    terminated) that custom-columns cannot represent as a single column
    without guessing which variant is populated, and conditions require
    pairing two independently-selected array columns (type/status) with
    no columns-level alignment guarantee. Neither is reconstructed here.

    Readiness and restart counts are reported as explicit POD-LEVEL
    AGGREGATES (`ready_count`/`total_count`, `max`), never as a false
    precise per-container attribution - they come from
    status.containerStatuses[*], a different array from
    spec.containers[*], with no guaranteed same-length/same-order
    relationship to it (e.g. a Pending pod may have no containerStatuses
    yet at all).

    Fails CLOSED on any ambiguity: a malformed/wrong-column-count row, an
    unexpected `<none>` on a required field, an unparseable boolean/
    integer token, or a container/image count mismatch all cause the
    ENTIRE response to be withheld - never a partial pod list, and never a
    fallback to the raw kubectl output, which this function never returns
    under any circumstance."""
    try:
        stripped = raw_output.strip()
        if not stripped or stripped.startswith(_NO_RESOURCES_PREFIX):
            return json.dumps({"pods": []}, indent=2)

        pods: list[dict] = []
        for line in raw_output.splitlines():
            if not line.strip():
                # A blank line amid otherwise non-empty output is not a
                # row this parser recognizes - never silently skipped.
                return _WITHHELD_FAIL_CLOSED
            pod = _parse_line(line)
            if pod is None:
                return _WITHHELD_FAIL_CLOSED
            pods.append(pod)

        return json.dumps({"pods": pods}, indent=2)
    except Exception:
        # Defense in depth: any unexpected internal error - never an
        # unhandled traceback reaching the MCP layer, never a fallback to
        # raw_output.
        return _WITHHELD_FAIL_CLOSED
