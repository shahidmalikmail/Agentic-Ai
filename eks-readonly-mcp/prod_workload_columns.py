"""PROD-only parsers for `kubectl get {deployments,replicasets,statefulsets,
daemonsets} -o custom-columns=... --no-headers` output (P11B, implementing
the P11A design).

Pure, deterministic text-to-JSON transformation - no I/O, no SSH, no
Kubernetes access, no filesystem, no network, no environment access, no
dependency on ssh_client.py/kube_core.py/config.py/prod_pod_sanitizer.py/
prod_pod_columns.py. Never logs or persists raw input.

This is a PREVENTION-based control, exactly like prod_pod_columns.py's
get_pods parser, NOT an extension of prod_pod_sanitizer.sanitize_workload_
list_json() (which is retained, unmodified, and simply no longer wired to
any tool after this change - see prod_server.py). Each fixed column spec
below NEVER asks the API server for `env`, `envFrom`, `data`, `stringData`,
any secret/configMap reference path, service-account fields, labels,
annotations, `volumes`, `imagePullSecrets`, or container `command`/`args`
in the first place - there is no redaction step to get wrong, because the
sensitive data is never fetched at all (P11 finding: the JSON+blacklist
approach left exactly these fields unprotected).

The four resource types do NOT share a uniform status schema - Deployment/
ReplicaSet/StatefulSet use `spec.replicas`/`status.readyReplicas`/
`status.availableReplicas`; DaemonSet has no `spec.replicas` concept at
all and uses `status.desiredNumberScheduled`/`numberReady`/
`numberAvailable`/`updatedNumberScheduled` instead; ReplicaSet has no
rolling-update concept and so has no UPDATED column at all (never
requested from kubectl, not merely nulled out after the fact). Each
column spec is a fixed, hardcoded constant, never caller-controlled and
never influenced by the `namespace` argument.

Fails CLOSED, all-or-nothing: any row that does not split into exactly
the expected column count, any required field (`name`, `namespace`,
`desired`, `ready`, `containers`, `images`) that is unexpectedly `<none>`
or unparseable, a container/image count mismatch, or any unexpected
internal error causes the ENTIRE response to be withheld via the fixed
placeholder below - never a partial item list, never a silently-skipped
row, and never a fallback to the raw kubectl output.

`available`/`updated` are OPTIONAL: `<none>` becomes `null` (never the
literal string "<none>"), distinct from a genuine `0` - an invalid
(non-`<none>`, non-integer) value on these fields still fails closed
rather than being silently treated as null or defaulted to 0.
"""
from __future__ import annotations

import json
from typing import Optional

_NONE = "<none>"

# Fixed, hardcoded - never caller-controlled, never derived from the
# `namespace` argument. Deliberately excludes env/envFrom/data/stringData/
# secretKeyRef/configMapKeyRef/secretRef/configMapRef/serviceAccount/
# labels/annotations/volumes/imagePullSecrets/command/args - see module
# docstring.
DEPLOYMENT_COLUMNS_SPEC = (
    "NAME:.metadata.name,"
    "NAMESPACE:.metadata.namespace,"
    "DESIRED:.spec.replicas,"
    "READY:.status.readyReplicas,"
    "AVAILABLE:.status.availableReplicas,"
    "UPDATED:.status.updatedReplicas,"
    "CONTAINERS:.spec.template.spec.containers[*].name,"
    "IMAGES:.spec.template.spec.containers[*].image"
)

# No UPDATED column: ReplicaSets do not perform rolling updates themselves
# (that is the owning Deployment's job) - this field is never requested
# from kubectl at all for this resource type, not merely nulled out
# after the fact.
REPLICASET_COLUMNS_SPEC = (
    "NAME:.metadata.name,"
    "NAMESPACE:.metadata.namespace,"
    "DESIRED:.spec.replicas,"
    "READY:.status.readyReplicas,"
    "AVAILABLE:.status.availableReplicas,"
    "CONTAINERS:.spec.template.spec.containers[*].name,"
    "IMAGES:.spec.template.spec.containers[*].image"
)

STATEFULSET_COLUMNS_SPEC = (
    "NAME:.metadata.name,"
    "NAMESPACE:.metadata.namespace,"
    "DESIRED:.spec.replicas,"
    "READY:.status.readyReplicas,"
    "AVAILABLE:.status.availableReplicas,"
    "UPDATED:.status.updatedReplicas,"
    "CONTAINERS:.spec.template.spec.containers[*].name,"
    "IMAGES:.spec.template.spec.containers[*].image"
)

# DaemonSet has no spec.replicas concept - it schedules one pod per
# matching node, not a replica count - so DESIRED/READY/AVAILABLE/UPDATED
# map to its own status field names instead.
DAEMONSET_COLUMNS_SPEC = (
    "NAME:.metadata.name,"
    "NAMESPACE:.metadata.namespace,"
    "DESIRED:.status.desiredNumberScheduled,"
    "READY:.status.numberReady,"
    "AVAILABLE:.status.numberAvailable,"
    "UPDATED:.status.updatedNumberScheduled,"
    "CONTAINERS:.spec.template.spec.containers[*].name,"
    "IMAGES:.spec.template.spec.containers[*].image"
)

_DEPLOYMENT_COLUMN_COUNT = 8
_REPLICASET_COLUMN_COUNT = 7
_STATEFULSET_COLUMN_COUNT = 8
_DAEMONSET_COLUMN_COUNT = 8

_NO_RESOURCES_PREFIX = "No resources found"

_WITHHELD_FAIL_CLOSED = json.dumps(
    {"error": "PROD workload data could not be safely parsed and was withheld before being returned."}
)


def _parse_containers_and_images(containers_raw: str, images_raw: str) -> Optional[list]:
    """CONTAINERS and IMAGES are selected from the identical
    spec.template.spec.containers[*] array; both `name` and `image` are
    required, always-present fields on every container in the Kubernetes
    API schema. Returns None (fail closed) if either is `<none>`/empty,
    contains an empty token, or the two lists differ in length - a
    mismatch means the data cannot be safely aligned, never guessed."""
    if not containers_raw or containers_raw == _NONE:
        return None
    if not images_raw or images_raw == _NONE:
        return None

    names = containers_raw.split(",")
    images = images_raw.split(",")
    if any(not n for n in names) or any(not i for i in images):
        return None
    if len(names) != len(images):
        return None

    return [{"name": n, "image": i} for n, i in zip(names, images)]


def _parse_required_int(raw: str) -> Optional[int]:
    """Required numeric field: `<none>` or any unparseable token fails
    closed (returns None) - never silently defaulted to 0. A genuine `0`
    parses correctly and is distinct from "missing"."""
    if not raw or raw == _NONE:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _parse_optional_int(raw: str) -> tuple[bool, Optional[int]]:
    """Optional numeric field: `<none>` maps to (True, None) - a genuine
    null, never the literal string. Any other unparseable token is NOT
    silently treated as null - it returns (False, None), signaling the
    caller to fail closed, since that represents corrupt/ambiguous data,
    not a legitimately absent value."""
    if raw == _NONE:
        return True, None
    try:
        return True, int(raw)
    except ValueError:
        return False, None


def _parse_workload_line(parts: list[str], has_updated: bool) -> Optional[dict]:
    """Parse one `-o custom-columns` row into a controlled dict, or None
    if the row is malformed/ambiguous in any way. None from this function
    always means "fail the entire response closed" in the caller - it is
    never used to silently skip just this one row."""
    if has_updated:
        if len(parts) != 8:
            return None
        name, namespace, desired_raw, ready_raw, available_raw, updated_raw, containers_raw, images_raw = parts
    else:
        if len(parts) != 7:
            return None
        name, namespace, desired_raw, ready_raw, available_raw, containers_raw, images_raw = parts
        updated_raw = None

    for required in (name, namespace):
        if not required or required == _NONE:
            return None

    desired = _parse_required_int(desired_raw)
    if desired is None:
        return None

    ready = _parse_required_int(ready_raw)
    if ready is None:
        return None

    available_ok, available = _parse_optional_int(available_raw)
    if not available_ok:
        return None

    if updated_raw is None:
        updated = None
    else:
        updated_ok, updated = _parse_optional_int(updated_raw)
        if not updated_ok:
            return None

    containers = _parse_containers_and_images(containers_raw, images_raw)
    if containers is None:
        return None

    return {
        "name": name,
        "namespace": namespace,
        "desired": desired,
        "ready": ready,
        "available": available,
        "updated": updated,
        "containers": containers,
    }


def _parse_workload_columns(raw_output: str, *, has_updated: bool, top_level_key: str) -> str:
    """Shared parsing engine for all four workload resource types. Fails
    CLOSED on any ambiguity: a blank line amid otherwise non-empty output,
    a wrong-column-count row, an unexpected `<none>`/unparseable value on
    a required field, an invalid (non-`<none>`) value on an optional
    field, a container/image count mismatch, or any unexpected internal
    error all cause the ENTIRE response to be withheld - never a partial
    item list, and never a fallback to the raw kubectl output, which this
    function never returns under any circumstance."""
    try:
        stripped = raw_output.strip()
        if not stripped or stripped.startswith(_NO_RESOURCES_PREFIX):
            return json.dumps({top_level_key: []}, indent=2)

        items: list[dict] = []
        for line in raw_output.splitlines():
            if not line.strip():
                # A blank line amid otherwise non-empty output is not a
                # row this parser recognizes - never silently skipped.
                return _WITHHELD_FAIL_CLOSED
            item = _parse_workload_line(line.split(), has_updated=has_updated)
            if item is None:
                return _WITHHELD_FAIL_CLOSED
            items.append(item)

        return json.dumps({top_level_key: items}, indent=2)
    except Exception:
        # Defense in depth: any unexpected internal error - never an
        # unhandled traceback reaching the MCP layer, never a fallback to
        # raw_output.
        return _WITHHELD_FAIL_CLOSED


def parse_get_deployments_columns(raw_output: str) -> str:
    """Parse `kubectl get deployments -o custom-columns={DEPLOYMENT_COLUMNS_SPEC}
    --no-headers` stdout into `{"deployments": [...]}`."""
    return _parse_workload_columns(raw_output, has_updated=True, top_level_key="deployments")


def parse_get_replicasets_columns(raw_output: str) -> str:
    """Parse `kubectl get replicasets -o custom-columns={REPLICASET_COLUMNS_SPEC}
    --no-headers` stdout into `{"replicasets": [...]}`. Every item's
    `updated` is always `null` - ReplicaSets have no rolling-update
    concept, and this field is never requested from kubectl at all."""
    return _parse_workload_columns(raw_output, has_updated=False, top_level_key="replicasets")


def parse_get_statefulsets_columns(raw_output: str) -> str:
    """Parse `kubectl get statefulsets -o custom-columns={STATEFULSET_COLUMNS_SPEC}
    --no-headers` stdout into `{"statefulsets": [...]}`."""
    return _parse_workload_columns(raw_output, has_updated=True, top_level_key="statefulsets")


def parse_get_daemonsets_columns(raw_output: str) -> str:
    """Parse `kubectl get daemonsets -o custom-columns={DAEMONSET_COLUMNS_SPEC}
    --no-headers` stdout into `{"daemonsets": [...]}`. `desired`/`ready`/
    `available`/`updated` map to DaemonSet's own status field names
    (desiredNumberScheduled/numberReady/numberAvailable/
    updatedNumberScheduled), since DaemonSets have no spec.replicas
    concept at all."""
    return _parse_workload_columns(raw_output, has_updated=True, top_level_key="daemonsets")
