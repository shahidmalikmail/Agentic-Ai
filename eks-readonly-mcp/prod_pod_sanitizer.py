"""PROD-only sanitizer for pod and pod-template-bearing `kubectl -o json`
output (Pods directly, and Deployments/ReplicaSets/StatefulSets/DaemonSets
via their embedded `spec.template.spec`).

Pure, deterministic JSON transformation - no I/O, no SSH, no Kubernetes
access, no dependency on ssh_client.py/kube_core.py/config.py. Takes the
raw JSON text kubectl already returned and removes every
credential-bearing section before it can reach the MCP caller.

Unlike commerce_log_analyzer.redact_secrets() (keyword/regex substitution
on log TEXT, matched by variable-name-like patterns such as "password="),
this module never inspects variable names to decide what is "sensitive".
A container's `env`/`envFrom` blocks are removed in their entirety,
structurally, for every container - the same treatment for
`SOME_VARIABLE` as for `DB_PASSWORD`, because a keyword-based allow/deny
list can always miss an unanticipated name. This is deliberately the
least clever, most mechanical option available.

There is exactly ONE redaction implementation (_sanitize_container /
_sanitize_containers_list / _sanitize_pod_spec below), reused by both
public entry points:

- sanitize_pod_list_json(): Pod / PodList - containers live at spec
  directly (P10.1).
- sanitize_workload_list_json(): Deployment/ReplicaSet/StatefulSet/
  DaemonSet (and their List variants) - containers live one level deeper,
  at spec.template.spec, since these objects wrap a pod template rather
  than being a pod themselves (P10.2). Everything else in `spec`
  (replicas, selector, template.metadata.labels, ...) and all of `status`
  and `metadata` is left untouched.

Fails CLOSED: if the input cannot be parsed as JSON, or its shape is not a
recognized/supported kind for the entry point being called, the raw text
is never returned - a fixed error placeholder is returned instead. This
matters because run_readonly()'s 120,000-character output cap could
otherwise truncate mid-object on a very large list; sanitizing must happen
on the full JSON before any truncation, and unparsable/unexpected input
must never fall back to passing the original bytes through.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Callable

logger = logging.getLogger("prod-pod-sanitizer")

_REDACTED = "[REDACTED]"

# The complete, fixed set of Kubernetes "kind" values any PROD sanitizer in
# this project knows how to handle (Pod/PodList here; the four workload
# kinds via sanitize_workload_list_json()). Used ONLY to decide what the
# P10.3B diagnostic below is allowed to name in a log line - naming one of
# these is not a disclosure of anything (they're a small, fixed, public
# vocabulary of Kubernetes API object kinds already handled by this
# codebase), never used to change sanitization behavior itself.
_RECOGNIZED_KINDS = frozenset(
    {
        "Pod",
        "PodList",
        "Deployment",
        "DeploymentList",
        "ReplicaSet",
        "ReplicaSetList",
        "StatefulSet",
        "StatefulSetList",
        "DaemonSet",
        "DaemonSetList",
    }
)


# P10.3F: fixed lookup from the first non-whitespace character to a
# closed-vocabulary structural label. Never used to log the character
# itself - only ever this label.
_STARTS_WITH_MAP = {
    "{": "object",
    "[": "array",
    '"': "string",
    "t": "true",
    "f": "false",
    "n": "null",
}


def _pre_parse_diagnostic_fields(raw_json: str) -> dict:
    """P10.3E/P10.3F: structural facts about the raw string, computable
    WITHOUT parsing - safe to call even when json.loads() will go on to
    fail. Every value is an int, a bool, or a fixed-enum string drawn from
    _STARTS_WITH_MAP (plus the two additional fixed labels below) - never
    a substring of raw_json and never the raw text itself."""
    stripped = raw_json.strip()
    if not stripped:
        starts_with = "empty"
    else:
        starts_with = _STARTS_WITH_MAP.get(stripped[0], "digit_or_minus_or_other")
    return {
        "stdout_length": len(raw_json),
        "has_leading_whitespace": raw_json != raw_json.lstrip(),
        "has_trailing_whitespace": raw_json != raw_json.rstrip(),
        "starts_with": starts_with,
    }


def _format_pre_parse_fields(fields: dict) -> str:
    return (
        f"stdout_length={fields['stdout_length']} "
        f"has_leading_whitespace={fields['has_leading_whitespace']} "
        f"has_trailing_whitespace={fields['has_trailing_whitespace']} "
        f"starts_with={fields['starts_with']}"
    )


def _json_type_name(data: Any) -> str:
    """Fixed-enum classification of an already-parsed JSON value's Python
    type. Never returns or is derived from the value's content."""
    if isinstance(data, dict):
        return "dict"
    if isinstance(data, list):
        return "list"
    if isinstance(data, bool):
        return "bool"
    if isinstance(data, str):
        return "string"
    if isinstance(data, (int, float)):
        return "number"
    if data is None:
        return "null"
    return "other"


def _log_malformed_json(raw_json: str) -> None:
    """P10.3F: local-only diagnostic for sanitize_pod_list_json()'s
    fail-closed malformed-JSON (JSONDecodeError) path. Logs ONLY the
    pre-parse structural fields (_pre_parse_diagnostic_fields) - never the
    JSONDecodeError's own message (which can quote fragments of the
    payload), never any substring of raw_json, never the raw text itself.
    Never part of the string returned to the MCP caller, which stays
    exactly _WITHHELD_UNPARSABLE regardless of what this logs."""
    fields = _pre_parse_diagnostic_fields(raw_json)
    logger.warning("sanitize_pod_list_json: malformed JSON - %s", _format_pre_parse_fields(fields))


def _log_unexpected_shape(raw_json: str, data: Any) -> None:
    """P10.3B/P10.3F: local-only diagnostic for sanitize_pod_list_json()'s
    fail-closed unexpected-shape path (see the P10.3/P10.3A/P10.3D/P10.3E
    investigation). Goes to the local `logging` module only - stderr in
    this project's convention (see kube_core.py/readonly_exec.py) - and is
    NEVER part of the string returned to the MCP caller, which stays
    exactly _WITHHELD_UNEXPECTED_SHAPE regardless of what this logs.

    Every value logged is one of: an int, a bool, or a value drawn from a
    small fixed enum/allow-list:
      - the pre-parse structural fields (stdout_length/has_leading_
        whitespace/has_trailing_whitespace/starts_with - see
        _pre_parse_diagnostic_fields).
      - json_type: dict/list/string/number/bool/null/other.
      - for dict values only: kind_present, kind_is_string,
        kind_recognized (all bool), kind_named (an allow-listed
        _RECOGNIZED_KINDS string, or the literal "<UNRECOGNIZED>" - the
        actual kind string is NEVER logged when not allow-listed),
        items_present, items_is_list (bool), and items_count (an int,
        only when items_is_list is true).

    Never logs: the payload, any dict key/value other than the fixed facts
    above, any nested pod/container/env/secret/configMap data, or any
    substring of the raw input text."""
    fields = _pre_parse_diagnostic_fields(raw_json)
    parts = [_format_pre_parse_fields(fields), f"json_type={_json_type_name(data)}"]

    if isinstance(data, dict):
        kind = data.get("kind")
        kind_is_string = isinstance(kind, str)
        kind_recognized = kind_is_string and kind in _RECOGNIZED_KINDS
        kind_named = kind if kind_recognized else "<UNRECOGNIZED>"
        items = data.get("items")
        items_is_list = isinstance(items, list)

        parts.append(f"kind_present={'kind' in data}")
        parts.append(f"kind_is_string={kind_is_string}")
        parts.append(f"kind_recognized={kind_recognized}")
        parts.append(f"kind_named={kind_named}")
        parts.append(f"items_present={'items' in data}")
        parts.append(f"items_is_list={items_is_list}")
        if items_is_list:
            parts.append(f"items_count={len(items)}")

    logger.warning("sanitize_pod_list_json: unexpected shape - %s", " ".join(parts))

# Every container-level field that can carry or reference credential
# material. Replaced wholesale (not filtered by key name) - see module
# docstring for why.
_SENSITIVE_CONTAINER_FIELDS = ("env", "envFrom")

_WITHHELD_UNPARSABLE = json.dumps(
    {"error": "PROD Kubernetes data could not be safely parsed and was withheld before being returned."}
)
_WITHHELD_UNEXPECTED_SHAPE = json.dumps(
    {"error": "PROD Kubernetes data had an unexpected or unsupported shape and was withheld before being returned."}
)


def _sanitize_container(container: dict) -> dict:
    sanitized = dict(container)
    for field in _SENSITIVE_CONTAINER_FIELDS:
        if field in sanitized:
            sanitized[field] = _REDACTED
    return sanitized


def _sanitize_containers_list(containers: Any) -> Any:
    if not isinstance(containers, list):
        return containers
    return [_sanitize_container(c) if isinstance(c, dict) else c for c in containers]


def _sanitize_pod_spec(spec: dict) -> dict:
    sanitized = dict(spec)
    for key in ("containers", "initContainers", "ephemeralContainers"):
        if key in sanitized:
            sanitized[key] = _sanitize_containers_list(sanitized[key])
    return sanitized


def _sanitize_pod(pod: dict) -> dict:
    sanitized = dict(pod)
    spec = pod.get("spec")
    if isinstance(spec, dict):
        sanitized["spec"] = _sanitize_pod_spec(spec)
    return sanitized


def sanitize_pod_list_json(raw_json: str) -> str:
    """Redact every container's `env`/`envFrom` block (and therefore every
    `value`, `valueFrom.secretKeyRef`, `valueFrom.configMapKeyRef`,
    `valueFrom.fieldRef`, `secretRef`, and `configMapRef` nested under
    them) from a `kubectl get pods -o json` response.

    Accepts a `PodList` (`{"kind": "PodList", "items": [...]}`, the shape
    `kubectl get pods` always returns for `-A`/`-n <namespace>`) or a
    single `Pod` object. Anything else, or text that isn't valid JSON,
    is withheld entirely rather than guessed at or partially redacted.

    Preserves everything else unchanged: metadata (name, namespace,
    labels, ...), status (phase, conditions, podIP, containerStatuses
    including each container's name/image/ready/restartCount/state),
    spec.nodeName, and each container's resources block.

    P10.3B/P10.3F: if the shape isn't recognized (or the JSON itself is
    malformed), a local-only structural diagnostic (_log_unexpected_shape /
    _log_malformed_json) is emitted to stderr before returning the fixed
    placeholder below - see those functions' docstrings for exactly what
    they do and do not log. The returned string is unaffected either way."""
    try:
        data = json.loads(raw_json)
    except (json.JSONDecodeError, ValueError, TypeError):
        _log_malformed_json(raw_json)
        return _WITHHELD_UNPARSABLE

    if isinstance(data, dict) and data.get("kind") == "PodList":
        items = data.get("items")
        if isinstance(items, list):
            data = dict(data)
            data["items"] = [_sanitize_pod(p) if isinstance(p, dict) else p for p in items]
        return json.dumps(data, indent=2)

    if isinstance(data, dict) and data.get("kind") == "Pod":
        return json.dumps(_sanitize_pod(data), indent=2)

    _log_unexpected_shape(raw_json, data)
    return _WITHHELD_UNEXPECTED_SHAPE


# --------------------------------------------------------------------------
# P10.2: Deployment/ReplicaSet/StatefulSet/DaemonSet - each wraps a pod
# template at spec.template.spec rather than being a pod itself. Reuses
# _sanitize_pod_spec/_sanitize_containers_list/_sanitize_container above
# unchanged - the only new logic here is finding spec.template.spec.
# --------------------------------------------------------------------------

_WORKLOAD_KINDS = ("Deployment", "ReplicaSet", "StatefulSet", "DaemonSet")


def _sanitize_workload_spec(spec: dict) -> dict:
    """Sanitize a workload's `spec`: only `spec.template.spec`'s container
    lists are pod-template-shaped and get the shared container-sanitizing
    treatment. `spec.replicas`, `spec.selector`, and
    `spec.template.metadata` (labels/annotations) are left untouched."""
    sanitized_spec = dict(spec)
    template = spec.get("template")
    if isinstance(template, dict):
        sanitized_template = dict(template)
        template_spec = template.get("spec")
        if isinstance(template_spec, dict):
            sanitized_template["spec"] = _sanitize_pod_spec(template_spec)
        sanitized_spec["template"] = sanitized_template
    return sanitized_spec


def _sanitize_workload_object(obj: dict) -> dict:
    sanitized = dict(obj)
    spec = obj.get("spec")
    if isinstance(spec, dict):
        sanitized["spec"] = _sanitize_workload_spec(spec)
    return sanitized


_WORKLOAD_KIND_SANITIZERS: dict[str, Callable[[dict], dict]] = {
    kind: _sanitize_workload_object for kind in _WORKLOAD_KINDS
}


def sanitize_workload_list_json(raw_json: str) -> str:
    """Redact every pod-template container's `env`/`envFrom` block (and
    therefore every `value`, `valueFrom.secretKeyRef`,
    `valueFrom.configMapKeyRef`, `valueFrom.fieldRef`, `secretRef`, and
    `configMapRef` nested under them) from a `kubectl get
    deployments|replicasets|statefulsets|daemonsets -o json` response.

    Accepts a `<Kind>List` (e.g. `DeploymentList`, the shape `kubectl get
    <resource>` always returns for `-A`/`-n <namespace>`) or a single
    workload object of one of the four supported kinds. Anything else
    (including a bare Pod/PodList - use sanitize_pod_list_json() for
    those), or text that isn't valid JSON, is withheld entirely rather
    than guessed at or partially redacted.

    Preserves everything else unchanged: metadata (name, namespace,
    labels, annotations, ...), spec.replicas, spec.selector,
    spec.template.metadata.labels, each container's name/image/resources/
    ports, and every status field (replicas/readyReplicas/
    availableReplicas/updatedReplicas/conditions/...)."""
    try:
        data = json.loads(raw_json)
    except (json.JSONDecodeError, ValueError, TypeError):
        return _WITHHELD_UNPARSABLE

    if not isinstance(data, dict):
        return _WITHHELD_UNEXPECTED_SHAPE

    kind = data.get("kind")
    if not isinstance(kind, str):
        return _WITHHELD_UNEXPECTED_SHAPE

    if kind.endswith("List"):
        base_kind = kind[: -len("List")]
        sanitizer = _WORKLOAD_KIND_SANITIZERS.get(base_kind)
        if sanitizer is None:
            return _WITHHELD_UNEXPECTED_SHAPE
        items = data.get("items")
        if isinstance(items, list):
            data = dict(data)
            data["items"] = [sanitizer(item) if isinstance(item, dict) else item for item in items]
        return json.dumps(data, indent=2)

    sanitizer = _WORKLOAD_KIND_SANITIZERS.get(kind)
    if sanitizer is None:
        return _WITHHELD_UNEXPECTED_SHAPE
    return json.dumps(sanitizer(data), indent=2)
