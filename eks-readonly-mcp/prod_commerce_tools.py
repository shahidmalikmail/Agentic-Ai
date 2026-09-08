"""HCL Commerce PROD-only discovery/health tools (P12A). This module
defines ONLY the 2 PROD Commerce MCP tools authorized for this phase:
list_prod_commerce_components and get_prod_commerce_health. It never
implements log retrieval, error analysis, correlation, timeline, diagnosis,
or recommendation - those are explicitly out of scope for P12A.

Neither tool exposes an `environment`/`env` parameter, and neither accepts
a `namespace="all"`/omitted-meaning-all value: this server is intrinsically
PROD-only by construction (see prod_commerce_config.py - one hardcoded
BastionSSHClient, no environment dict, no resolver), and every kubectl call
here is explicitly scoped to one specific namespace, never `-A`.

Component identity is resolved live against real pod data via
commerce_mapping (imported unmodified) - no pod name, container name list,
or namespace mapping is duplicated or hardcoded here beyond what
commerce_mapping.COMPONENT_MAP already defines. commerce_mapping is
reused as-is because it is pure data/resolution logic with no I/O, no
credentials, and no environment coupling of any kind.

Pod discovery uses a fixed, PROD-only `kubectl get pods -o custom-columns=...`
specification - modeled on the same prevention-based philosophy already
proven by prod_pod_columns.py: the ONLY Kubernetes fields ever requested
from the API server, at all, by this module are exactly these 8 (see
_POD_DISCOVERY_COLUMNS_SPEC below, which contains no others):

    1. .metadata.name
    2. .metadata.namespace
    3. .status.phase
    4. .metadata.labels.release   (exact key only - never a wildcard/
       all-labels expression such as `.metadata.labels` or
       `.metadata.labels[*]`, and no other label of any kind)
    5. .metadata.labels.group     (exact key only - same restriction as #4)
    6. .status.containerStatuses[*].restartCount
    7. .status.containerStatuses[*].state.waiting.reason
    8. .spec.containers[*].name

Everything else - arbitrary/wildcard labels, annotations, env, envFrom,
data, stringData, secretKeyRef, configMapKeyRef, secretRef, configMapRef,
serviceAccount, volumes, imagePullSecrets, command, args, container images,
any other metadata/spec/status field, conditions, and events - is NEVER
requested from the API server in the first place; there is no redaction
step for any of these to get wrong, because none of them are ever fetched.
The `release`/`group` labels are the SOLE, INTENTIONAL, EXPLICIT exception
to "no labels" - required for commerce_mapping's live release
identification - and only those two exact keys, never any other label.

This module is written fresh rather than importing prod_pod_columns.py's
parser, because that parser's fixed column set (pod IP/node/images/ready/
restarts) does not carry the release/group label or waiting-reason data
commerce_mapping needs, and is not meant to be reused for a different
column contract.

Unlike commerce_tools.py's DEV/UAT discovery parser (which skips a single
malformed row so one bad line can't take down the whole fetch),
this PROD parser FAILS CLOSED on any malformed row: the entire fetch for
that namespace is withheld rather than silently dropping a row.

Output is always the small, controlled JSON shape defined below - never
raw kubectl JSON. On any parsing/schema failure, a fixed safe withheld
response is returned instead of raw or partial data, matching the P10/P11
fail-closed philosophy.
"""
from __future__ import annotations

import json
from typing import Optional

import commerce_mapping
from prod_commerce_config import run_prod_commerce_readonly
from readonly_exec import validate_namespace

_DEFAULT_NAMESPACE = "commerce"
_MAX_OUTPUT_CHARS = 120_000
_NONE = "<none>"

# Fixed, hardcoded - never caller-controlled, never derived from the
# `namespace` argument. This is the COMPLETE, exhaustive list of the only 8
# fields this module ever requests (see module docstring above for the
# full contract): .metadata.name, .metadata.namespace, .status.phase,
# .metadata.labels.release, .metadata.labels.group,
# .status.containerStatuses[*].restartCount,
# .status.containerStatuses[*].state.waiting.reason,
# .spec.containers[*].name. The two label paths are exact keys only -
# never `.metadata.labels` or `.metadata.labels[*]` (which would return
# every label on the pod) - and are the sole intentional exception to
# "no labels/annotations of any kind". Nothing else (env/envFrom/data/
# stringData/secretKeyRef/configMapKeyRef/secretRef/configMapRef/service
# account fields/any other annotation or label/volumes/imagePullSecrets/
# command/args/container images) is ever requested from the API server.
_POD_DISCOVERY_COLUMNS_SPEC = (
    "NAME:.metadata.name,NAMESPACE:.metadata.namespace,PHASE:.status.phase,"
    "RELEASE:.metadata.labels.release,GROUP:.metadata.labels.group,"
    "RESTARTS:.status.containerStatuses[*].restartCount,"
    "WAITING_REASON:.status.containerStatuses[*].state.waiting.reason,"
    "CONTAINERS:.spec.containers[*].name"
)
_POD_DISCOVERY_COLUMN_COUNT = 8

_WITHHELD_FAIL_CLOSED = json.dumps(
    {"error": "PROD Commerce data could not be safely parsed and was withheld before being returned."}
)


class ProdCommerceNamespaceError(ValueError):
    """Raised when a caller-supplied namespace would mean 'all namespaces'
    or otherwise fails validation. Never silently coerced to `-A`."""


def _validate_commerce_namespace(namespace: Optional[str]) -> str:
    """Resolve and validate the target namespace for PROD Commerce
    discovery/health. Defaults to 'commerce' when omitted/None/empty.
    Explicitly rejects anything that would mean "all namespaces"
    (None/""/"all") once a value has been supplied - this tool must never
    silently expand to a cluster-wide scan."""
    candidate = namespace if namespace else _DEFAULT_NAMESPACE
    validated = validate_namespace(candidate)
    if validated is None:
        raise ProdCommerceNamespaceError(
            f"Invalid namespace {namespace!r}: PROD Commerce discovery/health requires a "
            "specific namespace - 'all' namespaces is not a valid target for this tool."
        )
    return validated


def _in_scope_namespaces(default_namespace: str) -> list[str]:
    """Every namespace PROD Commerce discovery/health may touch: the
    caller's namespace plus any component's namespace override (nginx,
    redis) - never a wildcard."""
    namespaces = {default_namespace}
    for spec in commerce_mapping.COMPONENT_MAP.values():
        if spec.namespace:
            namespaces.add(spec.namespace)
    return sorted(namespaces)


def _parse_pod_discovery_line(line: str) -> Optional[dict]:
    """Parse one `-o custom-columns` row into the nested dict shape
    commerce_mapping expects (metadata.name/namespace/labels,
    status.phase/restart_count/waiting_reason, spec.containers[].name).
    Returns None for ANY malformed/short/ambiguous row - the caller treats
    None as "fail this namespace's fetch closed", never as "skip this row
    and continue" (unlike commerce_tools.py's DEV/UAT parser)."""
    parts = line.split()
    if len(parts) != _POD_DISCOVERY_COLUMN_COUNT:
        return None
    name, namespace, phase, release_raw, group_raw, restarts_raw, waiting_raw, containers_raw = parts

    if not name or not namespace or not phase or not containers_raw or containers_raw == _NONE:
        return None

    labels: dict[str, str] = {}
    if release_raw != _NONE:
        labels["release"] = release_raw
    if group_raw != _NONE:
        labels["group"] = group_raw

    restart_count = 0
    if restarts_raw != _NONE:
        for token in restarts_raw.split(","):
            try:
                restart_count = max(restart_count, int(token))
            except ValueError:
                # Fail closed: PROD never silently defaults an unparseable
                # restart count to 0.
                return None

    waiting_reason: Optional[str] = None
    if waiting_raw != _NONE:
        for token in waiting_raw.split(","):
            if token and token != _NONE:
                waiting_reason = token
                break

    container_names = [c for c in containers_raw.split(",") if c and c != _NONE]
    if not container_names:
        return None

    return {
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "status": {"phase": phase, "restart_count": restart_count, "waiting_reason": waiting_reason},
        "spec": {"containers": [{"name": c} for c in container_names]},
    }


def _parse_pod_discovery(raw_output: str) -> Optional[list[dict]]:
    """Parse the full multi-row `-o custom-columns` body. Fails CLOSED
    (returns None) on ANY malformed row - the entire fetch is withheld,
    never a partial pod list."""
    stripped = raw_output.strip()
    if not stripped or stripped in ("(empty result - no matching resources)", "No resources found."):
        return []
    pods: list[dict] = []
    for line in raw_output.splitlines():
        if not line.strip():
            return None
        item = _parse_pod_discovery_line(line)
        if item is None:
            return None
        pods.append(item)
    return pods


def _fetch_pods(namespace: str) -> tuple[Optional[list[dict]], Optional[str]]:
    """Fetch pods in one PROD namespace via the fixed custom-columns spec
    above. Returns (pods, None) on success, or (None, safe_error_message)
    on any SSH/kubectl/parsing failure - a fetch error is never silently
    treated as "zero pods found"."""
    raw = run_prod_commerce_readonly(
        f"kubectl get pods -n {namespace} -o custom-columns={_POD_DISCOVERY_COLUMNS_SPEC} --no-headers"
    )
    first_line = raw.split("\n", 1)[0]
    if "] Error:" in first_line:
        return None, raw
    body = raw.split("\n", 1)[1] if "\n" in raw else ""
    pods = _parse_pod_discovery(body)
    if pods is None:
        return None, f"[prod-commerce] Error: pod discovery output for namespace {namespace!r} could not be safely parsed and was withheld."
    return pods, None


def _pod_status_summary(matches: list[commerce_mapping.MatchedPod]) -> dict:
    """Aggregate health across a component's matched pods. Never collapses
    to a single "healthy" bit from phase alone."""
    phase_counts: dict[str, int] = {}
    crash_looping = 0
    image_pull_backoff = 0
    pods_with_restarts = 0
    for m in matches:
        health = commerce_mapping.pod_health_summary(m)
        phase_counts[health["phase"]] = phase_counts.get(health["phase"], 0) + 1
        if health["state"] == "crash_looping":
            crash_looping += 1
        elif health["state"] == "image_pull_backoff":
            image_pull_backoff += 1
        if health["restart_count"] > 0:
            pods_with_restarts += 1
    return {
        "total": len(matches),
        "phase_counts": phase_counts,
        "crash_looping": crash_looping,
        "image_pull_backoff": image_pull_backoff,
        "pods_with_restarts": pods_with_restarts,
    }


def _cap(text: str, limit: int = _MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...(output truncated)"


def list_prod_commerce_components(namespace: str = "commerce") -> str:
    """List configured HCL Commerce components (ts-app, crs-app, ts-web,
    store-web, search-app, cache-app, nginx, redis, tooling-web, wcbd,
    utils) in PROD and, for each, whether matching pods are currently found
    by LIVE discovery (container name, never a hardcoded pod name), their
    phase/restart-count/waiting-reason-derived health state, and their live
    Helm release/release_group. 'search-app' is reported as its repeater
    and slave roles. Absent wcbd/utils/tooling-web is a normal, expected
    outcome, not an error. This tool is PROD-only - there is no
    environment parameter; namespace defaults to 'commerce' and must be a
    specific namespace, never 'all'."""
    try:
        ns = _validate_commerce_namespace(namespace)
    except ValueError as exc:
        return f"Error: {exc}"

    try:
        scope_namespaces = _in_scope_namespaces(ns)
        pods_by_ns: dict[str, list[dict]] = {}
        fetch_errors: list[str] = []
        for scope_ns in scope_namespaces:
            items, err = _fetch_pods(scope_ns)
            if err:
                fetch_errors.append(err)
            pods_by_ns[scope_ns] = items if items is not None else []

        components: dict[str, object] = {}
        for component in commerce_mapping.ALL_COMPONENTS:
            leaves = commerce_mapping.expand_roles(component)
            roles = []
            total_matches = 0
            for leaf in leaves:
                leaf_ns = commerce_mapping.resolve_namespace(leaf, ns)
                matches = commerce_mapping.match_pods(leaf, pods_by_ns.get(leaf_ns, []))
                total_matches += len(matches)
                roles.append(
                    {
                        "leaf_component": leaf,
                        "namespace": leaf_ns,
                        "matched_pods": [
                            {
                                "pod": m.pod,
                                "container": m.container,
                                "release": m.release,
                                "release_group": m.release_group,
                                **commerce_mapping.pod_health_summary(m),
                            }
                            for m in matches
                        ],
                    }
                )
            spec = commerce_mapping.COMPONENT_MAP[component]
            status = "found" if total_matches else ("not_deployed" if spec.known_optional else "no_matching_pods")
            components[component] = {"status": status, "roles": roles}

        body = {"namespaces_checked": scope_namespaces, "fetch_errors": fetch_errors, "components": components}
        return f"[prod-commerce]\n{_cap(json.dumps(body, indent=2))}"
    except Exception:
        # Defense in depth: any unexpected internal error - never an
        # unhandled traceback reaching the MCP layer, never a fallback to
        # raw/partial data.
        return f"[prod-commerce]\n{_WITHHELD_FAIL_CLOSED}"


def get_prod_commerce_health(namespace: str = "commerce") -> str:
    """Read-only health snapshot for HCL Commerce in PROD: per-component
    pod status (phase breakdown, crash_looping/image_pull_backoff/
    pods_with_restarts counts - never "healthy" from phase alone) and live
    release/release_group. No logs are fetched, no events are classified,
    and no error analysis/correlation/diagnosis is performed by this tool
    (out of scope for P12A) - use a future PROD Commerce log/diagnosis
    capability for that once separately approved. This tool is PROD-only -
    there is no environment parameter; namespace defaults to 'commerce'
    and must be a specific namespace, never 'all'."""
    try:
        ns = _validate_commerce_namespace(namespace)
    except ValueError as exc:
        return f"Error: {exc}"

    try:
        scope_namespaces = _in_scope_namespaces(ns)
        pods_by_ns: dict[str, list[dict]] = {}
        fetch_errors: list[str] = []
        for scope_ns in scope_namespaces:
            items, err = _fetch_pods(scope_ns)
            if err:
                fetch_errors.append(err)
            pods_by_ns[scope_ns] = items if items is not None else []

        components: dict[str, object] = {}
        for component in commerce_mapping.ALL_COMPONENTS:
            leaves = commerce_mapping.expand_roles(component)
            matches: list[commerce_mapping.MatchedPod] = []
            for leaf in leaves:
                leaf_ns = commerce_mapping.resolve_namespace(leaf, ns)
                matches.extend(commerce_mapping.match_pods(leaf, pods_by_ns.get(leaf_ns, [])))

            spec = commerce_mapping.COMPONENT_MAP[component]
            pod_status = _pod_status_summary(matches)
            if pod_status["total"] == 0:
                status = "not_deployed" if spec.known_optional else "no_matching_pods"
            elif pod_status["crash_looping"] or pod_status["image_pull_backoff"]:
                status = "attention_needed"
            elif pod_status["phase_counts"].get("Running", 0) == pod_status["total"]:
                status = "healthy"
            else:
                status = "attention_needed"

            releases = sorted({m.release for m in matches if m.release})
            release_groups = sorted({m.release_group for m in matches if m.release_group})
            components[component] = {
                "status": status,
                "release": releases[0] if len(releases) == 1 else (releases or None),
                "release_group": release_groups[0] if len(release_groups) == 1 else (release_groups or None),
                "pod_status": pod_status,
            }

        body = {"namespaces_checked": scope_namespaces, "fetch_errors": fetch_errors, "components": components}
        return f"[prod-commerce]\n{_cap(json.dumps(body, indent=2))}"
    except Exception:
        # Defense in depth: any unexpected internal error - never an
        # unhandled traceback reaching the MCP layer, never a fallback to
        # raw/partial data.
        return f"[prod-commerce]\n{_WITHHELD_FAIL_CLOSED}"


def register(mcp) -> None:
    """Register exactly the 2 PROD Commerce discovery/health tools
    authorized for P12A onto `mcp`. No other tool may be added here."""
    mcp.add_tool(list_prod_commerce_components)
    mcp.add_tool(get_prod_commerce_health)
