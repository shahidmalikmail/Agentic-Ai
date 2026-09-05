"""HCL Commerce 9.1 troubleshooting/diagnostic layer. This module defines
ONLY the 7 Commerce MCP tools - it never modifies, refactors, or bypasses
any of the 31 standard Kubernetes tools in server.py, and it never issues a
kubectl verb outside `get`/`logs` (both already on ssh_client.py's
allow-list). Every kubectl call this module makes goes through the
existing, unmodified kube_core._run() or kube_core.get_pod_logs_impl(), so
the read-only guard and env routing are identical to every other tool -
standard or Commerce.

This module is registered onto its own eks-commerce MCPServer instance
(see commerce_server.py) via the register(mcp) function at the bottom of
this file. It deliberately never imports server.py and never creates or
imports a global MCPServer of its own, so it can be loaded standalone
without pulling in the 31 standard tools.

Component identity is resolved live against real pod data via
commerce_mapping - no pod name is ever hardcoded. Log text is always
bounded and passed through commerce_log_analyzer.redact_secrets() before
being returned. commerce_knowledge supplies only generic, explicitly
labeled reference guidance - this module never invents an HCL Commerce
9.1-specific root cause or fix, and it takes no write/remediation action.

This module COLLECTS AND NORMALIZES evidence (release/component context,
pod health beyond raw phase, deduplicated+severity-ranked log findings,
classified Kubernetes events, log-coverage honesty, current+previous log
pairing on restart) - it does not perform root-cause reasoning itself;
`diagnose_commerce_issue`'s "likely_cause"/"recommended_*" fields are
generic knowledge-base lookups keyed by evidence category, never an
AI-generated or HCL Commerce-specific conclusion synthesized in this file.
"""
from __future__ import annotations

import json
from datetime import timezone
from typing import Optional

import commerce_correlation
import commerce_knowledge
import commerce_log_analyzer
import commerce_mapping
from kube_core import (
    _MAX_OUTPUT_CHARS,
    _run,
    _validate_required_namespace,
    get_pod_logs_impl,
)

_MAX_PODS_PER_COMPONENT = 3
_MAX_LOG_CHARS_PER_POD = 20_000
_MAX_AGGREGATE_CHARS = 100_000
_MAX_EVENTS_CLASSIFIED = 30

# Phase 4B: separate from _MAX_EVENTS_CLASSIFIED - bounds the number of
# CorrelationGroups returned by correlate_commerce_timeline(), not the
# number of observations within one group (that cap lives in
# commerce_correlation._MAX_OBSERVATIONS_PER_GROUP, since it's intrinsic
# to what a CorrelationGroup's evidence_count-vs-observations means).
_MAX_CORRELATION_GROUPS = 20

_DEFAULT_DIAGNOSIS_COMPONENTS = ("ts-app", "crs-app", "ts-web", "store-web")

_KEYWORD_COMPONENT_HINTS: dict[str, tuple[str, ...]] = {
    "ts-app": ("ts-app", "transaction server", "transaction"),
    "crs-app": ("crs-app", "crs", "store server", "rest api"),
    "ts-web": ("ts-web",),
    "store-web": ("store-web", "storefront", "store front"),
    "search-app": ("search", "solr", "elastic"),
    "cache-app": ("cache-app", "dynacache"),
    "nginx": ("nginx", "ingress", "4xx", "5xx", " http "),
    "redis": ("redis", "session store"),
    "tooling-web": ("tooling",),
    "wcbd": ("wcbd",),
    "utils": (" utils",),
}


# --------------------------------------------------------------------------
# Internal helpers - all read-only, all built on kube_core._run/get_pod_logs_impl.
# --------------------------------------------------------------------------

def _run_json(kubectl_command: str, env: str) -> tuple[Optional[dict], Optional[str]]:
    """Run a kubectl command via the existing, unmodified kube_core._run() and
    parse its JSON body. Returns (data, None) on success or (None, the
    original [env=...]-tagged message) on any error/non-JSON output."""
    raw = _run(kubectl_command, env=env)
    first_line = raw.split("\n", 1)[0]
    if "] Error:" in first_line:
        return None, raw
    body = raw.split("\n", 1)[1] if "\n" in raw else raw
    stripped = body.strip()
    if stripped == "(empty result - no matching resources)":
        return {"items": []}, None
    try:
        return json.loads(body), None
    except json.JSONDecodeError:
        return None, f"[env={env}] Error: unexpected non-JSON output (possibly truncated): {stripped[:200]}"


_POD_DISCOVERY_COLUMNS = (
    "NAME:.metadata.name,NAMESPACE:.metadata.namespace,PHASE:.status.phase,"
    "RELEASE:.metadata.labels.release,GROUP:.metadata.labels.group,"
    "RESTARTS:.status.containerStatuses[*].restartCount,"
    "WAITING_REASON:.status.containerStatuses[*].state.waiting.reason,"
    "CONTAINERS:.spec.containers[*].name"
)
_POD_DISCOVERY_COLUMN_COUNT = 8
_CUSTOM_COLUMNS_NONE = "<none>"  # kubectl's placeholder for an absent field


def _parse_pod_discovery_line(line: str) -> Optional[dict]:
    """Parse one `-o custom-columns` row (see _POD_DISCOVERY_COLUMNS) into
    the same nested dict shape commerce_mapping expects from `-o json`
    (metadata.name/namespace/labels, status.phase/restart_count/
    waiting_reason, spec.containers[].name). Returns None for a
    malformed/short row rather than raising, so one bad line can't take
    down the whole fetch.

    RESTARTS/WAITING_REASON come from `[*]`-selected array fields
    (containerStatuses), so for a multi-container pod they may not align
    positionally with CONTAINERS (kubectl omits array entries whose
    sub-field is absent, e.g. a Running container has no `.state.waiting`).
    Every real Commerce pod observed so far has exactly one container, so
    this is exact for them; as a general-purpose simplification (not an
    HCL Commerce-specific assumption) this takes restart_count as the MAX
    of whatever restart counts are present, and waiting_reason as the
    first non-<none> reason found - a pod-level signal rather than a
    precise per-container attribution."""
    parts = line.split()
    if len(parts) < _POD_DISCOVERY_COLUMN_COUNT:
        return None
    name, pod_namespace, phase, release_raw, group_raw, restarts_raw, waiting_raw, containers = parts[
        :_POD_DISCOVERY_COLUMN_COUNT
    ]

    labels: dict[str, str] = {}
    if release_raw != _CUSTOM_COLUMNS_NONE:
        labels["release"] = release_raw
    if group_raw != _CUSTOM_COLUMNS_NONE:
        labels["group"] = group_raw

    restart_count = 0
    if restarts_raw != _CUSTOM_COLUMNS_NONE:
        for token in restarts_raw.split(","):
            try:
                restart_count = max(restart_count, int(token))
            except ValueError:
                continue

    waiting_reason: Optional[str] = None
    if waiting_raw != _CUSTOM_COLUMNS_NONE:
        for token in waiting_raw.split(","):
            if token and token != _CUSTOM_COLUMNS_NONE:
                waiting_reason = token
                break

    container_names = [c for c in containers.split(",") if c and c != _CUSTOM_COLUMNS_NONE]
    return {
        "metadata": {"name": name, "namespace": pod_namespace, "labels": labels},
        "status": {
            "phase": phase,
            "restart_count": restart_count,
            "waiting_reason": waiting_reason,
        },
        "spec": {"containers": [{"name": c} for c in container_names]},
    }


def _fetch_pods(namespace: str, env: str) -> tuple[list[dict], Optional[str]]:
    """Lightweight pod discovery: name/namespace/phase/release/group-label/
    restart-count/waiting-reason/container names only, via `-o
    custom-columns` rather than `-o json`. The commerce namespace's pods
    carry enough annotations that a full `-o json` response can exceed
    _run()'s 120k output cap and get truncated mid-JSON (observed: ~209KB
    for 9 pods in DEV); custom-columns avoids that since component
    discovery never needs the full pod spec. Still routed through the
    unmodified _run()/allow-list - only the requested kubectl flags
    change."""
    raw = _run(
        f"kubectl get pods -n {namespace} -o custom-columns={_POD_DISCOVERY_COLUMNS} --no-headers",
        env=env,
    )
    first_line = raw.split("\n", 1)[0]
    if "] Error:" in first_line:
        return [], raw
    body = raw.split("\n", 1)[1] if "\n" in raw else raw
    if body.strip() in ("(empty result - no matching resources)", "No resources found."):
        return [], None

    items: list[dict] = []
    for line in body.splitlines():
        item = _parse_pod_discovery_line(line)
        if item is not None:
            items.append(item)
    return items, None


def _in_scope_namespaces(default_namespace: str) -> list[str]:
    namespaces = {default_namespace}
    for spec in commerce_mapping.COMPONENT_MAP.values():
        if spec.namespace:
            namespaces.add(spec.namespace)
    return sorted(namespaces)


def _leaf_pods_for_component(
    component: str, default_namespace: str, env: str
) -> tuple[list[tuple[str, commerce_mapping.MatchedPod]], list[str]]:
    """Expand a (possibly role-group) component to leaves, fetch pods per
    distinct namespace once, and return [(leaf_component, MatchedPod), ...]
    plus any fetch errors encountered."""
    leaves = commerce_mapping.expand_roles(component)
    out: list[tuple[str, commerce_mapping.MatchedPod]] = []
    errors: list[str] = []
    ns_cache: dict[str, list[dict]] = {}
    for leaf in leaves:
        leaf_ns = commerce_mapping.resolve_namespace(leaf, default_namespace)
        if leaf_ns not in ns_cache:
            items, err = _fetch_pods(leaf_ns, env)
            if err:
                errors.append(err)
            ns_cache[leaf_ns] = items
        out.extend((leaf, m) for m in commerce_mapping.match_pods(leaf, ns_cache[leaf_ns]))
    return out, errors


def _pod_status_summary(matches: list[commerce_mapping.MatchedPod]) -> dict:
    """Aggregate health across a component's matched pods. Never collapses
    to a single "healthy" bit from phase alone - crash_looping/
    image_pull_backoff/pods_with_restarts are tracked explicitly alongside
    the phase breakdown."""
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


def _collect_component_logs(
    component: str,
    default_namespace: str,
    tail_lines: int,
    since: Optional[str],
    previous: bool,
    env: str,
    auto_previous_on_restart: bool = False,
) -> tuple[list[dict], list[str], int]:
    """Fetch bounded, redacted logs for up to _MAX_PODS_PER_COMPONENT pods
    of a component, via the existing get_pod_logs_impl() (unmodified) -
    every validation/guard it already applies (namespace/pod/container
    regex, tail cap, since format) applies here too.

    Each pod normally yields ONE log entry, `log_source` labeled "current"
    or "previous" to match the `previous` argument. When
    auto_previous_on_restart=True (used by the analysis tools, not
    get_commerce_component_logs), a pod with restart_count > 0 yields TWO
    entries - current AND previous - each explicitly labeled; a pod with
    zero restarts still yields only the current entry (never fetches
    previous logs it has no reason to have)."""
    leaf_pods, fetch_errors = _leaf_pods_for_component(component, default_namespace, env)
    entries: list[dict] = []
    for leaf, pod in leaf_pods[:_MAX_PODS_PER_COMPONENT]:
        if auto_previous_on_restart:
            sources = [False] + ([True] if pod.restart_count > 0 else [])
        else:
            sources = [previous]

        for is_previous in sources:
            raw = get_pod_logs_impl(
                namespace=pod.namespace,
                pod=pod.pod,
                container=pod.container,
                tail_lines=tail_lines,
                previous=is_previous,
                since=since,
                env=env,
            )
            body = raw.split("\n", 1)[1] if raw.startswith("[env=") and "\n" in raw else raw
            lines_returned = len(body.splitlines())
            redacted = commerce_log_analyzer.redact_secrets(body)
            if len(redacted) > _MAX_LOG_CHARS_PER_POD:
                redacted = redacted[:_MAX_LOG_CHARS_PER_POD] + "\n...(pod log truncated)"
            entries.append(
                {
                    "leaf_component": leaf,
                    "pod": pod.pod,
                    "namespace": pod.namespace,
                    "container": pod.container,
                    "phase": pod.phase,
                    "release": pod.release,
                    "release_group": pod.release_group,
                    "restart_count": pod.restart_count,
                    "waiting_reason": pod.waiting_reason,
                    "log_source": "previous" if is_previous else "current",
                    "log": redacted,
                    "log_coverage": {
                        "requested_tail_lines": tail_lines,
                        "lines_returned": lines_returned,
                        # kubectl's --tail applies INSIDE the --since window; if we got
                        # exactly the requested cap, the window may hold more than we
                        # saw. This must never be read as "confirmed complete".
                        "tail_cap_hit": lines_returned >= tail_lines,
                    },
                }
            )
    return entries, fetch_errors, len(leaf_pods)


def _cap(text: str, limit: int = _MAX_AGGREGATE_CHARS) -> str:
    if len(text) > limit:
        return text[:limit] + "\n...(truncated)"
    return text


def _infer_components(issue_description: str) -> list[str]:
    text = (issue_description or "").lower()
    hits = [
        comp
        for comp, keywords in _KEYWORD_COMPONENT_HINTS.items()
        if any(kw in text for kw in keywords)
    ]
    return hits or list(_DEFAULT_DIAGNOSIS_COMPONENTS)


def _confidence(pods_total: int, pods_running: int, matched_categories: int) -> str:
    """Per-component confidence (see item 8: never aggregate this across
    components - a healthy ts-app must not dilute a fully-down crs-app)."""
    if pods_total == 0:
        return "none - no matching pods found for this component"
    if pods_running == 0:
        return "low - no pods currently Running; only cluster-state evidence available, no live logs"
    if matched_categories == 0:
        return "low - pods running, no error patterns matched in the scanned log window"
    if matched_categories >= 2:
        return "medium - multiple error categories observed"
    return "low"


def _finding_to_dict(f: commerce_log_analyzer.CategoryFinding, source: str = "log") -> dict:
    return {
        "category": f.category,
        "severity": commerce_log_analyzer.severity_of(f.category),
        "count": f.count,
        "total_occurrences": f.total_occurrences,
        "distinct_messages": f.distinct_messages,
        "evidence": f.evidence,
        "source": source,
    }


def _classify_warning_events(scope_namespaces: list[str], env: str) -> tuple[list[dict], list[str]]:
    """Fetch Warning events (server-side filtered, see the truncation note
    below) per namespace and classify each message with the SAME
    classifier/vocabulary used for logs (severity_of/classify_log_text),
    tagged source="event". This is what makes oom_killed/crash_loop/
    scheduling_failure/readiness_liveness_failure reachable at all - those
    are Kubernetes status/event signals, essentially never present in
    application log text. One entry per event (no separate raw+classified
    copy), capped and severity-sorted so a noisy namespace doesn't flood
    the response."""
    fetch_errors: list[str] = []
    classified: list[dict] = []
    for scope_ns in scope_namespaces:
        # Filtered server-side to Warning events only: an unfiltered
        # namespace event list can itself exceed _run()'s 120k output cap
        # (observed: ~204KB for 9 pods' worth of events in DEV) and get
        # truncated mid-JSON; type=Warning is a supported field selector
        # for core/v1 Events and keeps this well under the cap.
        data, err = _run_json(f"kubectl get events -n {scope_ns} --field-selector type=Warning -o json", env)
        if data is None:
            fetch_errors.append(err or f"no data for namespace {scope_ns}")
            continue
        for item in data.get("items", []):
            if item.get("type") != "Warning":
                continue
            message = commerce_log_analyzer.redact_secrets(item.get("message", ""))
            analysis = commerce_log_analyzer.classify_log_text(message)
            category = analysis.findings[0].category if analysis.findings else "unclassified"
            classified.append(
                {
                    "category": category,
                    "severity": commerce_log_analyzer.severity_of(category),
                    "source": "event",
                    "namespace": scope_ns,
                    "involved_object": item.get("involvedObject", {}).get("name"),
                    "reason": item.get("reason"),
                    "message": message[:300],
                    "count": item.get("count"),
                    # Phase 4A: kept SEPARATE, never conflated - lastTimestamp is
                    # not "when this started" and firstTimestamp is not "when
                    # every occurrence happened" (K8s can coalesce repeats into
                    # one Event with an incrementing count). Any of the three
                    # may legitimately be null (eventTime is null in the vast
                    # majority of events observed live).
                    "firstTimestamp": item.get("firstTimestamp"),
                    "lastTimestamp": item.get("lastTimestamp"),
                    "eventTime": item.get("eventTime"),
                }
            )

    classified.sort(
        key=lambda e: (
            commerce_log_analyzer.severity_rank(e["category"]),
            -(e.get("count") or 0),
        )
    )
    truncated = len(classified) > _MAX_EVENTS_CLASSIFIED
    classified = classified[:_MAX_EVENTS_CLASSIFIED]
    if truncated:
        classified.append({"note": f"...additional events omitted, capped at {_MAX_EVENTS_CLASSIFIED}"})
    return classified, fetch_errors


# --------------------------------------------------------------------------
# Timeline assembly (Phase 4A). PURE evidence normalization + ordering -
# no correlation, no causal claims, no root-cause reasoning. See module
# docstring: MCP collects/normalizes evidence, Claude/AI reasons about it.
# Not wired into any @mcp.tool() yet - that wiring, and any actual
# temporal correlation, is explicitly deferred to Phase 4B.
# --------------------------------------------------------------------------

_MAX_TIMELINE_ENTRIES = 200

# Kept as three SEPARATE possible rows per event, never collapsed into one
# chosen "the" timestamp - see _classify_warning_events' comment on why
# lastTimestamp/firstTimestamp/eventTime must not be conflated.
_EVENT_TIMESTAMP_FIELDS = (
    ("eventTime", "eventTime"),
    ("firstTimestamp", "event_firstTimestamp"),
    ("lastTimestamp", "event_lastTimestamp"),
)

_TIMELINE_BASE_ROW = {
    "timestamp": None,
    "timestamp_source": None,
    "timezone_known": None,
    "timestamp_precision": None,
    "partial_time": None,
    "component": None,
    "leaf_component": None,
    "release": None,
    "release_group": None,
    "pod": None,
    "container": None,
    "log_source": None,
    "namespace": None,
    "involved_object": None,
    "reason": None,
    "category": None,
    "severity": None,
    "source": None,
    "summary": None,
}


def _apply_parsed_timestamp(row: dict, parsed, source_label: Optional[str]) -> None:
    """Fill a timeline row's timestamp fields from a
    commerce_log_analyzer.ParsedTimestamp (or None). Never fabricates: a
    None `parsed` leaves every timestamp field at its None default."""
    if parsed is None:
        return
    row["timestamp_source"] = source_label
    if parsed.kind == "absolute":
        row["timestamp_precision"] = "absolute"
        row["timezone_known"] = parsed.timezone_known
        row["timestamp"] = parsed.value.isoformat()
        row["_sort_dt"] = parsed.value  # internal only - stripped before return
    elif parsed.kind == "time_only":
        row["timestamp_precision"] = "time_only"
        row["partial_time"] = parsed.partial_time.isoformat()
        row["_sort_time"] = parsed.partial_time  # internal only - stripped before return


def _timeline_rows_from_log_sample(log_entry: dict, finding, sample) -> dict:
    """One row per (deduplicated) evidence sample already produced by
    classify_log_text(). `log_entry` supplies the component/pod/release
    context this module already has (commerce_log_analyzer has none)."""
    row = dict(_TIMELINE_BASE_ROW)
    row.update(
        component=log_entry.get("component"),
        leaf_component=log_entry.get("leaf_component"),
        release=log_entry.get("release"),
        release_group=log_entry.get("release_group"),
        pod=log_entry.get("pod"),
        container=log_entry.get("container"),
        log_source=log_entry.get("log_source"),
        category=finding.category,
        severity=commerce_log_analyzer.severity_of(finding.category),
        source="log",
        summary=sample.text,
    )
    _apply_parsed_timestamp(row, sample.timestamp, "log_line")
    return row


def _timeline_rows_from_event(event: dict) -> list[dict]:
    """Up to 3 rows for one classified event - one per populated
    eventTime/firstTimestamp/lastTimestamp field, each correctly labeled.
    component/leaf_component/release/pod/container are deliberately left
    None: an event's involvedObject is not safely mappable to a Commerce
    canonical component without guessing (see module docstring/Phase 4A
    instructions) - that mapping, if ever added, is not this phase's job."""
    base = dict(_TIMELINE_BASE_ROW)
    base.update(
        namespace=event.get("namespace"),
        involved_object=event.get("involved_object"),
        reason=event.get("reason"),
        category=event.get("category"),
        severity=event.get("severity"),
        source="event",
        summary=event.get("message"),
    )
    rows = []
    for field_name, source_label in _EVENT_TIMESTAMP_FIELDS:
        raw_value = event.get(field_name)
        if not raw_value:
            continue
        row = dict(base)
        parsed = commerce_log_analyzer.parse_timestamp(raw_value)
        _apply_parsed_timestamp(row, parsed, source_label)
        rows.append(row)
    return rows or [dict(base)]


def _timeline_sort_key(entry: dict):
    """Chronological ascending, with two disjoint absolute-time tiers so a
    naive/tz-unknown datetime is NEVER compared against a tz-aware one
    (Python raises on that comparison, and silently assuming a timezone
    to avoid it would violate the "never guess a timezone" requirement).
    Tier 0: timezone-known absolute (converted to a UTC-equivalent naive
    value purely for ordering - this is a correct conversion, not a
    guess, since the offset was explicitly present in the source).
    Tier 1: timezone-UNKNOWN absolute, ordered only among themselves.
    Tier 2: time-only (no date), ordered by time-of-day only among
    themselves - never compared to an absolute timestamp.
    Tier 3: no timestamp at all - always last, stable (encounter) order."""
    dt = entry.get("_sort_dt")
    if dt is not None:
        if entry.get("timezone_known"):
            return (0, dt.astimezone(timezone.utc).replace(tzinfo=None))
        return (1, dt)
    t = entry.get("_sort_time")
    if t is not None:
        return (2, t)
    return (3, 0)


def assemble_timeline(
    log_entries: list[dict],
    events_classified: list[dict],
    max_entries: int = _MAX_TIMELINE_ENTRIES,
) -> list[dict]:
    """Pure assembly: merge already-classified log findings and already-
    classified Warning events into one compact, chronologically-ordered
    timeline. Does NOT fetch anything, does NOT correlate or infer
    causality - purely evidence normalization + ordering (Phase 4B will
    add actual correlation on top of this).

    `log_entries`: caller-built list of dicts, each
    `{"component", "leaf_component", "release", "release_group", "pod",
    "container", "log_source", "findings": [CategoryFinding, ...]}` - the
    caller has already run classify_log_text() and attached its own
    component/pod context; this function has no cluster/mapping knowledge
    of its own (kept pure/testable).

    `events_classified`: the list already produced by
    _classify_warning_events() (its trailing truncation-marker dict, if
    present, is skipped automatically).

    Never fabricates a timestamp - entries with none are kept (never
    dropped), sorted after every timestamped entry, timestamp=None.
    Time-only (bracketed, no date) timestamps are kept distinct
    (timestamp_precision="time_only") and never promoted to a fake
    absolute time. Bounded to `max_entries`, truncated with the same
    "...omitted..." marker convention _classify_warning_events uses."""
    entries: list[dict] = []

    for log_entry in log_entries:
        for finding in log_entry.get("findings") or []:
            for sample in getattr(finding, "evidence_detail", None) or []:
                entries.append(_timeline_rows_from_log_sample(log_entry, finding, sample))

    for event in events_classified:
        if "category" not in event:
            continue  # the "...omitted..." truncation marker, not a real event
        entries.extend(_timeline_rows_from_event(event))

    entries.sort(key=_timeline_sort_key)

    truncated = len(entries) > max_entries
    entries = entries[:max_entries]
    for row in entries:
        row.pop("_sort_dt", None)
        row.pop("_sort_time", None)
    if truncated:
        entries.append({"note": f"...additional timeline entries omitted, capped at {max_entries}"})
    return entries


# --------------------------------------------------------------------------
# Phase 4B: per-pod log_entries adapter for assemble_timeline()/
# correlate_timeline(). Deliberately SEPARATE from correlate_commerce_errors'
# combined-text-per-component path above, which is left completely
# unchanged - this adapter classifies each pod's log text on its OWN
# (via classify_log_text), preserving per-pod/per-release attribution,
# because assemble_timeline() expects one log_entries dict per pod/
# log_source, not one per component. Reuses _collect_component_logs() and
# classify_log_text() unchanged; introduces no new kubectl command.
# --------------------------------------------------------------------------

def _build_per_pod_log_entries(
    components: list[str], default_namespace: str, tail_lines: int, since: Optional[str], env: str
) -> tuple[list[dict], list[str]]:
    """For every matched pod of every requested component, fetch its
    logs (current, plus previous if restarted - same as
    analyze_commerce_component_errors/diagnose_commerce_issue) and
    classify that pod's OWN log text independently. Returns
    (log_entries, fetch_errors) where log_entries is directly consumable
    by assemble_timeline()'s `log_entries` parameter - each entry keeps
    component/leaf_component/release/release_group/pod/container/
    log_source/namespace so no pod attribution is lost."""
    log_entries: list[dict] = []
    fetch_errors: list[str] = []
    for component in components:
        entries, errors, _total_pods = _collect_component_logs(
            component, default_namespace, tail_lines, since, False, env, auto_previous_on_restart=True
        )
        fetch_errors.extend(errors)
        for entry in entries:
            analysis = commerce_log_analyzer.classify_log_text(entry["log"])
            log_entries.append(
                {
                    "component": component,
                    "leaf_component": entry["leaf_component"],
                    "release": entry["release"],
                    "release_group": entry["release_group"],
                    "pod": entry["pod"],
                    "container": entry["container"],
                    "log_source": entry["log_source"],
                    "namespace": entry["namespace"],
                    "findings": analysis.findings,
                }
            )
    return log_entries, fetch_errors


def _correlation_group_to_dict(group: commerce_correlation.CorrelationGroup) -> dict:
    return {
        "group_id": group.group_id,
        "temporal_comparability": group.temporal_comparability,
        "start_timestamp": group.start_timestamp,
        "end_timestamp": group.end_timestamp,
        "duration_seconds": group.duration_seconds,
        "evidence_count": group.evidence_count,
        "components": group.components,
        "pods": group.pods,
        "releases": group.releases,
        "categories": group.categories,
        "severities": group.severities,
        "sources": group.sources,
        "observations": group.observations,
    }


# --------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------

def list_commerce_components(namespace: str = "commerce", env: str = "dev") -> str:
    """List configured HCL Commerce components (ts-app, crs-app, ts-web,
    store-web, search-app, cache-app, nginx, redis, tooling-web, wcbd,
    utils) and, for each, whether matching pods are currently found by
    LIVE discovery (container name, never a hardcoded pod name), their
    phase/restart-count/waiting-reason-derived health state, and their
    live Helm release/release_group. 'search-app' is reported as its
    repeater and slave roles. Absent wcbd/utils/tooling-web is a normal,
    expected outcome, not an error. env selects the target cluster: 'dev'
    (default) or 'uat'."""
    try:
        ns = _validate_required_namespace(namespace)
    except ValueError as exc:
        return f"Error: {exc}"

    scope_namespaces = _in_scope_namespaces(ns)
    pods_by_ns: dict[str, list[dict]] = {}
    fetch_errors: list[str] = []
    for scope_ns in scope_namespaces:
        items, err = _fetch_pods(scope_ns, env)
        if err:
            fetch_errors.append(err)
        pods_by_ns[scope_ns] = items

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
    return f"[env={env}]\n{_cap(json.dumps(body, indent=2), _MAX_OUTPUT_CHARS)}"


def get_commerce_component_logs(
    component: str,
    namespace: str = "commerce",
    tail_lines: int = 100,
    since: Optional[str] = None,
    previous: bool = False,
    env: str = "dev",
) -> str:
    """Fetch bounded, secret-redacted logs for an HCL Commerce component,
    resolved to live pods by container name (see list_commerce_components
    for the component list; 'search-app' expands to both its repeater and
    slave pods). Up to 3 pods per component; tail_lines/since/previous are
    passed through to the existing get_pod_logs_impl() validation and caps
    (tail_lines max 1000). Each entry carries its release/release_group,
    restart_count/waiting_reason, and a log_coverage block
    (requested_tail_lines/lines_returned/tail_cap_hit) so truncation-
    within-window is visible rather than silent. Secret-like values
    (passwords/tokens/API keys/AWS keys/Bearer headers/JDBC passwords) are
    redacted before the logs are returned. env selects 'dev' (default) or
    'uat'."""
    try:
        ns = _validate_required_namespace(namespace)
        component = commerce_mapping.normalize_component(component)
    except ValueError as exc:
        return f"Error: {exc}"

    entries, fetch_errors, total_pods = _collect_component_logs(
        component, ns, tail_lines, since, previous, env
    )
    if not entries:
        spec = commerce_mapping.COMPONENT_MAP[component]
        status = "not_deployed (expected)" if spec.known_optional else "no_matching_pods_found"
        body = {"component": component, "status": status, "fetch_errors": fetch_errors}
        return f"[env={env}]\n{json.dumps(body, indent=2)}"

    body = {
        "component": component,
        "pods_included": len(entries),
        "pods_available": total_pods,
        "fetch_errors": fetch_errors,
        "logs": entries,
    }
    return f"[env={env}]\n{_cap(json.dumps(body, indent=2))}"


def analyze_commerce_component_errors(
    component: str,
    namespace: str = "commerce",
    tail_lines: int = 200,
    since: Optional[str] = None,
    env: str = "dev",
) -> str:
    """Fetch bounded logs for an HCL Commerce component and classify them
    into deduplicated, severity-ranked evidence categories: ERROR/
    Exception/stack traces, HTTP 4xx/5xx, connection failures, timeouts,
    authentication failures, database/Redis/search errors, JVM errors,
    OOMKilled, CrashLoopBackOff, probe failures, scheduling failures,
    upstream/downstream failures. If a pod has restarted (restart_count >
    0), its PREVIOUS container's logs are fetched and analyzed alongside
    the current ones, each explicitly labeled. Returns classified EVIDENCE
    only - no root-cause claim (use diagnose_commerce_issue for that). env
    selects 'dev' (default) or 'uat'."""
    try:
        ns = _validate_required_namespace(namespace)
        component = commerce_mapping.normalize_component(component)
    except ValueError as exc:
        return f"Error: {exc}"

    entries, fetch_errors, total_pods = _collect_component_logs(
        component, ns, tail_lines, since, False, env, auto_previous_on_restart=True
    )
    if not entries:
        spec = commerce_mapping.COMPONENT_MAP[component]
        status = "not_deployed (expected)" if spec.known_optional else "no_matching_pods_found"
        body = {"component": component, "status": status, "fetch_errors": fetch_errors}
        return f"[env={env}]\n{json.dumps(body, indent=2)}"

    pod_reports = []
    for entry in entries:
        analysis = commerce_log_analyzer.classify_log_text(entry["log"])
        pod_reports.append(
            {
                "pod": entry["pod"],
                "leaf_component": entry["leaf_component"],
                "container": entry["container"],
                "phase": entry["phase"],
                "release": entry["release"],
                "release_group": entry["release_group"],
                "restart_count": entry["restart_count"],
                "waiting_reason": entry["waiting_reason"],
                "log_source": entry["log_source"],
                "log_coverage": entry["log_coverage"],
                "lines_scanned": analysis.total_lines,
                "findings": [_finding_to_dict(f) for f in analysis.findings],
            }
        )

    releases = sorted({e["release"] for e in entries if e["release"]})
    body = {
        "component": component,
        "release": releases[0] if len(releases) == 1 else (releases or None),
        "pods_analyzed": len({e["pod"] for e in entries}),
        "pods_available": total_pods,
        "fetch_errors": fetch_errors,
        "pods": pod_reports,
    }
    return f"[env={env}]\n{_cap(json.dumps(body, indent=2))}"


def correlate_commerce_errors(
    components: list[str],
    namespace: str = "commerce",
    tail_lines: int = 200,
    since: Optional[str] = None,
    env: str = "dev",
) -> str:
    """Analyze logs across multiple HCL Commerce components in the same
    window and report which error categories CO-OCCUR (e.g. both ts-app
    and crs-app show 'timeout' in this window). Each component's findings
    are deduplicated and severity-ranked; restarted pods (restart_count >
    0) have their previous-container logs included alongside current ones.
    Reports co-occurring evidence only - it does not assert that one
    component caused the other's errors. env selects 'dev' (default) or
    'uat'."""
    try:
        ns = _validate_required_namespace(namespace)
        norm_components = [commerce_mapping.normalize_component(c) for c in (components or [])]
    except ValueError as exc:
        return f"Error: {exc}"
    if not norm_components:
        return "Error: components must be a non-empty list of known component names."

    per_component: dict[str, object] = {}
    category_to_components: dict[str, set[str]] = {}
    for component in norm_components:
        entries, fetch_errors, total_pods = _collect_component_logs(
            component, ns, tail_lines, since, False, env, auto_previous_on_restart=True
        )
        combined_text = "\n".join(e["log"] for e in entries)
        analysis = commerce_log_analyzer.classify_log_text(combined_text)
        for f in analysis.findings:
            category_to_components.setdefault(f.category, set()).add(component)

        releases = sorted({e["release"] for e in entries if e["release"]})
        release_groups = sorted({e["release_group"] for e in entries if e["release_group"]})
        per_component[component] = {
            "release": releases[0] if len(releases) == 1 else (releases or None),
            "release_group": release_groups[0] if len(release_groups) == 1 else (release_groups or None),
            "pods_analyzed": len({e["pod"] for e in entries}),
            "pods_available": total_pods,
            "fetch_errors": fetch_errors,
            "log_coverage": {
                "pods_sampled": len({e["pod"] for e in entries}),
                "any_tail_cap_hit": any(e["log_coverage"]["tail_cap_hit"] for e in entries),
            },
            "top_findings": [_finding_to_dict(f) for f in analysis.findings],
        }

    shared = {cat: sorted(comps) for cat, comps in category_to_components.items() if len(comps) > 1}

    body = {
        "components": per_component,
        "since": since,
        "co_occurring_categories": shared,
        "note": (
            "Co-occurrence means the same error category appeared in each listed "
            "component's logs within this call's window; it is not a confirmed "
            "causal link."
        ),
    }
    return f"[env={env}]\n{_cap(json.dumps(body, indent=2))}"


def diagnose_commerce_issue(
    issue_description: str,
    namespace: str = "commerce",
    components: Optional[list[str]] = None,
    since: str = "30m",
    env: str = "dev",
) -> str:
    """Best-effort, evidence-based diagnosis for an HCL Commerce issue
    description (e.g. 'checkout is failing', 'search is slow', 'nginx 5xx
    errors'). Picks relevant components (from `components`, or inferred by
    keyword from `issue_description`, or a default core set: ts-app,
    crs-app, ts-web, store-web), then per component reports pod health
    (phase/crash-looping/restarts, never "healthy" from phase alone),
    deduplicated+severity-ranked log findings (with previous-container logs
    included for any restarted pod) and its live release/release_group.
    Warning events are classified with the SAME vocabulary as logs
    (source="event") so Kubernetes-native signals like OOMKilled/
    CrashLoopBackOff/FailedScheduling are covered even though they rarely
    appear in application log text. Confidence is reported PER COMPONENT,
    never averaged across them. Guidance in 'likely_cause'/
    'recommended_fix' comes from a static, generic local knowledge base
    (commerce_knowledge.py), explicitly labeled as general guidance, NOT a
    verified HCL Commerce 9.1 procedure or an AI-generated conclusion -
    this tool collects and normalizes evidence only; it takes no action.
    env selects 'dev' (default) or 'uat'."""
    try:
        ns = _validate_required_namespace(namespace)
        target_components = (
            [commerce_mapping.normalize_component(c) for c in components]
            if components
            else _infer_components(issue_description)
        )
    except ValueError as exc:
        return f"Error: {exc}"

    scope_namespaces = sorted(
        {ns} | {commerce_mapping.resolve_namespace(c, ns) for c in target_components}
    )
    events_classified, event_fetch_errors = _classify_warning_events(scope_namespaces, env)

    components_out: dict[str, object] = {}
    confidence: dict[str, str] = {}
    knowledge_notes: dict[str, commerce_knowledge.KnowledgeEntry] = {}
    category_to_components: dict[str, set[str]] = {}

    for component in target_components:
        leaf_pods, pod_fetch_errors = _leaf_pods_for_component(component, ns, env)
        pod_status = _pod_status_summary([m for _leaf, m in leaf_pods])

        entries, log_fetch_errors, total_pods = _collect_component_logs(
            component, ns, 300, since, False, env, auto_previous_on_restart=True
        )
        combined_text = "\n".join(e["log"] for e in entries)
        analysis = commerce_log_analyzer.classify_log_text(combined_text)
        for f in analysis.findings:
            category_to_components.setdefault(f.category, set()).add(component)
            entry_kb = commerce_knowledge.lookup(f.category)
            if entry_kb and f.category not in knowledge_notes:
                knowledge_notes[f.category] = entry_kb

        pods_running = pod_status["phase_counts"].get("Running", 0)
        confidence[component] = _confidence(total_pods, pods_running, len(analysis.findings))

        releases = sorted({e["release"] for e in entries if e["release"]})
        components_out[component] = {
            "release": releases[0] if len(releases) == 1 else (releases or None),
            "release_group": next((e["release_group"] for e in entries if e["release_group"]), None),
            "pod_status": pod_status,
            "log_coverage": {
                "pods_sampled": len({e["pod"] for e in entries}),
                "any_tail_cap_hit": any(e["log_coverage"]["tail_cap_hit"] for e in entries),
            },
            "top_findings": [_finding_to_dict(f) for f in analysis.findings],
            "fetch_errors": pod_fetch_errors + log_fetch_errors,
        }

    # Warning events feed the same knowledge lookup as log findings - this
    # is what makes oom_killed/crash_loop/scheduling_failure/
    # readiness_liveness_failure reachable at all (see _classify_warning_events).
    for event in events_classified:
        category = event.get("category")
        if not category or category == "unclassified":
            continue
        category_to_components.setdefault(category, set())  # tracked for co-occurrence completeness
        if category not in knowledge_notes:
            entry_kb = commerce_knowledge.lookup(category)
            if entry_kb:
                knowledge_notes[category] = entry_kb

    if not knowledge_notes:
        likely_cause_lines = [
            "No error pattern in the scanned logs/events matches a known category, "
            "and/or no pods are currently running to produce logs. No likely cause "
            "can be stated from evidence."
        ]
    else:
        likely_cause_lines = [
            f"[{cat}] (general guidance, not evidence-verified): {entry_kb.general_guidance}"
            for cat, entry_kb in knowledge_notes.items()
        ]

    investigation_lines = [entry_kb.typical_investigation for entry_kb in knowledge_notes.values()]
    any_non_running = any(
        c["pod_status"]["total"] > 0 and c["pod_status"]["phase_counts"].get("Running", 0) == 0
        for c in components_out.values()
    )
    if any_non_running:
        investigation_lines.insert(
            0,
            "At least one considered component has matched pods with none in the "
            "Running phase (see per-component pod_status) - confirm whether this is "
            "an intentional scale-down before investigating logs further.",
        )
    if not investigation_lines:
        investigation_lines.append(
            "No specific leads from log/event evidence; check per-component "
            "pod_status and events_classified first."
        )

    fix_lines = [entry_kb.general_next_step for entry_kb in knowledge_notes.values()]
    fix_lines.append(
        "This MCP is read-only and applies no fixes automatically. The above are "
        "generic, non-product-specific suggestions from a static local knowledge "
        "base, not a verified HCL Commerce 9.1 runbook and not an AI-generated "
        "conclusion - confirm against real documentation/runbooks before acting, "
        "and route any change through your normal change process."
    )

    shared = {cat: sorted(comps) for cat, comps in category_to_components.items() if len(comps) > 1}

    body = {
        "issue_description": issue_description,
        "since": since,
        "namespaces_checked": scope_namespaces,
        "components": components_out,
        "cross_component_signals": {
            "co_occurring_categories": shared,
            "events_classified": events_classified,
        },
        "confidence": confidence,
        "likely_cause": likely_cause_lines,
        "recommended_investigation": investigation_lines,
        "recommended_fix": fix_lines,
        "fetch_errors": event_fetch_errors,
    }
    return f"[env={env}]\n{_cap(json.dumps(body, indent=2))}"


def get_commerce_health(namespace: str = "commerce", env: str = "dev") -> str:
    """Read-only health snapshot for HCL Commerce: per-component pod status
    (phase breakdown, crash_looping/image_pull_backoff/pods_with_restarts
    counts - never "healthy" from phase alone) and live release/
    release_group, plus recent Warning events (classified with the same
    category/severity vocabulary as logs) in the commerce/nginx/redis
    namespaces. No logs are fetched by this tool - use
    get_commerce_component_logs/analyze_commerce_component_errors for
    that. env selects 'dev' (default) or 'uat'."""
    try:
        ns = _validate_required_namespace(namespace)
    except ValueError as exc:
        return f"Error: {exc}"

    scope_namespaces = _in_scope_namespaces(ns)
    pods_by_ns: dict[str, list[dict]] = {}
    fetch_errors: list[str] = []
    for scope_ns in scope_namespaces:
        items, err = _fetch_pods(scope_ns, env)
        if err:
            fetch_errors.append(err)
        pods_by_ns[scope_ns] = items

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

    events_classified, event_fetch_errors = _classify_warning_events(scope_namespaces, env)

    body = {
        "namespaces_checked": scope_namespaces,
        "fetch_errors": fetch_errors + event_fetch_errors,
        "components": components,
        "events_classified": events_classified,
    }
    return f"[env={env}]\n{_cap(json.dumps(body, indent=2), _MAX_OUTPUT_CHARS)}"


def correlate_commerce_timeline(
    components: list[str],
    namespace: str = "commerce",
    tail_lines: int = 200,
    since: Optional[str] = None,
    window_seconds: int = commerce_correlation.DEFAULT_WINDOW_SECONDS,
    env: str = "dev",
) -> str:
    """Phase 4B: group already-collected, already-classified evidence
    (per-pod logs + classified Warning events, fetched via the SAME
    read-only path as the other commerce tools) into groups of
    observations that occurred within `window_seconds` of each other.

    CORRELATION IS NOT CAUSATION: a group means only "these observations
    happened close together in time" - it never claims or implies that
    one component's errors caused another's. That judgment is left to a
    human or a later, explicitly separate diagnosis phase - this tool
    collects and organizes evidence only.

    Unlike correlate_commerce_errors() (whole-tail-window co-occurrence
    per component, unchanged by this tool), each pod's log is classified
    independently here so per-pod/per-release attribution survives into
    every observation. Grouping is by parsed timestamp proximity alone -
    never by component identity or any assumed dependency; no component
    dependency graph exists or is inferred anywhere in this tool.

    Timestamps are compared only within the same comparability tier -
    absolute-with-known-timezone, absolute-with-unknown-timezone, and
    time-only (no date) are NEVER mixed with each other. Observations
    with no usable timestamp are preserved separately under
    "uncorrelated", never dropped and never assigned a fabricated time.

    window_seconds is clamped to [1, 3600] and the value actually used is
    always returned as "window_seconds" in the response - 60s is a
    reasonable starting default, not a validated causal/incident
    constant. env selects 'dev' (default) or 'uat'."""
    try:
        ns = _validate_required_namespace(namespace)
        norm_components = [commerce_mapping.normalize_component(c) for c in (components or [])]
    except ValueError as exc:
        return f"Error: {exc}"
    if not norm_components:
        return "Error: components must be a non-empty list of known component names."

    log_entries, log_fetch_errors = _build_per_pod_log_entries(norm_components, ns, tail_lines, since, env)

    scope_namespaces = sorted(
        {ns} | {commerce_mapping.resolve_namespace(c, ns) for c in norm_components}
    )
    events_classified, event_fetch_errors = _classify_warning_events(scope_namespaces, env)

    timeline = assemble_timeline(log_entries, events_classified)
    groups, uncorrelated, resolved_window = commerce_correlation.correlate_timeline(
        timeline, window_seconds=window_seconds
    )

    truncated = len(groups) > _MAX_CORRELATION_GROUPS
    groups_out = [_correlation_group_to_dict(g) for g in groups[:_MAX_CORRELATION_GROUPS]]
    if truncated:
        groups_out.append(
            {"note": f"...additional correlation groups omitted, capped at {_MAX_CORRELATION_GROUPS}"}
        )

    body = {
        "components": norm_components,
        "since": since,
        "window_seconds": resolved_window,
        "namespaces_checked": scope_namespaces,
        "fetch_errors": log_fetch_errors + event_fetch_errors,
        "timeline_entries_considered": len(timeline),
        "correlation_groups": groups_out,
        "uncorrelated": uncorrelated,
        "note": (
            "Temporal proximity only - groups reflect observations that occurred close "
            "together in time. This is NOT a causal claim: it does not assert that any "
            "component caused another's errors."
        ),
    }
    return f"[env={env}]\n{_cap(json.dumps(body, indent=2))}"


# --------------------------------------------------------------------------
# Registration - called by commerce_server.py against its own MCPServer
# instance. Deliberately not a module-level `mcp = MCPServer(...)` +
# `@mcp.tool()` pattern: this module must stay importable without creating
# or depending on any particular MCP server instance, so it can be unit
# tested and reused without side effects on import.
# --------------------------------------------------------------------------

def register(mcp) -> None:
    """Register exactly the 7 HCL Commerce diagnostic tools onto `mcp`."""
    mcp.add_tool(list_commerce_components)
    mcp.add_tool(get_commerce_component_logs)
    mcp.add_tool(analyze_commerce_component_errors)
    mcp.add_tool(correlate_commerce_errors)
    mcp.add_tool(diagnose_commerce_issue)
    mcp.add_tool(get_commerce_health)
    mcp.add_tool(correlate_commerce_timeline)
