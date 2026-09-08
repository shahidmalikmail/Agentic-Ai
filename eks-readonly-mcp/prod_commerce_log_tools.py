"""HCL Commerce PROD-only safe log evidence tool (P12B). This module
defines ONLY the get_prod_commerce_logs tool. It never implements
correlation, timeline, diagnosis, or recommendation - those remain out of
scope for this phase.

PREVENTION-FIRST DESIGN: raw pod log text is fetched and classified
in-memory only, for the duration of one call. It is NEVER placed into the
output structure, NEVER logged, NEVER persisted, and NEVER embedded in an
exception message. What crosses the MCP boundary is exclusively structured
evidence (category/severity/counts/timestamps/a sanitizer-gated normalized
message) - never a raw log line or log body. This mirrors the exact
philosophy already proven for Kubernetes objects by prod_pod_columns.py/
prod_workload_columns.py (ask for less, and prevention over redaction),
now applied to free-text logs instead of structured API fields.

Reused unmodified, pure logic:
  - commerce_mapping (component -> pod/container resolution; no I/O)
  - commerce_log_analyzer.classify_log_text/severity_of (line
    classification + severity ranking; no I/O) - its own `evidence`/
    `evidence_detail` samples (already redacted+capped by that module) are
    used ONLY transiently here, to derive exception_class/normalized_message
    candidates, and are never themselves returned.
  - prod_commerce_tools._fetch_pods / _validate_commerce_namespace (the
    already-approved P12A pod-discovery and namespace-validation logic for
    this exact PROD Commerce subsystem/credential source - reusing it here
    avoids duplicating tested logic; it introduces no new credential or
    environment coupling, since both modules route through the same
    prod_commerce_config.run_prod_commerce_readonly()).

This module never depends on commerce_tools.py (DEV/UAT-coupled via
kube_core) or kube_core.py (which itself loads DEV/UAT config at import
time) - see prod_commerce_config.py for the PROD-only credential source
this module transitively uses via prod_commerce_tools.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Optional

import commerce_log_analyzer
import commerce_mapping
from prod_commerce_config import run_prod_commerce_readonly
from prod_commerce_log_sanitizer import sanitize_candidate
from prod_commerce_tools import ProdCommerceNamespaceError, _fetch_pods, _validate_commerce_namespace

_MAX_PODS_PER_COMPONENT = 3
_DEFAULT_TAIL_LINES = 50
_MAX_TAIL_LINES = 200
_MAX_EVIDENCE_RECORDS = 20
_MAX_EXCERPT_CHARS = 200  # reserved for a future, separately-approved excerpt feature; unused in P12B v1

_EXCEPTION_CLASS_PATTERN = re.compile(r"([\w.$]*(?:Exception|Error))\b")
_EXCEPTION_LIKE_CATEGORIES = {"exception", "jvm_application_error", "database_error", "redis_error", "search_error"}

# Strips a parenthesized "(File.java:42)" suffix from a stack-trace frame
# line, leaving only the method reference (e.g. "at pkg.Class.method") -
# used ONLY as a fingerprint hash preimage for the stack_trace category,
# never returned as output (see _build_evidence_records).
_FRAME_SIGNATURE_PATTERN = re.compile(r"\([^)]*\)")

_TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\[\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\]"
)
_UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_LONG_NUMBER_PATTERN = re.compile(r"\b\d{4,}\b")

_TOP_LEVEL_KEYS = {"namespace", "component", "evidence", "log_coverage", "fetch_errors"}
_EVIDENCE_KEYS = {
    "pod", "container", "log_source", "category", "severity", "exception_class",
    "normalized_message", "stack_fingerprint", "frame_count", "occurrence_count",
    "first_seen", "last_seen", "timestamp_known", "excerpt",
}
_COVERAGE_KEYS = {"requested_tail_lines", "lines_scanned", "tail_cap_hit", "output_truncated"}
_FETCH_ERROR_KEYS = {"category", "pod"}
_FETCH_ERROR_CATEGORIES = {
    "pod_discovery_failed", "log_fetch_failed", "previous_logs_unavailable", "log_parse_failed",
}

_WITHHELD_FAIL_CLOSED = json.dumps(
    {"error": "PROD Commerce log data could not be safely parsed and was withheld before being returned."}
)


class ProdCommerceContainerError(ValueError):
    """Raised when a caller-supplied container is not associated with the
    resolved component. Never silently ignored or passed through to
    kubectl unvalidated."""


def _normalize_message(line: str) -> str:
    """Collapse timestamp/UUID/long-numeric-id tokens to fixed
    placeholders - same normalization CONCEPT as
    commerce_log_analyzer._normalize_for_dedup (that function is private
    to commerce_log_analyzer.py and is not imported here, so this module
    stays fully self-contained; the regexes are intentionally the exact
    same shapes)."""
    normalized = _TIMESTAMP_PATTERN.sub("<TS>", line)
    normalized = _UUID_PATTERN.sub("<UUID>", normalized)
    normalized = _LONG_NUMBER_PATTERN.sub("<NUM>", normalized)
    return normalized.strip()


def _validate_tail_lines(tail_lines: Any) -> int:
    """Clamp to [1, _MAX_TAIL_LINES]. Never raises - an invalid input
    falls back to the default rather than failing the whole call, since
    tail_lines is a convenience bound, not a security boundary (the
    security boundary is the fixed command shape itself)."""
    try:
        value = int(tail_lines)
    except (TypeError, ValueError):
        return _DEFAULT_TAIL_LINES
    return max(1, min(value, _MAX_TAIL_LINES))


def _validate_container_for_component(leaves: list[str], container: Optional[str]) -> Optional[str]:
    """If container is None, no filter is applied (each pod's own
    commerce_mapping-matched container is used). If given, it must match
    one of the resolved component's own known exact container names or
    regex patterns for AT LEAST ONE of its (possibly role-group-expanded)
    leaves - never an arbitrary caller string passed straight to
    kubectl's -c flag."""
    if container is None:
        return None
    for leaf in leaves:
        spec = commerce_mapping.COMPONENT_MAP[commerce_mapping.normalize_component(leaf)]
        if container in spec.containers:
            return container
        for pattern in spec.container_patterns:
            if re.search(pattern, container, re.IGNORECASE):
                return container
    raise ProdCommerceContainerError(
        f"Container {container!r} is not associated with the resolved component."
    )


def _resolve_pods_for_logs(
    component: str, default_namespace: str
) -> tuple[list[tuple[str, commerce_mapping.MatchedPod]], list[dict]]:
    """Resolve a (possibly role-group) component to leaf pods, capped at
    _MAX_PODS_PER_COMPONENT total - reuses the already-approved P12A pod
    discovery (prod_commerce_tools._fetch_pods, itself built on the fixed,
    prevention-based custom-columns spec) and the pure, unmodified
    commerce_mapping resolution logic."""
    leaves = commerce_mapping.expand_roles(component)
    out: list[tuple[str, commerce_mapping.MatchedPod]] = []
    fetch_errors: list[dict] = []
    ns_cache: dict[str, list[dict]] = {}
    for leaf in leaves:
        leaf_ns = commerce_mapping.resolve_namespace(leaf, default_namespace)
        if leaf_ns not in ns_cache:
            items, err = _fetch_pods(leaf_ns)
            if err:
                fetch_errors.append({"category": "pod_discovery_failed", "pod": None})
            ns_cache[leaf_ns] = items if items is not None else []
        out.extend((leaf, m) for m in commerce_mapping.match_pods(leaf, ns_cache[leaf_ns]))
    return out[:_MAX_PODS_PER_COMPONENT], fetch_errors


def _fetch_pod_log_text(pod: commerce_mapping.MatchedPod, container: Optional[str], tail: int, previous: bool) -> tuple[Optional[str], Optional[str]]:
    """Fetch one pod's log text via the fixed, single-shape command:
    `kubectl logs {pod} -n {namespace} --tail={tail} [-c {container}] [--previous]`.
    Returns (log_text, None) on success, or (None, safe_error_category) on
    any failure - the raw error/stderr text from readonly_exec is NEVER
    propagated (see module docstring: kubectl stderr is never surfaced)."""
    cmd = f"kubectl logs {pod.pod} -n {pod.namespace} --tail={tail}"
    if container:
        cmd += f" -c {container}"
    if previous:
        cmd += " --previous"

    raw = run_prod_commerce_readonly(cmd)
    first_line = raw.split("\n", 1)[0]
    if "] Error:" in first_line:
        return None, "previous_logs_unavailable" if previous else "log_fetch_failed"
    body = raw.split("\n", 1)[1] if "\n" in raw else ""
    if body.strip() in ("(empty result - no matching resources)",):
        return "", None
    return body, None


def _build_evidence_records(
    pod: commerce_mapping.MatchedPod, log_source: str, log_text: str
) -> list[dict]:
    """Classify one pod's raw log text (commerce_log_analyzer, pure, reused
    unmodified) into structured evidence records - one per (pod, category).
    The raw text and the analyzer's own redacted-but-still-free-text
    `evidence`/`evidence_detail` samples are used ONLY transiently here to
    derive exception_class/normalized_message candidates; neither is ever
    placed into the returned record. Every candidate string is additionally
    passed through prod_commerce_log_sanitizer.sanitize_candidate() before
    being retained - a stricter, whole-candidate-withholding gate on top of
    the analyzer's own line-level redaction."""
    analysis = commerce_log_analyzer.classify_log_text(log_text)
    records: list[dict] = []

    for finding in analysis.findings:
        samples = finding.evidence  # transient only - never returned
        first_sample = samples[0] if samples else ""

        exception_class: Optional[str] = None
        if finding.category in _EXCEPTION_LIKE_CATEGORIES:
            for sample in samples:
                match = _EXCEPTION_CLASS_PATTERN.search(sample)
                if match:
                    exception_class = sanitize_candidate(match.group(1))
                    break

        if finding.category == "stack_trace":
            # Never return frame text in any form (no file paths, no line
            # numbers, no raw or "normalized" frame line) - frame_count is
            # the ONLY representation of stack_trace-category content in
            # the output. A frame SIGNATURE (method reference only, file:
            # line stripped) is derived purely as a fingerprint hash
            # preimage below - it is never itself returned.
            normalized_message = None
            frame_signature = _FRAME_SIGNATURE_PATTERN.sub("", first_sample).strip() if first_sample else ""
        else:
            normalized_candidate = _normalize_message(first_sample) if first_sample else None
            normalized_message = sanitize_candidate(normalized_candidate)
            frame_signature = None

        aware_times = [
            s.timestamp.value for s in finding.evidence_detail
            if s.timestamp is not None and s.timestamp.value is not None and s.timestamp.value.tzinfo is not None
        ]
        naive_times = [
            s.timestamp.value for s in finding.evidence_detail
            if s.timestamp is not None and s.timestamp.value is not None and s.timestamp.value.tzinfo is None
        ]
        # Never mix naive and aware datetimes in one min()/max() (they are
        # not comparable) - prefer the aware set when both are present,
        # matching commerce_correlation's own established timezone-tier rule.
        chosen_times = aware_times if aware_times else naive_times
        timestamp_known = bool(chosen_times)
        first_seen = min(chosen_times).isoformat() if chosen_times else None
        last_seen = max(chosen_times).isoformat() if chosen_times else None

        # Fingerprint input is always either sanitizer-cleared text, a
        # file/line-stripped frame SIGNATURE (method reference only), or
        # pure structural data (category/exception_class) - never a raw or
        # unsanitized log line, even transiently as a hash preimage. Only
        # the resulting digest is ever returned - the seed text itself
        # never is.
        if finding.category == "stack_trace":
            fingerprint_seed = f"stack_trace|{frame_signature or ''}"
        else:
            fingerprint_seed = f"{finding.category}|{exception_class or ''}|{normalized_message or ''}"
        stack_fingerprint = hashlib.sha256(fingerprint_seed.encode("utf-8")).hexdigest()[:16]

        records.append({
            "pod": pod.pod,
            "container": pod.container,
            "log_source": log_source,
            "category": finding.category,
            "severity": commerce_log_analyzer.severity_of(finding.category),
            "exception_class": exception_class,
            "normalized_message": normalized_message,
            "stack_fingerprint": stack_fingerprint,
            "frame_count": finding.total_occurrences if finding.category == "stack_trace" else 0,
            "occurrence_count": finding.total_occurrences,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "timestamp_known": timestamp_known,
            # P12B v1: always null. An excerpt is only ever safe to return
            # after it independently passes the full sanitizer AND stays
            # under _MAX_EXCERPT_CHARS AND is derived from already-
            # normalized content - none of that is wired up in this phase.
            # Security is preferred over convenience for v1 (per design).
            "excerpt": None,
        })

    return records


def get_prod_commerce_logs(
    component: str,
    namespace: str = "commerce",
    container: Optional[str] = None,
    tail_lines: int = 50,
    previous: bool = False,
) -> str:
    """Safe, evidence-only PROD Commerce log investigation. Returns
    structured error/exception EVIDENCE (category, severity, exception
    class, a sanitizer-gated normalized message, a deterministic stack
    fingerprint, occurrence/timestamp aggregates) for up to 3 pods of the
    resolved component - NEVER a raw log line or log body. This tool is
    PROD-only - there is no environment parameter; namespace defaults to
    'commerce' and must be a specific namespace, never 'all'. `component`
    is resolved via commerce_mapping (role groups like 'search-app'
    expand to their leaves); no caller-supplied pod name is ever accepted.
    `container`, if given, must be one of the resolved component's own
    known container names/patterns. `tail_lines` is clamped to [1, 200],
    default 50. `previous=True` fetches the last terminated container's
    logs instead of the running one."""
    try:
        ns = _validate_commerce_namespace(namespace)
    except (ValueError, ProdCommerceNamespaceError) as exc:
        return f"Error: {exc}"

    try:
        leaves = commerce_mapping.expand_roles(component)
    except ValueError as exc:
        return f"Error: {exc}"

    try:
        validated_container = _validate_container_for_component(leaves, container)
    except ProdCommerceContainerError as exc:
        return f"Error: {exc}"

    tail = _validate_tail_lines(tail_lines)

    try:
        pods, fetch_errors = _resolve_pods_for_logs(component, ns)

        all_records: list[dict] = []
        lines_scanned = 0
        for _leaf, pod in pods:
            pod_container = validated_container or pod.container
            if validated_container is not None and pod.container != validated_container:
                # Caller narrowed to a specific container this pod/leaf
                # doesn't actually have - skip, never fetch an unrequested
                # container's logs.
                continue

            sources = [True] if previous else [False]
            for is_previous in sources:
                log_text, error_category = _fetch_pod_log_text(pod, pod_container, tail, is_previous)
                if error_category is not None:
                    fetch_errors.append({"category": error_category, "pod": pod.pod})
                    continue
                if log_text is None:
                    continue
                lines_scanned += len(log_text.splitlines())
                try:
                    all_records.extend(
                        _build_evidence_records(pod, "previous" if is_previous else "current", log_text)
                    )
                except Exception:
                    fetch_errors.append({"category": "log_parse_failed", "pod": pod.pod})

        all_records.sort(key=lambda r: (commerce_log_analyzer.severity_rank(r["category"]), -r["occurrence_count"]))
        output_truncated = len(all_records) > _MAX_EVIDENCE_RECORDS
        all_records = all_records[:_MAX_EVIDENCE_RECORDS]

        body = {
            "namespace": ns,
            "component": component,
            "evidence": all_records,
            "log_coverage": {
                "requested_tail_lines": tail,
                "lines_scanned": lines_scanned,
                "tail_cap_hit": lines_scanned >= tail and lines_scanned > 0,
                "output_truncated": output_truncated,
            },
            "fetch_errors": fetch_errors,
        }
        return f"[prod-commerce]\n{json.dumps(body, indent=2)}"
    except Exception:
        # Defense in depth: any unexpected internal error - never an
        # unhandled traceback reaching the MCP layer, never a fallback to
        # raw/partial log data. The exception object itself is never
        # interpolated into any message (it could carry raw log content).
        return f"[prod-commerce]\n{_WITHHELD_FAIL_CLOSED}"


def register(mcp) -> None:
    """Register exactly the 1 PROD Commerce log tool authorized for P12B
    onto `mcp`. No other tool may be added here."""
    mcp.add_tool(get_prod_commerce_logs)
