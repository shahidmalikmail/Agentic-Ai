"""Static HCL Commerce troubleshooting knowledge layer.

This is reference material, keyed by the same category names
commerce_log_analyzer produces - it is NOT observed evidence and NOT a
diagnosis. diagnose_commerce_issue may cite it alongside observed
evidence, always clearly labeled as general guidance, never presented as
a confirmed cause or a verified HCL Commerce 9.1 procedure.

Deliberately minimal and generic for now (standard Kubernetes/Java-app
troubleshooting knowledge, not HCL Commerce internals) - this file does
not invent HCL Commerce 9.1-specific behavior, known-error codes, or
fixes. Real HCL Commerce documentation, known errors, internal runbooks,
and incident history belong here later, added deliberately by someone
with that knowledge, not generated on request.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KnowledgeEntry:
    category: str
    general_guidance: str
    typical_investigation: str
    general_next_step: str


KNOWLEDGE_BASE: dict[str, KnowledgeEntry] = {
    "oom_killed": KnowledgeEntry(
        category="oom_killed",
        general_guidance=(
            "The container was killed by the kernel/kubelet for exceeding its memory "
            "limit. This is a generic Kubernetes signal, not specific to HCL Commerce."
        ),
        typical_investigation=(
            "Compare the container's memory limit to its actual usage over time; "
            "check whether usage grew gradually (possible leak) or spiked (load event)."
        ),
        general_next_step=(
            "Generic option: review/raise the memory limit or reduce load, after "
            "confirming this isn't masking a leak. Not an HCL Commerce-specific fix."
        ),
    ),
    "crash_loop": KnowledgeEntry(
        category="crash_loop",
        general_guidance=(
            "The container is repeatedly failing to stay up (CrashLoopBackOff). The "
            "actual failure reason is in the container's logs/previous-container logs, "
            "not in this signal itself."
        ),
        typical_investigation=(
            "Check the previous container's logs (get_pod_logs previous=True) and "
            "recent Warning events for the pod for the underlying error."
        ),
        general_next_step=(
            "No fix can be inferred from the crash signal alone - identify the "
            "underlying error first."
        ),
    ),
    "readiness_liveness_failure": KnowledgeEntry(
        category="readiness_liveness_failure",
        general_guidance=(
            "A readiness or liveness probe is failing, generic Kubernetes health-check "
            "signal - the app may be slow to start, overloaded, or genuinely unhealthy."
        ),
        typical_investigation=(
            "Check probe path/thresholds (kubectl describe pod) against actual app "
            "startup/response time under current load."
        ),
        general_next_step=(
            "Generic option: verify probe configuration is realistic for this "
            "component's startup/response profile before assuming an app defect."
        ),
    ),
    "scheduling_failure": KnowledgeEntry(
        category="scheduling_failure",
        general_guidance=(
            "The scheduler could not place the pod (e.g. insufficient CPU/memory, no "
            "matching nodes). This is a cluster-capacity signal, not an application error."
        ),
        typical_investigation=(
            "Check node capacity/availability (get_nodes) and the pod's resource "
            "requests; confirm whether nodes are intentionally scaled down."
        ),
        general_next_step=(
            "Generic option: adjust cluster/node capacity or pod resource requests - "
            "outside this read-only tool's scope to change."
        ),
    ),
    "http_5xx": KnowledgeEntry(
        category="http_5xx",
        general_guidance=(
            "Server-side HTTP error responses were observed. Generic signal - the "
            "failing tier could be this component or one it depends on."
        ),
        typical_investigation=(
            "Correlate timing with downstream/upstream components (correlate_commerce_errors) "
            "and check for accompanying exceptions/timeouts in the same window."
        ),
        general_next_step=(
            "No specific fix without knowing which downstream call failed - "
            "identify that first."
        ),
    ),
    "http_4xx": KnowledgeEntry(
        category="http_4xx",
        general_guidance=(
            "Client-side HTTP error responses were observed (e.g. bad request, "
            "unauthorized, not found). May indicate a caller/config/auth issue rather "
            "than a server defect."
        ),
        typical_investigation=(
            "Check whether 4xx responses cluster around a specific path/client or "
            "coincide with an auth/config change."
        ),
        general_next_step=(
            "Generic option: verify request routing/config or credentials for the "
            "affected path before assuming an application bug."
        ),
    ),
    "timeout": KnowledgeEntry(
        category="timeout",
        general_guidance=(
            "A timeout was logged - generic signal of a slow or unresponsive "
            "dependency (network, database, downstream service)."
        ),
        typical_investigation=(
            "Identify which call is timing out (DB, Redis, search, another service) "
            "from the surrounding log lines, and check that dependency's health."
        ),
        general_next_step=(
            "No specific fix without knowing which dependency is slow - identify it first."
        ),
    ),
    "connection_failure": KnowledgeEntry(
        category="connection_failure",
        general_guidance=(
            "A connection was refused/reset/closed. Generic networking signal - the "
            "target service may be down, unreachable, or rejecting connections."
        ),
        typical_investigation=(
            "Check the target service's pod status/events and any NetworkPolicy "
            "affecting the two components."
        ),
        general_next_step=(
            "Generic option: confirm the target service is Running and reachable "
            "before assuming an application defect."
        ),
    ),
    "authentication_failure": KnowledgeEntry(
        category="authentication_failure",
        general_guidance=(
            "An authentication/authorization failure was logged. Generic signal - "
            "credential, token expiry, or permission misconfiguration."
        ),
        typical_investigation=(
            "Check whether credentials/tokens/secrets used by this component recently "
            "changed or expired (metadata only - this MCP never returns secret values)."
        ),
        general_next_step=(
            "Generic option: verify credential/config validity through your normal "
            "secret-rotation process; this tool cannot inspect or change secret values."
        ),
    ),
    "database_error": KnowledgeEntry(
        category="database_error",
        general_guidance=(
            "A database-layer error/exception was logged (SQL error, deadlock, "
            "connection pool exhaustion). Generic signal - not HCL Commerce-specific."
        ),
        typical_investigation=(
            "Check DB connectivity/health from this component's namespace and whether "
            "the error is isolated to one query pattern or a broad connectivity issue."
        ),
        general_next_step=(
            "No specific fix without the exact DB error - identify it from the "
            "evidence lines first."
        ),
    ),
    "redis_error": KnowledgeEntry(
        category="redis_error",
        general_guidance=(
            "A Redis-related error/timeout was logged. Generic signal - Redis "
            "unavailability, auth mismatch, or a type/command mismatch."
        ),
        typical_investigation=(
            "Check the redis component's pod status (get_commerce_health) and whether "
            "other components see the same signal at the same time (correlate_commerce_errors)."
        ),
        general_next_step=(
            "Generic option: confirm the Redis pod is Running and reachable before "
            "assuming an application-side defect."
        ),
    ),
    "search_error": KnowledgeEntry(
        category="search_error",
        general_guidance=(
            "A search-layer error/timeout was logged (Solr/Elasticsearch-style "
            "signal). Generic - not a confirmed HCL Commerce search-app root cause."
        ),
        typical_investigation=(
            "Check search-app-repeater and search-app-slave together "
            "(correlate_commerce_errors) - a repeater/slave sync issue can present as "
            "an error on only one of the two."
        ),
        general_next_step=(
            "No specific fix without identifying whether the repeater, the slave, or "
            "both are affected."
        ),
    ),
    "upstream_downstream_failure": KnowledgeEntry(
        category="upstream_downstream_failure",
        general_guidance=(
            "A dependency call (upstream/downstream/backend) was reported as failed "
            "or unavailable. Generic signal about a cross-component dependency."
        ),
        typical_investigation=(
            "Use correlate_commerce_errors across the components in the dependency "
            "chain to see whether the failure originates elsewhere."
        ),
        general_next_step=(
            "No specific fix without identifying the failing dependency - trace it first."
        ),
    ),
    "jvm_application_error": KnowledgeEntry(
        category="jvm_application_error",
        general_guidance=(
            "A JVM-level error was logged (e.g. OutOfMemoryError, StackOverflowError, "
            "NoClassDefFoundError). Generic Java runtime signal."
        ),
        typical_investigation=(
            "Check for a preceding pattern (memory growth, recursive call, recent "
            "deployment/classpath change) around the same timestamp."
        ),
        general_next_step=(
            "No specific fix without more context - this is a runtime-level symptom, "
            "not a diagnosis."
        ),
    ),
    "exception": KnowledgeEntry(
        category="exception",
        general_guidance=(
            "An unclassified exception was logged - didn't match a more specific "
            "category above."
        ),
        typical_investigation=(
            "Read the full stack trace (stack_trace evidence, if present) for the "
            "originating exception type and message."
        ),
        general_next_step="No specific fix without the exception's full detail.",
    ),
    "stack_trace": KnowledgeEntry(
        category="stack_trace",
        general_guidance="A Java stack trace frame was logged.",
        typical_investigation=(
            "Read the full trace together with the exception line above it."
        ),
        general_next_step="No fix implied by a stack trace line alone.",
    ),
    "generic_error": KnowledgeEntry(
        category="generic_error",
        general_guidance=(
            "A line was logged at ERROR level but didn't match any more specific "
            "category above."
        ),
        typical_investigation="Read the full line and surrounding context directly.",
        general_next_step="No specific fix without more detail.",
    ),
}


def lookup(category: str) -> KnowledgeEntry | None:
    return KNOWLEDGE_BASE.get(category)
