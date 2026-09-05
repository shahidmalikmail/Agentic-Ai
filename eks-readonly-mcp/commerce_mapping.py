"""Static, configurable mapping from HCL Commerce component names to
Kubernetes identity (container name(s), namespace override, role groups),
plus live Helm-release discovery.

No SSH/I-O happens here - this module is pure data plus resolution logic
against pod JSON that has already been fetched via the existing read-only
kubectl path (server._run / commerce_tools._fetch_pods).

Data model: environment -> namespace -> release -> canonical_component ->
pod -> container. `environment` and `namespace` are inputs supplied by the
caller (commerce_tools.py); this module resolves the rest:

- `canonical_component` (this file's COMPONENT_MAP keys, e.g. "ts-app") is
  the stable identity - it does not vary by environment or release.
- `container` name is the PRIMARY match key within a canonical component:
  discovery (2026-09-03, DEV+UAT) showed it is stable across environments
  and across redeploys, while pod names carry a random ReplicaSet suffix
  plus an env-and-release-specific prefix (e.g. obdevlive-, obdevshare-).
- `release` is discovered LIVE from each matched pod's own `release` label
  (e.g. "ob-dev-live", "ob-uat-share") - never hardcoded or assumed. A
  canonical component is not statically tied to one release name: which
  release currently owns it is read off the live pod, so a component
  reassigned to a new release, or a genuinely new release appearing later
  (e.g. a real ob-uat-auth, which is NOT modeled here because it was not
  found in live UAT as of 2026-09-04 - see distinct_releases()), needs no
  mapping change to be discovered and reported correctly.

Regex fallback container-name patterns exist for components whose exact
container name may vary (nginx) or that have never been observed deployed
(wcbd, utils) - an empty resolution result for those is a normal "not
deployed" outcome, not an error.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ComponentSpec:
    containers: tuple[str, ...] = ()
    """Exact container-name matches - primary, preferred match."""

    container_patterns: tuple[str, ...] = ()
    """Regex fallbacks (case-insensitive), tried only if no exact match."""

    namespace: Optional[str] = None
    """Namespace override. None means "use the caller's default namespace"."""

    roles: tuple[str, ...] = ()
    """If set, this key is a role GROUP (e.g. search-app) that expands to
    these leaf component keys instead of being matched directly."""

    known_optional: bool = False
    """True = commonly absent in this deployment; an empty match is
    expected, not a sign of a problem."""


# Discovered 2026-09-03 against DEV (ob-dev-eksCluster) and UAT
# (ob-uat-eksCluster) "commerce" namespace, plus the dedicated "nginx" and
# "redis" namespaces. Both environments use an identical container-name
# scheme; only the pod-name prefix and `release`/`component` labels differ
# per environment (obdevlive* vs obuatlive*).
COMPONENT_MAP: dict[str, ComponentSpec] = {
    "ts-app": ComponentSpec(containers=("ts-app",)),
    "crs-app": ComponentSpec(containers=("crs-app",)),
    "ts-web": ComponentSpec(containers=("ts-web",)),
    "store-web": ComponentSpec(containers=("store-web",)),
    "cache-app": ComponentSpec(containers=("cache-app",)),
    "tooling-web": ComponentSpec(containers=("tooling-web",), known_optional=True),
    "search-app": ComponentSpec(roles=("search-app-repeater", "search-app-slave")),
    "search-app-repeater": ComponentSpec(containers=("search-app-repeater",)),
    "search-app-slave": ComponentSpec(containers=("search-app-slave",)),
    # nginx's container name is literally "dev-nginx-nginx-ingress" in BOTH
    # dev and uat (observed) - matched by pattern rather than hardcoded so a
    # future rename doesn't silently break discovery.
    "nginx": ComponentSpec(container_patterns=(r"nginx",), namespace="nginx"),
    "redis": ComponentSpec(containers=("redis",), namespace="redis"),
    # Never observed deployed in either environment as of the 2026-09-03
    # discovery. Patterns are best-effort guesses, not confirmed names.
    "wcbd": ComponentSpec(container_patterns=(r"wcbd",), known_optional=True),
    "utils": ComponentSpec(container_patterns=(r"^utils?$",), known_optional=True),
}

ALL_COMPONENTS: tuple[str, ...] = tuple(COMPONENT_MAP.keys())


@dataclass(frozen=True)
class MatchedPod:
    pod: str
    namespace: str
    container: str
    phase: str
    release: Optional[str] = None
    """The pod's `release` label, verbatim (e.g. "ob-dev-live",
    "ob-uat-share") - read live, never hardcoded. None if the pod carries
    no `release` label (e.g. nginx/redis, which aren't part of the
    hcl-commerce chart)."""

    release_group: Optional[str] = None
    """The pod's `group` label, verbatim (e.g. "obdevlive", "obuat").
    Read live alongside `release`; None if absent."""

    restart_count: int = 0
    """Highest restartCount seen across the pod's containerStatuses. Pod-
    level (not per-container) - see match_pods()'s docstring for why: real
    Commerce pods observed so far are single-container, so this is exact
    for them; for a hypothetical multi-container pod it is a conservative
    upper bound, not attributed to a specific container."""

    waiting_reason: Optional[str] = None
    """The first non-empty containerStatuses[].state.waiting.reason found
    on the pod (e.g. "CrashLoopBackOff", "ImagePullBackOff"), or None if no
    container is currently in a Waiting state. This is the signal that
    catches a crash-looping container while status.phase still reads
    "Running" - phase alone must never be read as "healthy"."""


_CRASH_LOOP_WAITING_REASONS = frozenset({"CrashLoopBackOff"})
_IMAGE_PULL_WAITING_REASONS = frozenset({"ImagePullBackOff", "ErrImagePull"})


def pod_health_summary(matched: MatchedPod) -> dict:
    """Combine phase + waiting_reason + restart_count into one explicit
    health signal per pod. Never labels a pod "healthy" from phase alone -
    a container in CrashLoopBackOff commonly still reports pod
    phase="Running", so phase is necessary but not sufficient."""
    if matched.waiting_reason in _CRASH_LOOP_WAITING_REASONS:
        state = "crash_looping"
    elif matched.waiting_reason in _IMAGE_PULL_WAITING_REASONS:
        state = "image_pull_backoff"
    elif matched.waiting_reason:
        state = f"waiting:{matched.waiting_reason}"
    elif matched.phase == "Running" and matched.restart_count == 0:
        state = "running_stable"
    elif matched.phase == "Running" and matched.restart_count > 0:
        state = "running_with_restarts"
    else:
        state = (matched.phase or "unknown").lower()
    return {
        "phase": matched.phase,
        "restart_count": matched.restart_count,
        "waiting_reason": matched.waiting_reason,
        "state": state,
    }


def normalize_component(name: str) -> str:
    """Validate and lowercase a component name. Raises ValueError for
    anything not in COMPONENT_MAP (never silently guesses)."""
    key = (name or "").strip().lower()
    if key not in COMPONENT_MAP:
        raise ValueError(
            f"Unknown component {name!r}. Known components: {', '.join(ALL_COMPONENTS)}."
        )
    return key


def resolve_namespace(component: str, default_namespace: str) -> str:
    """Namespace a leaf component's pods live in: its override, or the
    caller's default (e.g. 'commerce')."""
    spec = COMPONENT_MAP[normalize_component(component)]
    return spec.namespace or default_namespace


def expand_roles(component: str) -> tuple[str, ...]:
    """Return the leaf component key(s) this component resolves to. A
    plain component expands to itself; a role group (search-app) expands
    to its member leaves."""
    key = normalize_component(component)
    spec = COMPONENT_MAP[key]
    return spec.roles or (key,)


def match_pods(component: str, pods_items: list[dict]) -> list[MatchedPod]:
    """Resolve a single LEAF component (not a role group) against already-
    fetched pod `items`. Never hardcodes a pod name - matches purely on
    container name (exact, then regex fallback).

    Reads `status.restart_count`/`status.waiting_reason` as pod-level
    scalars if present (see commerce_tools._parse_pod_discovery_line,
    which derives them from `-o custom-columns` rather than a real k8s
    `containerStatuses` array). Missing/absent is fine - defaults to
    restart_count=0, waiting_reason=None."""
    key = normalize_component(component)
    spec = COMPONENT_MAP[key]
    if spec.roles:
        raise ValueError(
            f"{key!r} is a role group ({', '.join(spec.roles)}); call "
            "expand_roles() and match each leaf, not the group itself."
        )

    compiled_patterns = [re.compile(p, re.IGNORECASE) for p in spec.container_patterns]
    matches: list[MatchedPod] = []
    for item in pods_items:
        meta = item.get("metadata", {})
        pod_name = meta.get("name", "")
        namespace = meta.get("namespace", "")
        status = item.get("status", {})
        phase = status.get("phase", "Unknown")
        restart_count = status.get("restart_count", 0) or 0
        waiting_reason = status.get("waiting_reason") or None
        labels = meta.get("labels") or {}
        release = labels.get("release") or None
        release_group = labels.get("group") or None
        container_names = [c.get("name", "") for c in item.get("spec", {}).get("containers", [])]

        matched_container = next((c for c in container_names if c in spec.containers), None)
        if matched_container is None and compiled_patterns:
            matched_container = next(
                (c for c in container_names if any(p.search(c) for p in compiled_patterns)),
                None,
            )
        if matched_container is not None:
            matches.append(
                MatchedPod(
                    pod=pod_name,
                    namespace=namespace,
                    container=matched_container,
                    phase=phase,
                    release=release,
                    release_group=release_group,
                    restart_count=restart_count,
                    waiting_reason=waiting_reason,
                )
            )
    return matches


def distinct_releases(pods_items: list[dict]) -> list[str]:
    """Enumerate the actual Helm release names present across already-
    fetched pods, read LIVE from each pod's `release` label - never a
    hardcoded/assumed list (e.g. this is how a genuine future ob-uat-auth
    would be discovered, without any mapping change, if it is ever
    actually deployed - it was not found in live UAT as of 2026-09-04).
    Pods with no `release` label (nginx, redis - not part of the
    hcl-commerce chart) are excluded, not reported as an empty release."""
    releases: set[str] = set()
    for item in pods_items:
        release = ((item.get("metadata", {}).get("labels")) or {}).get("release")
        if release:
            releases.add(release)
    return sorted(releases)
