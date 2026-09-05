"""Pure temporal/evidence correlation over an already-assembled timeline
(Phase 4B). Consumes exactly the row shape commerce_tools.assemble_timeline()
produces and groups rows that occurred close together in time - it never
fetches anything, never talks to SSH/kubectl/MCP, and never claims
causality. CORRELATION != CAUSATION: a CorrelationGroup says "these
observations happened close together in time," nothing more. Any
likely-cause/root-event/dependency reasoning belongs to a later,
explicitly separate diagnosis phase - this module has no fields and no
logic for that.

Timestamp safety (mirrors commerce_log_analyzer.parse_timestamp()'s own
contract): a timezone-aware absolute timestamp is NEVER compared against
a timezone-naive one as if they were on the same timeline; a time-only
(no-date) value is NEVER compared against an absolute one; no date, year,
or timezone is ever invented. Concretely, every row is placed into one of
four timestamp-comparability TIERS before any comparison happens, and
correlation only ever compares rows within the same tier:

    Tier 0: absolute timestamp, timezone_known=True  -> "absolute_tz_known"
    Tier 1: absolute timestamp, timezone_known=False -> "absolute_tz_unknown"
    Tier 2: time_only (bracketed, no date)            -> "time_only"
    Tier 3: no timestamp at all                        -> never clustered

Tier 3 rows are never grouped with anything - they are returned separately
(see correlate_timeline()'s `uncorrelated` return value), preserved in
full, never silently dropped and never assigned a fabricated timestamp.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from typing import Optional

DEFAULT_WINDOW_SECONDS = 60
MAX_WINDOW_SECONDS = 3600

# Separately capped from the number of groups (which the MCP tool layer
# bounds, mirroring commerce_tools._classify_warning_events' own
# cap+"...omitted..." marker convention) - this cap lives here because it
# is intrinsic to what a CorrelationGroup means: `evidence_count` always
# reports the TRUE number of grouped observations even when `observations`
# is capped shorter, exactly like CategoryFinding.count vs. its capped
# `.evidence` list.
_MAX_OBSERVATIONS_PER_GROUP = 20

_TIER_LABELS: dict[int, str] = {
    0: "absolute_tz_known",
    1: "absolute_tz_unknown",
    2: "time_only",
}


@dataclass(frozen=True)
class CorrelationGroup:
    """One cluster of timeline observations that fell within
    `window_seconds` of each other, all within the SAME timestamp-
    comparability tier (see module docstring) - never mixed across tiers.

    Deliberately minimal: no likely_cause, no root_event, no
    causal_relationship/confidence/dependency/upstream/downstream/cause/
    recommendation field of any kind. This organizes evidence; it does
    not diagnose it.

    `group_id` is DETERMINISTIC (a content hash, never uuid4/random/
    wall-clock) - identical input always produces identical group_ids.

    `start_timestamp`/`end_timestamp` are the first/last observation's
    OWN `timestamp` field verbatim (or `partial_time` for a
    temporal_comparability="time_only" group) - never a re-derived or
    UTC-converted value not literally present in the source rows.

    `observations` holds the actual timeline rows (capped at
    _MAX_OBSERVATIONS_PER_GROUP); `evidence_count` is always the TRUE
    total even when `observations` is capped shorter."""

    group_id: str
    temporal_comparability: str  # "absolute_tz_known" | "absolute_tz_unknown" | "time_only"
    start_timestamp: Optional[str]
    end_timestamp: Optional[str]
    duration_seconds: float
    observations: list = field(default_factory=list)
    evidence_count: int = 0
    components: list = field(default_factory=list)
    pods: list = field(default_factory=list)
    releases: list = field(default_factory=list)
    categories: list = field(default_factory=list)
    severities: list = field(default_factory=list)
    sources: list = field(default_factory=list)


def _is_truncation_marker(row: dict) -> bool:
    """assemble_timeline()'s own bounded-output marker row - exactly one
    key, "note". Never a real observation; skipped rather than treated as
    unclusterable evidence (which would otherwise land it in
    `uncorrelated` and look like a fabricated evidence row)."""
    return set(row.keys()) == {"note"}


def _tier_and_key(row: dict):
    """Return (tier, sort_key) for one timeline row - (3, None) when the
    row cannot be safely placed on any comparable timeline. Never raises:
    a malformed/unparseable timestamp field degrades to tier 3, exactly
    like commerce_log_analyzer.parse_timestamp() degrades a malformed
    timestamp to None rather than raising."""
    if row.get("timestamp_precision") == "absolute" and row.get("timestamp"):
        try:
            value = datetime.fromisoformat(row["timestamp"])
        except (TypeError, ValueError):
            return 3, None
        if row.get("timezone_known") and value.tzinfo is not None:
            return 0, value.astimezone(timezone.utc)
        # Tier 1: never trust/guess a timezone - always compared as naive,
        # even if a stray tzinfo is present on a hand-built/malformed row.
        return 1, value.replace(tzinfo=None)

    if row.get("timestamp_precision") == "time_only" and row.get("partial_time"):
        try:
            parsed_time = time.fromisoformat(row["partial_time"])
        except (TypeError, ValueError):
            return 3, None
        seconds_of_day = (
            parsed_time.hour * 3600
            + parsed_time.minute * 60
            + parsed_time.second
            + parsed_time.microsecond / 1_000_000
        )
        return 2, seconds_of_day

    return 3, None


def _seconds_between(a, b) -> float:
    """`a`/`b` are either both datetimes (tier 0/1 - always both aware or
    both naive within one tier, never mixed) or both tier-2 seconds-of-day
    floats. Never wraps around midnight for tier 2 - see module docstring
    / correlate_timeline()'s docstring for that documented limitation."""
    if isinstance(a, datetime):
        return (b - a).total_seconds()
    return float(b - a)


def _cluster_tier(
    rows_with_keys: list[tuple[object, dict]], window_seconds: float
) -> list[list[tuple[object, dict]]]:
    """Approved rolling/chained sliding-window clustering for ONE tier's
    rows (never mixed with another tier). Sorts first (stable, so this
    function is correct regardless of whether the caller's timeline was
    already sorted), then walks once: each row is compared to the CURRENT
    GROUP'S LAST row, not its first - so a burst of many observations each
    <= window_seconds apart still merges into one group even if the first
    and last are further apart than the window."""
    ordered = sorted(rows_with_keys, key=lambda pair: pair[0])
    groups: list[list[tuple[object, dict]]] = []
    current: list[tuple[object, dict]] = []
    for key, row in ordered:
        if current and _seconds_between(current[-1][0], key) <= window_seconds:
            current.append((key, row))
        else:
            if current:
                groups.append(current)
            current = [(key, row)]
    if current:
        groups.append(current)
    return groups


def _sorted_unique(rows: list[dict], field_name: str) -> list:
    return sorted({row[field_name] for row in rows if row.get(field_name)})


def _stable_hash(rows: list[dict]) -> str:
    """Content hash of a group's rows (never random, never wall-clock) so
    group_id is reproducible for identical input - see CorrelationGroup's
    docstring and rule 16."""
    parts = []
    for row in rows:
        parts.append(
            "|".join(
                [
                    str(row.get("component")),
                    str(row.get("pod")),
                    str(row.get("category")),
                    str(row.get("timestamp") or row.get("partial_time")),
                    str(row.get("summary")),
                ]
            )
        )
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:12]


def _build_group(tier_label: str, index_in_tier: int, cluster: list[tuple[object, dict]]) -> CorrelationGroup:
    rows_full = [row for _key, row in cluster]
    start_key, start_row = cluster[0]
    end_key, end_row = cluster[-1]
    if tier_label == "time_only":
        start_ts = start_row.get("partial_time")
        end_ts = end_row.get("partial_time")
    else:
        start_ts = start_row.get("timestamp")
        end_ts = end_row.get("timestamp")
    return CorrelationGroup(
        group_id=f"{tier_label}-{index_in_tier}-{_stable_hash(rows_full)}",
        temporal_comparability=tier_label,
        start_timestamp=start_ts,
        end_timestamp=end_ts,
        duration_seconds=_seconds_between(start_key, end_key),
        observations=rows_full[:_MAX_OBSERVATIONS_PER_GROUP],
        evidence_count=len(rows_full),
        components=_sorted_unique(rows_full, "component"),
        pods=_sorted_unique(rows_full, "pod"),
        releases=_sorted_unique(rows_full, "release"),
        categories=_sorted_unique(rows_full, "category"),
        severities=_sorted_unique(rows_full, "severity"),
        sources=_sorted_unique(rows_full, "source"),
    )


def correlate_timeline(
    timeline: list[dict],
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> tuple[list[CorrelationGroup], list[dict], int]:
    """Group timeline rows (the output shape of
    commerce_tools.assemble_timeline()) that occurred within
    `window_seconds` of each other - organizes evidence by time only,
    never claims or implies causality. Pure: no I/O, never raises on
    malformed input (a row that cannot be safely placed on any comparable
    timeline is preserved in the returned `uncorrelated` list instead of
    being dropped or crashing the call).

    Returns (groups, uncorrelated, resolved_window_seconds):

    - `groups`: one CorrelationGroup per cluster, across all three
      timestamped tiers (absolute_tz_known / absolute_tz_unknown /
      time_only) - tiers are NEVER mixed within one group (see module
      docstring). A single isolated observation with no temporal
      neighbor within the window still becomes its own one-observation
      group (duration_seconds=0) - this is different from `uncorrelated`,
      which is reserved for rows with NO usable timestamp at all.
    - `uncorrelated`: tier-3 rows (no timestamp, or an unparseable one),
      preserved verbatim, in their original order - never clustered,
      never dropped.
    - `resolved_window_seconds`: the ACTUAL window used after clamping
      `window_seconds` to [1, MAX_WINDOW_SECONDS] - always report this
      value rather than the caller's raw input, so a caller/AI never
      has to guess what window actually produced the grouping.

    Known, documented limitation for temporal_comparability="time_only"
    groups: proximity is computed on time-of-day only (seconds since
    midnight, no wraparound handling) since the date is genuinely
    unknown - two observations at 23:59:59 and 00:00:01 are treated as
    ~86398 seconds apart, not ~2, because no date exists to prove they
    were on adjacent days. This is the honest answer given what the
    source data actually contains, not a bug to silently paper over."""
    resolved_window = max(1, min(int(window_seconds), MAX_WINDOW_SECONDS))

    tiered: dict[int, list[tuple[object, dict]]] = {0: [], 1: [], 2: []}
    uncorrelated: list[dict] = []

    for row in timeline or []:
        if not isinstance(row, dict) or _is_truncation_marker(row):
            continue
        tier, key = _tier_and_key(row)
        if tier == 3:
            uncorrelated.append(row)
        else:
            tiered[tier].append((key, row))

    groups: list[CorrelationGroup] = []
    for tier in (0, 1, 2):
        for index_in_tier, cluster in enumerate(_cluster_tier(tiered[tier], resolved_window)):
            groups.append(_build_group(_TIER_LABELS[tier], index_in_tier, cluster))

    return groups, uncorrelated, resolved_window
