"""Structured query plans and request fingerprints (pure, no AWS)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Sequence

KIND_COUNT_OVER_TIME = "count_over_time"
KIND_COUNT_BY = "count_by"
KIND_SAMPLE_EVENTS = "sample_events"
KINDS = (KIND_COUNT_OVER_TIME, KIND_COUNT_BY, KIND_SAMPLE_EVENTS)

DIM_LOG_GROUP = "log_group"
DIM_LOG_STREAM = "log_stream"
DIM_STATUS_CODE = "status_code"
DIMENSIONS = (DIM_LOG_GROUP, DIM_LOG_STREAM, DIM_STATUS_CODE)

QUERY_LANGUAGE = "CWLI"


@dataclass(frozen=True)
class MatchSpec:
    """What to match, in a closed vocabulary. Never a regex or field name from the caller."""
    presets: tuple = ()
    contains: tuple = ()
    exclude: tuple = ()
    status_codes: tuple = ()

    def is_empty(self) -> bool:
        return not (self.presets or self.contains or self.status_codes)

    def as_dict(self) -> dict:
        return {"presets": list(self.presets), "contains": list(self.contains),
                "exclude": list(self.exclude), "status_codes": list(self.status_codes)}


@dataclass(frozen=True)
class QueryPlan:
    kind: str
    log_groups: tuple
    start: datetime
    end: datetime
    match: MatchSpec
    dimension: Optional[str] = None
    bin_seconds: Optional[int] = None
    limit: int = 10

    @property
    def start_s(self) -> int:
        return int(self.start.timestamp())

    @property
    def end_s(self) -> int:
        return int(self.end.timestamp())

    @property
    def seconds(self) -> int:
        return self.end_s - self.start_s


def request_fingerprint(query: str, group_names: Sequence[str], start_s: int, end_s: int,
                        limit: Optional[int]) -> str:
    """Stable hash of exactly what will be sent to StartQuery. Used by the validator (to approve)
    and by the boto gate (to re-derive from the outgoing request and compare).

    `limit` is None for an ESTIMATE request: it is sent WITHOUT the API `limit` parameter (see the V2
    finding: AWS applies the API limit as a trailing `limit` stage, which would land after `| estimate`
    and break the rule that `estimate` must be the final command)."""
    payload = json.dumps([query, sorted(group_names), int(start_s), int(end_s),
                          None if limit is None else int(limit)],
                         separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def plan_cache_key(plan: QueryPlan) -> str:
    """Result-cache / de-duplication key: independent of the estimate suffix."""
    payload = json.dumps([plan.kind, sorted(plan.log_groups), plan.start_s, plan.end_s,
                          plan.match.as_dict(), plan.dimension, plan.bin_seconds, plan.limit],
                         separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
