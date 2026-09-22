"""Thread-safe registries: approved requests, owned queries, and continuation handles.

* ApprovedQueryRegistry: only the validator adds fingerprints; the boto gate consumes them (single use).
* OwnedQueryRegistry: queryIds returned by THIS process's StartQuery. GetQueryResults/StopQuery are refused
  for any other id.
* JobTable: opaque handles (never raw AWS queryIds) for continuation/cancellation, plus recently
  finished outcomes so a late get_results still answers.
"""
from __future__ import annotations

import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from aws_cw_mcp.utils.errors import InputError


class ApprovedQueryRegistry:
    def __init__(self, ttl_seconds: float = 60.0, clock: Callable[[], float] = time.monotonic):
        self._ttl = ttl_seconds
        self._clock = clock
        self._items: dict = {}
        self._lock = threading.Lock()

    def approve(self, fingerprint: str) -> None:
        with self._lock:
            self._purge()
            self._items[fingerprint] = self._clock() + self._ttl

    def is_approved(self, fingerprint: str) -> bool:
        with self._lock:
            self._purge()
            return fingerprint in self._items

    def consume(self, fingerprint: str) -> bool:
        """Single use: True exactly once per approval."""
        with self._lock:
            self._purge()
            return self._items.pop(fingerprint, None) is not None

    def __len__(self) -> int:
        with self._lock:
            self._purge()
            return len(self._items)

    def _purge(self) -> None:
        now = self._clock()
        for fp in [k for k, exp in self._items.items() if exp <= now]:
            del self._items[fp]


class OwnedQueryRegistry:
    def __init__(self):
        self._ids: set = set()
        self._lock = threading.Lock()

    def add(self, query_id: str) -> None:
        with self._lock:
            self._ids.add(query_id)

    def contains(self, query_id: str) -> bool:
        with self._lock:
            return query_id in self._ids

    def discard(self, query_id: str) -> None:
        with self._lock:
            self._ids.discard(query_id)

    def snapshot(self) -> list:
        with self._lock:
            return sorted(self._ids)


@dataclass
class Job:
    handle: str
    query_id: str
    kind: str
    cache_key: str
    validated: Any                     # ValidatedPlan
    reservation: Any                   # ByteBudget reservation
    estimated_bytes: int
    started_at: float
    deadline: float
    retention: dict = field(default_factory=dict)
    last_bytes: int = 0
    settled: bool = False
    state: str = "running"
    lock: threading.Lock = field(default_factory=threading.Lock)


class JobTable:
    """Running jobs by handle, and a bounded memory of recent outcomes."""

    def __init__(self, keep_finished: int = 32, clock: Callable[[], float] = time.monotonic,
                 finished_ttl: float = 900.0):
        self._jobs: dict = {}
        self._finished: OrderedDict = OrderedDict()
        self._keep = keep_finished
        self._ttl = finished_ttl
        self._clock = clock
        self._lock = threading.Lock()

    @staticmethod
    def new_handle() -> str:
        return "qh_" + secrets.token_urlsafe(9)

    def add(self, job: Job) -> None:
        with self._lock:
            self._jobs[job.handle] = job

    def running(self, handle: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(handle)

    def finished(self, handle: str):
        with self._lock:
            item = self._finished.get(handle)
            if item and item[0] > self._clock():
                return item[1]
            self._finished.pop(handle, None)
            return None

    def require(self, handle: str) -> tuple:
        """(job|None, finished_outcome|None) or InputError for handles this process never issued."""
        if not isinstance(handle, str) or not handle.startswith("qh_") or len(handle) > 64:
            raise InputError("Unknown or expired query_handle.")
        job = self.running(handle)
        if job is not None:
            return job, None
        done = self.finished(handle)
        if done is not None:
            return None, done
        raise InputError("Unknown or expired query_handle (only queries started by this server can be resumed).")

    def finish(self, job: Job, outcome: Any) -> None:
        with self._lock:
            self._jobs.pop(job.handle, None)
            if job.handle in self._finished:          # first recorded outcome wins (no overwrite races)
                return
            self._finished[job.handle] = (self._clock() + self._ttl, outcome)
            while len(self._finished) > self._keep:
                self._finished.popitem(last=False)

    def all_running(self) -> list:
        with self._lock:
            return list(self._jobs.values())

    def overdue(self, now: float) -> list:
        with self._lock:
            return [j for j in self._jobs.values() if j.deadline <= now]
