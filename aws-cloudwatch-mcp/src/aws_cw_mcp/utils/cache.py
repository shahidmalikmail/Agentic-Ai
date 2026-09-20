"""Tiny thread-safe TTL cache for repeated metadata lookups."""
from __future__ import annotations

import threading
import time
from typing import Any, Callable, Hashable


class TTLCache:
    def __init__(self, ttl_seconds: float, max_entries: int = 256,
                 clock: Callable[[], float] = time.monotonic):
        self._ttl = ttl_seconds
        self._max = max_entries
        self._clock = clock
        self._data: dict = {}
        self._lock = threading.Lock()

    def get_or_set(self, key: Hashable, factory: Callable[[], Any]) -> tuple:
        """Return (value, was_cached). Exceptions from factory are never cached."""
        if self._ttl <= 0:
            return factory(), False
        now = self._clock()
        with self._lock:
            hit = self._data.get(key)
            if hit and hit[0] > now:
                return hit[1], True
        value = factory()
        with self._lock:
            if len(self._data) >= self._max:
                oldest = min(self._data, key=lambda k: self._data[k][0])
                del self._data[oldest]
            self._data[key] = (now + self._ttl, value)
        return value, False
