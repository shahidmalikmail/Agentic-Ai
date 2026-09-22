"""Rate limiting, concurrency, circuit breaker, in-flight de-duplication and result cache.

Every component takes an injectable clock/sleep so tests are deterministic and instant, and every
one is thread-safe (MCP tool handlers are not assumed to run serially). AWS's own limits are
StartQuery 10 TPS and GetQueryResults 10 TPS per account/region, not adjustable [V]; ours are far lower.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from typing import Any, Callable, Optional

from aws_cw_mcp.utils.errors import ConcurrencyLimit


class TokenBucket:
    def __init__(self, capacity: float, refill_per_second: float, clock: Callable[[], float] = time.monotonic):
        self._cap = float(capacity)
        self._rate = float(refill_per_second)
        self._clock = clock
        self._tokens = float(capacity)
        self._last = clock()
        self._lock = threading.Lock()

    def try_acquire(self, n: float = 1.0) -> bool:
        with self._lock:
            now = self._clock()
            self._tokens = min(self._cap, self._tokens + (now - self._last) * self._rate)
            self._last = now
            if self._tokens >= n:
                self._tokens -= n
                return True
            return False


class SlidingWindowCap:
    def __init__(self, max_events: int, window_seconds: float, clock: Callable[[], float] = time.monotonic):
        self._max, self._window, self._clock = max_events, window_seconds, clock
        self._events: deque = deque()
        self._lock = threading.Lock()

    def try_acquire(self) -> bool:
        with self._lock:
            now = self._clock()
            while self._events and self._events[0] <= now - self._window:
                self._events.popleft()
            if len(self._events) >= self._max:
                return False
            self._events.append(now)
            return True

    def has_room(self) -> bool:
        with self._lock:
            now = self._clock()
            while self._events and self._events[0] <= now - self._window:
                self._events.popleft()
            return len(self._events) < self._max

    def used(self) -> int:
        with self._lock:
            now = self._clock()
            return sum(1 for t in self._events if t > now - self._window)


class StartLimiter:
    """Burst bucket + per-minute cap for StartQuery (estimate and run each count)."""

    def __init__(self, per_minute: int, clock: Callable[[], float] = time.monotonic):
        self._bucket = TokenBucket(capacity=3, refill_per_second=0.5, clock=clock)
        self._cap = SlidingWindowCap(per_minute, 60.0, clock)
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Check BOTH limits before consuming either, so a refused request never uses up budget."""
        with self._lock:
            if not self._cap.has_room():
                raise ConcurrencyLimit("Insights start-rate limit reached (per-minute cap); wait a moment and retry.")
            if not self._bucket.try_acquire():
                raise ConcurrencyLimit("Insights start-rate limit reached (burst); wait a couple of seconds and retry.")
            self._cap.try_acquire()

    def used_last_minute(self) -> int:
        return self._cap.used()


class ConcurrencySlots:
    def __init__(self, max_concurrent: int, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self._max = max_concurrent
        self._in_use = 0
        self._clock, self._sleep = clock, sleep
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 3.0, poll: float = 0.25) -> None:
        deadline = self._clock() + timeout
        while True:
            with self._lock:
                if self._in_use < self._max:
                    self._in_use += 1
                    return
            if self._clock() >= deadline:
                raise ConcurrencyLimit(f"Already running {self._max} Insights queries; wait for one to finish "
                                       "or cancel it.")
            self._sleep(poll)

    def release(self) -> None:
        with self._lock:
            if self._in_use > 0:
                self._in_use -= 1

    @property
    def in_use(self) -> int:
        with self._lock:
            return self._in_use

    @property
    def limit(self) -> int:
        return self._max


class CircuitBreaker:
    """Opens after `threshold` consecutive throttling/limit errors and refuses new starts for `cooldown` s."""

    def __init__(self, threshold: int = 3, cooldown: float = 60.0, clock: Callable[[], float] = time.monotonic):
        self._threshold, self._cooldown, self._clock = threshold, cooldown, clock
        self._failures = 0
        self._open_until = 0.0
        self._lock = threading.Lock()

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self._threshold:
                self._open_until = self._clock() + self._cooldown

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0

    def check(self) -> None:
        with self._lock:
            remaining = self._open_until - self._clock()
        if remaining > 0:
            raise ConcurrencyLimit(f"AWS throttled Insights requests repeatedly; new queries are paused for "
                                   f"{int(remaining) + 1}s to protect the shared account quota.")

    @property
    def is_open(self) -> bool:
        with self._lock:
            return self._open_until > self._clock()


class PollLimiter:
    """Keeps GetQueryResults polling below a minimum interval across all jobs."""

    def __init__(self, min_interval: float = 0.5, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self._min, self._clock, self._sleep = min_interval, clock, sleep
        self._last = -1e9
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = self._clock()
            gap = self._last + self._min - now
            self._last = max(now, self._last + self._min) if gap > 0 else now
        if gap > 0:
            self._sleep(gap)


class _Flight:
    def __init__(self):
        self.event = threading.Event()
        self.result: Any = None
        self.error: Optional[BaseException] = None


class InFlight:
    """Identical concurrent requests share one job: the first is the leader, the rest wait."""

    def __init__(self):
        self._flights: dict = {}
        self._lock = threading.Lock()

    def begin(self, key: str) -> tuple:
        with self._lock:
            f = self._flights.get(key)
            if f is not None:
                return f, False
            f = _Flight()
            self._flights[key] = f
            return f, True

    def finish(self, key: str, result: Any = None, error: Optional[BaseException] = None) -> None:
        with self._lock:
            f = self._flights.pop(key, None)
        if f is not None:
            f.result, f.error = result, error
            f.event.set()

    @staticmethod
    def wait(flight: _Flight, timeout: float) -> Any:
        if not flight.event.wait(timeout):
            raise ConcurrencyLimit("An identical query is still running; retry shortly or use its handle.")
        if flight.error is not None:
            raise flight.error
        return flight.result


class ResultCache:
    def __init__(self, ttl_seconds: float, max_entries: int, clock: Callable[[], float] = time.monotonic):
        self._ttl, self._max, self._clock = ttl_seconds, max_entries, clock
        self._data: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[tuple]:
        """(value, age_seconds) or None."""
        if self._ttl <= 0:
            return None
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            stored_at, value = item
            age = self._clock() - stored_at
            if age >= self._ttl:
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return value, age

    def put(self, key: str, value: Any) -> None:
        if self._ttl <= 0:
            return
        with self._lock:
            self._data[key] = (self._clock(), value)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)
