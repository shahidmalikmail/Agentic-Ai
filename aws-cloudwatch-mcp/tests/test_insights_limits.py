"""Rate limiting, concurrency, breaker, in-flight sharing, cache; all with a fake clock and real threads where relevant."""
import threading

import pytest

from aws_cw_mcp.insights.limits import (CircuitBreaker, ConcurrencySlots, InFlight, PollLimiter, ResultCache,
                                        SlidingWindowCap, StartLimiter, TokenBucket)
from aws_cw_mcp.utils.errors import ConcurrencyLimit
from conftest import FakeClock


def test_token_bucket_burst_then_refill():
    c = FakeClock()
    b = TokenBucket(3, 0.5, c.now)
    assert [b.try_acquire() for _ in range(4)] == [True, True, True, False]
    c.advance(2)                                    # 2s * 0.5/s = 1 token
    assert b.try_acquire() and not b.try_acquire()
    c.advance(1000)
    assert sum(b.try_acquire() for _ in range(10)) == 3      # never above capacity


def test_sliding_window_cap():
    c = FakeClock()
    w = SlidingWindowCap(2, 60, c.now)
    assert w.try_acquire() and w.try_acquire() and not w.try_acquire() and w.used() == 2
    c.advance(61)
    assert w.try_acquire() and w.used() == 1


def test_start_limiter_enforces_burst_and_per_minute_cap_with_clear_messages():
    c = FakeClock()
    lim = StartLimiter(per_minute=6, clock=c.now)
    for _ in range(3):
        lim.acquire()
    with pytest.raises(ConcurrencyLimit, match="burst"):
        lim.acquire()
    assert lim.used_last_minute() == 3                # a refused request consumed nothing
    for _ in range(3):
        c.advance(2)
        lim.acquire()
    c.advance(2)
    with pytest.raises(ConcurrencyLimit, match="per-minute"):
        lim.acquire()
    assert lim.used_last_minute() == 6


def test_concurrency_slots_limit_release_and_wait_timeout():
    c = FakeClock()
    s = ConcurrencySlots(2, c.now, c.sleep)
    s.acquire()
    s.acquire()
    assert s.in_use == 2 and s.limit == 2
    t0 = c.now()
    with pytest.raises(ConcurrencyLimit, match="Already running 2"):
        s.acquire(timeout=3.0)
    assert c.now() - t0 >= 3.0                      # it waited (fake time) before giving up
    s.release()
    s.acquire()
    s.release()
    s.release()
    s.release()                                     # extra release never goes negative
    assert s.in_use == 0


def test_concurrency_slots_never_exceed_limit_under_threads():
    s = ConcurrencySlots(3)
    peak, current, lock = [0], [0], threading.Lock()

    def worker():
        try:
            s.acquire(timeout=5, poll=0.001)
        except ConcurrencyLimit:
            return
        with lock:
            current[0] += 1
            peak[0] = max(peak[0], current[0])
        threading.Event().wait(0.005)
        with lock:
            current[0] -= 1
        s.release()

    threads = [threading.Thread(target=worker) for _ in range(30)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert peak[0] <= 3 and s.in_use == 0


def test_circuit_breaker_opens_after_three_failures_and_recovers():
    c = FakeClock()
    b = CircuitBreaker(3, 60, c.now)
    b.check()
    b.record_failure()
    b.record_failure()
    b.check()                                       # still closed
    b.record_failure()
    assert b.is_open
    with pytest.raises(ConcurrencyLimit, match="paused"):
        b.check()
    c.advance(61)
    b.check()
    assert not b.is_open


def test_circuit_breaker_success_resets_the_count():
    b = CircuitBreaker(3, 60, FakeClock().now)
    b.record_failure()
    b.record_failure()
    b.record_success()
    b.record_failure()
    b.record_failure()
    b.check()                                       # would be open if success had not reset


def test_poll_limiter_enforces_minimum_interval():
    c = FakeClock()
    p = PollLimiter(0.5, c.now, c.sleep)
    p.wait()
    t = c.now()
    p.wait()
    assert c.now() - t == pytest.approx(0.5)
    c.advance(10)
    t = c.now()
    p.wait()
    assert c.now() == t                             # no wait needed after a long gap


def test_inflight_leader_follower_result_and_error_propagation():
    f = InFlight()
    flight, leader = f.begin("k")
    flight2, leader2 = f.begin("k")
    assert leader and not leader2 and flight is flight2
    got = {}
    t = threading.Thread(target=lambda: got.setdefault("v", f.wait(flight2, 2)))
    t.start()
    f.finish("k", result="done")
    t.join(2)
    assert got["v"] == "done"
    _, again = f.begin("k")
    assert again                                     # finished flights are cleared
    f.finish("k", error=RuntimeError("boom"))
    fl, _ = f.begin("z")
    f.finish("z", error=ValueError("bad"))
    with pytest.raises(ValueError):
        f.wait(fl, 1)


def test_inflight_wait_timeout_gives_a_helpful_error():
    f = InFlight()
    flight, _ = f.begin("k")
    with pytest.raises(ConcurrencyLimit, match="still running"):
        f.wait(flight, 0.01)


def test_result_cache_ttl_lru_and_disabled():
    c = FakeClock()
    cache = ResultCache(10, 2, c.now)
    cache.put("a", 1)
    cache.put("b", 2)
    assert cache.get("a") == (1, 0.0)               # touches 'a' -> 'b' becomes least recent
    cache.put("c", 3)
    assert cache.get("b") is None and cache.get("a")[0] == 1 and len(cache) == 2
    c.advance(11)
    assert cache.get("a") is None and cache.get("c") is None
    off = ResultCache(0, 5, c.now)
    off.put("x", 1)
    assert off.get("x") is None and len(off) == 0


def test_result_cache_reports_age():
    c = FakeClock()
    cache = ResultCache(120, 4, c.now)
    cache.put("k", "v")
    c.advance(30)
    assert cache.get("k") == ("v", 30.0)


def test_token_bucket_is_thread_safe():
    b = TokenBucket(50, 0, FakeClock().now)
    ok = []
    lock = threading.Lock()

    def worker():
        for _ in range(20):
            r = b.try_acquire()
            with lock:
                ok.append(r)

    ts = [threading.Thread(target=worker) for _ in range(10)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(ok) == 50
