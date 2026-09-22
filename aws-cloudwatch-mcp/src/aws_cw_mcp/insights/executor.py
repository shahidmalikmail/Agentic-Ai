"""Insights query executor: estimate -> cost guard -> start -> poll -> finish / continue / cancel.

Safety properties (each covered by tests):
* Every query is preceded by a `| estimate` run; if no unambiguous estimate exists, NOTHING runs (fail closed).
* Per-query byte cap and per-process byte budget (reserve -> commit actual / release).
* StartQuery is never retried after a timeout (no idempotency token -> could duplicate a billed query).
  Only a definite LimitExceeded/Throttling rejection is retried once after a backoff.
* Concurrency slots, start-rate limits, poll limits and a circuit breaker protect the shared account quota.
* Only queries this process started can be polled/cancelled (opaque handles + gate).
* A hard app deadline stops overdue queries (reaper, on-demand, and at shutdown).
* Logs contain fingerprint prefixes, counts, bytes, durations - never terms, messages or credentials.
"""
from __future__ import annotations

import logging
import random
import threading
import time
from typing import Callable, Optional

from botocore.exceptions import BotoCoreError, ClientError

from aws_cw_mcp.aws.insights_client import InsightsApi, QueryPage
from aws_cw_mcp.config import Config
from aws_cw_mcp.insights.cost import ByteBudget, CostGuard, Verdict, parse_estimate_bytes
from aws_cw_mcp.insights.limits import (CircuitBreaker, ConcurrencySlots, InFlight, PollLimiter, ResultCache,
                                        StartLimiter)
from aws_cw_mcp.insights.plans import QueryPlan
from aws_cw_mcp.insights.registry import Job, JobTable
from aws_cw_mcp.insights.results import RUNNING, InsightsOutcome
from aws_cw_mcp.insights.validator import ValidatedPlan, Validator
from aws_cw_mcp.utils.errors import (ConcurrencyLimit, CostGuardError, QueryFailed, QueryTimeout, ToolError,
                                     describe_exception)

logger = logging.getLogger("aws-cloudwatch-mcp")

_TERMINAL_FAILURE = {"Failed", "Cancelled", "Timeout", "Unknown"}
_THROTTLE_CODES = {"LimitExceededException", "ThrottlingException", "TooManyRequestsException"}
_ALREADY_ENDED = {"InvalidParameterException", "ResourceNotFoundException"}
_POLL_DELAYS = (1.0, 1.5, 2.0, 3.0, 4.0, 5.0)
_ESTIMATE_WAIT_SECONDS = 30.0


class EstimateOutcome:
    def __init__(self, validated: ValidatedPlan, estimated_bytes: int, verdict: Verdict, retention: dict,
                 cached: bool, price_usd: Optional[float]):
        self.validated, self.estimated_bytes, self.verdict = validated, estimated_bytes, verdict
        self.retention, self.cached, self.price_usd = retention, cached, price_usd


class InsightsExecutor:
    def __init__(self, cfg: Config, api: InsightsApi, catalog, validator: Validator, *,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 rng: Optional[random.Random] = None):
        self.cfg, self.api, self.catalog, self.validator = cfg, api, catalog, validator
        self.clock, self.sleep = clock, sleep
        self.rng = rng or random.Random()
        self.jobs = JobTable(clock=clock)
        self.budget = ByteBudget(cfg.insights_session_budget_bytes)
        self.guard = CostGuard(cfg)
        self.start_limiter = StartLimiter(cfg.insights_max_starts_per_minute, clock)
        self.slots = ConcurrencySlots(cfg.insights_max_concurrent, clock, sleep)
        self.breaker = CircuitBreaker(clock=clock)
        self.poll_limiter = PollLimiter(0.5, clock, sleep)
        self.cache = ResultCache(cfg.insights_cache_ttl, cfg.insights_cache_entries, clock)
        self.estimates = ResultCache(300, 64, clock)
        self.inflight = InFlight()
        self._reaper: Optional[threading.Thread] = None
        self._reaper_stop = threading.Event()

    # ------------------------------------------------------------------ public API
    def estimate(self, plan: QueryPlan) -> EstimateOutcome:
        self.reap()
        vp = self.validator.validate(plan)
        retention = self.catalog.check(vp.group_names)
        est, cached = self._estimate_bytes(vp)
        verdict = self.guard.evaluate(est, vp, self.budget.remaining)
        return EstimateOutcome(vp, est, verdict, retention, cached, self.guard.price_usd(est))

    def run(self, plan: QueryPlan, wait_seconds: Optional[float] = None) -> InsightsOutcome:
        self.reap()
        wait = self.cfg.insights_wait_seconds if wait_seconds is None else wait_seconds
        vp = self.validator.validate(plan)
        retention = self.catalog.check(vp.group_names)

        hit = self.cache.get(vp.cache_key)
        if hit is not None:
            cached, age = hit
            return self._copy(cached, cached=True, age=age)

        flight, leader = self.inflight.begin(vp.cache_key)
        if not leader:
            out = self.inflight.wait(flight, timeout=wait + 5)
            return self._copy(out, deduplicated=True)
        try:
            out = self._lead(vp, retention, wait)
        except BaseException as exc:
            self.inflight.finish(vp.cache_key, error=exc)
            raise
        self.inflight.finish(vp.cache_key, result=out)
        return out

    def resume(self, handle: str, wait_seconds: Optional[float] = None) -> InsightsOutcome:
        self.reap()
        job, finished = self.jobs.require(handle)
        if finished is not None:
            return self._copy(finished, cached=True, age=0.0)
        wait = self.cfg.insights_wait_seconds if wait_seconds is None else wait_seconds
        return self._drive(job, wait)

    def cancel(self, handle: str) -> InsightsOutcome:
        job, finished = self.jobs.require(handle)
        if finished is not None:
            return finished
        return self._stop_job(job, "user")

    def reap(self) -> int:
        """Stop queries that outlived the app deadline. Safe to call at any time."""
        n = 0
        for job in self.jobs.overdue(self.clock()):
            try:
                self._stop_job(job, "deadline")
                n += 1
            except Exception:  # noqa: BLE001 - reaper must never raise into a tool call
                logger.warning("reaper could not stop an overdue query (handle=%s)", job.handle, exc_info=False)
        return n

    def shutdown(self) -> None:
        self._reaper_stop.set()
        for job in self.jobs.all_running():
            try:
                self._stop_job(job, "shutdown")
            except Exception:  # noqa: BLE001
                logger.warning("could not stop a query during shutdown (handle=%s)", job.handle)

    def launch_reaper(self, interval: float = 15.0) -> None:
        if self._reaper is not None:
            return

        def loop():
            while not self._reaper_stop.wait(interval):
                self.reap()

        self._reaper = threading.Thread(target=loop, name="insights-reaper", daemon=True)
        self._reaper.start()

    def status(self) -> dict:
        now = self.clock()
        return {
            "budget": {"total_bytes": self.budget.total, "used_bytes": self.budget.used,
                       "reserved_bytes": self.budget.reserved, "remaining_bytes": self.budget.remaining,
                       "scope": "this server process only (resets on restart)"},
            "concurrency": {"in_use": self.slots.in_use, "limit": self.slots.limit},
            "start_rate": {"used_last_minute": self.start_limiter.used_last_minute(),
                           "limit_per_minute": self.cfg.insights_max_starts_per_minute},
            "circuit_breaker_open": self.breaker.is_open,
            "cache": {"entries": len(self.cache), "ttl_seconds": self.cfg.insights_cache_ttl},
            "running_jobs": [{"handle": j.handle, "kind": j.kind, "age_s": int(now - j.started_at),
                              "seconds_to_deadline": max(0, int(j.deadline - now)),
                              "estimated_bytes": j.estimated_bytes} for j in self.jobs.all_running()],
        }

    # ------------------------------------------------------------------ estimate
    def _estimate_bytes(self, vp: ValidatedPlan) -> tuple:
        hit = self.estimates.get(vp.cache_key)
        if hit is not None:
            return hit[0], True
        self.breaker.check()
        self.start_limiter.acquire()
        self.slots.acquire()
        query_id = None
        try:
            self.validator.approve(vp, estimate=True)
            query_id = self._begin(vp.estimate_query, vp, what="estimate")
            page = self._await_page(query_id, timeout=_ESTIMATE_WAIT_SECONDS)
            est = parse_estimate_bytes(page.rows)
        except ClientError as exc:
            info = describe_exception(exc)
            if info.kind in {"access_denied", "throttled", "credentials", "not_found"}:
                raise
            raise CostGuardError(f"A scan estimate could not be obtained ({info.code}); refusing to run the "
                                 "query (fail closed).") from None
        except QueryTimeout:
            self._best_effort_stop(query_id)
            raise CostGuardError("The scan estimate did not complete in time; refusing to run the query "
                                 "(fail closed).") from None
        finally:
            if query_id:
                self.api.forget(query_id)
            self.slots.release()
        self.estimates.put(vp.cache_key, est)
        logger.info("insights estimate fp=%s groups=%d est_bytes=%d", vp.fingerprint[:12],
                    len(vp.group_names), est)
        return est, False

    def _await_page(self, query_id: str, *, timeout: float) -> QueryPage:
        deadline = self.clock() + timeout
        i = 0
        while True:
            self.poll_limiter.wait()
            page = self.api.fetch_results(query_id, max_items=10)      # estimate results are tiny
            if page.status == "Complete":
                return page
            if page.status in _TERMINAL_FAILURE:
                raise CostGuardError(f"The scan estimate query ended with status {page.status}; refusing to "
                                     "run the query (fail closed).")
            if self.clock() >= deadline:
                raise QueryTimeout("estimate did not complete")
            self.sleep(self._delay(i))
            i += 1

    # ------------------------------------------------------------------ run
    def _lead(self, vp: ValidatedPlan, retention: dict, wait: float) -> InsightsOutcome:
        est, _ = self._estimate_bytes(vp)
        self.guard.enforce(est, vp, self.budget.remaining)
        reservation = self.budget.reserve(est)
        slot_held = False
        try:
            self.breaker.check()
            self.start_limiter.acquire()
            self.slots.acquire()
            slot_held = True
            self.validator.approve(vp, estimate=False)
            query_id = self._begin(vp.query, vp, what="query")
        except BaseException:
            if slot_held:
                self.slots.release()
            reservation.release()
            raise
        now = self.clock()
        job = Job(handle=JobTable.new_handle(), query_id=query_id, kind=vp.plan.kind, cache_key=vp.cache_key,
                  validated=vp, reservation=reservation, estimated_bytes=est, started_at=now,
                  deadline=now + self.cfg.insights_max_query_seconds, retention=retention)
        self.jobs.add(job)
        logger.info("insights started fp=%s kind=%s groups=%d est_bytes=%d", vp.fingerprint[:12], vp.plan.kind,
                    len(vp.group_names), est)
        return self._drive(job, wait)

    def _begin(self, query: str, vp: ValidatedPlan, *, what: str) -> str:
        """StartQuery with the documented retry policy: never after a timeout; once after a definite rejection."""
        attempts = 0
        while True:
            attempts += 1
            try:
                # Estimate: NO API limit (it would be appended after `| estimate`). Real query: bounded limit.
                query_id = self.api.begin_query(query=query, group_names=vp.group_names, start_s=vp.start_s,
                                                end_s=vp.end_s,
                                                limit=None if what == "estimate" else vp.api_limit)
                self.breaker.record_success()
                return query_id
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in _THROTTLE_CODES:
                    self.breaker.record_failure()
                    if attempts < 2:
                        self.sleep(2.0 + self.rng.random())
                        self.validator.approve(vp, estimate=(what == "estimate"))   # approval was single-use
                        continue
                    raise ConcurrencyLimit("AWS rejected the query start because the concurrent-query or request "
                                           "quota is exhausted; try again shortly.") from None
                raise
            except BotoCoreError:
                # Timeout / connection error: the query MAY have started and its id is unknown. Never retry.
                raise QueryFailed("The StartQuery request failed with an unknown outcome (timeout/connection). "
                                  "It was NOT retried, because a retry could start a duplicate billed query. "
                                  "Check again later or narrow the query.") from None

    # ------------------------------------------------------------------ drive / finish
    def _delay(self, i: int) -> float:
        base = _POLL_DELAYS[min(i, len(_POLL_DELAYS) - 1)]
        return base * (1 + self.rng.uniform(-0.1, 0.1))

    def _drive(self, job: Job, wait: float) -> InsightsOutcome:
        wait_deadline = self.clock() + wait
        i = 0
        try:
            while True:
                self.poll_limiter.wait()
                page = self.api.fetch_results(job.query_id, max_items=1)
                job.last_bytes = max(job.last_bytes, page.bytes_scanned)
                if page.status == "Complete":
                    return self._finish(job)
                if page.status in _TERMINAL_FAILURE:
                    self._settle(job, job.last_bytes)
                    self.jobs.finish(job, self._outcome(job, "failed", reason=page.status))
                    raise QueryFailed(f"AWS reported the query status '{page.status}'. No results are available.")
                now = self.clock()
                if now >= job.deadline:
                    return self._stop_job(job, "deadline")
                if now >= wait_deadline:
                    return self._outcome(job, RUNNING, handle=job.handle)
                self.sleep(self._delay(i))
                i += 1
        except ToolError:
            raise
        except Exception:
            self._abort(job)
            raise

    def _finish(self, job: Job) -> InsightsOutcome:
        vp = job.validated
        cap = self.cfg.insights_max_rows
        rows: list = []
        stats: dict = {}
        token = None
        for _ in range(5):
            page = self.api.fetch_results(job.query_id, max_items=max(1, cap - len(rows)), next_token=token)
            rows.extend(page.rows)
            stats = page.statistics or stats
            token = page.next_token
            if not token or len(rows) >= cap:
                break
        actual = int(float(stats.get("bytesScanned") or job.last_bytes or 0))
        self._settle(job, actual)
        out = self._outcome(job, "complete", rows=rows[:cap], statistics=stats, actual_bytes=actual)
        self.jobs.finish(job, out)
        self.cache.put(job.cache_key, out)
        logger.info("insights complete fp=%s rows=%d bytes=%d ms=%d", vp.fingerprint[:12], len(rows), actual,
                    int((self.clock() - job.started_at) * 1000))
        return out

    def _outcome(self, job: Job, state: str, *, rows=None, statistics=None, actual_bytes=None, handle=None,
                 reason=None) -> InsightsOutcome:
        return InsightsOutcome(
            state=state, validated=job.validated, rows=list(rows or []), statistics=dict(statistics or {}),
            estimated_bytes=job.estimated_bytes, actual_bytes=actual_bytes if actual_bytes is not None
            else (job.last_bytes if state != RUNNING else None), handle=handle,
            elapsed_s=self.clock() - job.started_at, retention=job.retention, reason=reason,
            budget_remaining=self.budget.remaining,
            price_usd=self.guard.price_usd(actual_bytes) if actual_bytes is not None else None)

    def _settle(self, job: Job, actual: int) -> None:
        """Exactly-once: commit bytes to the budget, release the slot, forget the id."""
        with job.lock:
            if job.settled:
                return
            job.settled = True
        job.reservation.commit(actual)
        self.slots.release()
        self.api.forget(job.query_id)

    def _stop_job(self, job: Job, reason: str) -> InsightsOutcome:
        with job.lock:
            already = job.settled
        if already:                                   # settled elsewhere: make sure it leaves the table
            out = self._outcome(job, "cancelled", reason=reason)
            self.jobs.finish(job, out)
            return out
        try:
            self.api.cancel_query(job.query_id)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in _ALREADY_ENDED:                   # "not running" == already ended == success [V]
                raise
        self._settle(job, job.last_bytes)
        out = self._outcome(job, "cancelled", reason=reason)
        self.jobs.finish(job, out)
        logger.info("insights stopped handle=%s reason=%s", job.handle, reason)
        return out

    def _abort(self, job: Job) -> None:
        try:
            self._stop_job(job, "error")
        except Exception:  # noqa: BLE001 - best effort; the deadline reaper and AWS's own timeout remain
            self._settle(job, job.last_bytes)

    def _best_effort_stop(self, query_id: Optional[str]) -> None:
        if not query_id:
            return
        try:
            self.api.cancel_query(query_id)
        except Exception:  # noqa: BLE001
            logger.warning("could not stop an unfinished estimate query")

    @staticmethod
    def _copy(out: InsightsOutcome, *, cached: bool = False, age: Optional[float] = None,
              deduplicated: bool = False) -> InsightsOutcome:
        import copy
        c = copy.copy(out)
        c.cached = cached or out.cached
        c.cache_age_s = age if age is not None else out.cache_age_s
        c.deduplicated = deduplicated or out.deduplicated
        return c
