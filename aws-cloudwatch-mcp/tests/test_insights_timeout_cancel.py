"""Wait budget, continuation handles, app deadline, cancellation, shutdown, concurrency, de-duplication."""
import threading
import time

import pytest
from botocore.exceptions import ClientError

from aws_cw_mcp.insights.plans import plan_cache_key
from aws_cw_mcp.insights.results import RUNNING, outcome_to_result
from aws_cw_mcp.utils.errors import ConcurrencyLimit, InputError
from conftest import Harness, make_insights_config, plan_for

ROWS = [{"bin(1m)": "2026-09-20 11:10:00.000", "matches": 3}]


def _start_running(h, query_id="q-1", polls=12, wait=3, **plan_kw):
    """estimate + start, then enough Running polls that the wait budget (not AWS) ends the call."""
    h.estimate_flow(1_000_000)
    h.start_ok(query_id)
    for _ in range(polls):
        h.results("Running", bytes_scanned=4096)
    out = h.executor.run(plan_for(h.cfg, **plan_kw), wait_seconds=wait)
    h.read_stub._queue.clear()          # drop unused Running polls so later stubs (stop/complete) are next in line
    return out


def test_wait_expiry_returns_handle_and_keeps_job_owned():
    h = Harness()
    out = _start_running(h)
    assert out.state == RUNNING and out.handle.startswith("qh_")
    assert out.handle != "q-1" and "q-1" not in out.handle       # opaque, never the AWS queryId
    st = h.executor.status()
    assert st["concurrency"]["in_use"] == 1 and st["budget"]["reserved_bytes"] == 1_000_000
    assert h.owned.contains("q-1")
    res = outcome_to_result("aws_insights_count_over_time", out, h.cfg).to_dict()
    assert res["status"] == "partial" and "not final" in res["summary"]
    assert "series" not in res["FACT"] and "rows" not in res["FACT"]      # no partial numbers as facts


def test_resume_with_handle_completes_and_releases_everything():
    h = Harness()
    out = _start_running(h, polls=12)
    h.read_stub._queue.clear()                                   # drop unused Running polls
    h.results("Complete", bytes_scanned=9000)
    h.results("Complete", ROWS, bytes_scanned=9000)
    done = h.executor.resume(out.handle, wait_seconds=5)
    assert done.state == "complete" and done.actual_bytes == 9000
    assert h.executor.slots.in_use == 0 and h.executor.budget.reserved == 0 and h.executor.budget.used == 9000
    again = h.executor.resume(out.handle)                        # late call still answers, no AWS call
    assert again.state == "complete" and again.cached
    h.done()


def test_app_deadline_during_poll_stops_the_query():
    h = Harness(make_insights_config(insights_max_query_seconds=10, insights_wait_seconds=5))
    h.start_ok("est-1")
    h.start_ok("q-1")
    from aws_cw_mcp.aws.insights_client import QueryPage

    def fake_fetch(qid, **kw):      # the estimate completes; the real query never does
        if qid == "est-1":
            return QueryPage("Complete", rows=[{"estimatedBytes": "1000000"}])
        return QueryPage("Running", statistics={"bytesScanned": 2048.0})

    h.api.fetch_results = fake_fetch
    h.stop_ok()
    out = h.executor.run(plan_for(h.cfg), wait_seconds=1000)      # wait longer than the deadline
    assert out.state == "cancelled" and out.reason == "deadline"
    assert h.executor.slots.in_use == 0 and h.executor.budget.used == 2048
    assert not h.owned.contains("q-1")


def test_reaper_stops_overdue_running_job():
    h = Harness()
    out = _start_running(h)
    h.stop_ok()
    h.clock.advance(h.cfg.insights_max_query_seconds + 1)
    assert h.executor.reap() == 1
    assert h.executor.status()["running_jobs"] == []
    res = h.executor.resume(out.handle)
    assert res.state == "cancelled" and res.reason == "deadline"
    assert h.executor.slots.in_use == 0 and h.executor.budget.reserved == 0


def test_reaper_runs_on_every_tool_entry():
    h = Harness()
    _start_running(h)
    h.stop_ok()
    h.clock.advance(h.cfg.insights_max_query_seconds + 5)
    h.estimate_flow(50, query_id="est-2")
    h.executor.estimate(plan_for(h.cfg, preset="timeouts"))       # any call reaps first
    assert h.executor.status()["running_jobs"] == []


def test_user_cancel_stops_and_second_cancel_makes_no_aws_call():
    h = Harness()
    out = _start_running(h)
    h.stop_ok()
    c = h.executor.cancel(out.handle)
    assert c.state == "cancelled" and c.reason == "user"
    assert h.executor.slots.in_use == 0 and not h.owned.contains("q-1")
    c2 = h.executor.cancel(out.handle)                            # Stubber would raise on an extra stop_query
    assert c2.state == "cancelled"


def test_stop_already_ended_is_treated_as_success():
    h = Harness()
    out = _start_running(h)
    h.read_stub.add_client_error("stop_query", "InvalidParameterException", "Query is not running")
    c = h.executor.cancel(out.handle)
    assert c.state == "cancelled"
    assert h.executor.slots.in_use == 0


def test_stop_failure_other_than_already_ended_propagates_and_job_is_retained():
    h = Harness()
    out = _start_running(h)
    h.read_stub.add_client_error("stop_query", "AccessDeniedException", "denied")
    with pytest.raises(ClientError):
        h.executor.cancel(out.handle)
    assert h.executor.slots.in_use == 1                           # still running -> slot not released
    assert len(h.executor.status()["running_jobs"]) == 1
    h.stop_ok()
    h.executor.cancel(out.handle)                                 # retry works
    assert h.executor.slots.in_use == 0


@pytest.mark.parametrize("bad", ["q-1", "qh_doesnotexist", "", "../etc", "qh_" + "x" * 100, None, 123])
def test_only_handles_issued_by_this_server_are_accepted(bad):
    h = Harness()
    with pytest.raises(InputError):
        h.executor.resume(bad)
    with pytest.raises(InputError):
        h.executor.cancel(bad)


def test_shutdown_stops_all_running_queries():
    h = Harness(make_insights_config(insights_max_concurrent=2))
    _start_running(h, "q-1")
    h.stop_ok()
    h.executor.shutdown()
    assert h.executor.status()["running_jobs"] == [] and h.executor.slots.in_use == 0


def test_background_reaper_thread_stops_overdue_job():
    h = Harness()
    _start_running(h)
    h.stop_ok()
    h.clock.advance(h.cfg.insights_max_query_seconds + 1)
    h.executor.launch_reaper(interval=0.01)
    h.executor.launch_reaper(interval=0.01)                       # idempotent
    for _ in range(300):
        if not h.executor.status()["running_jobs"]:
            break
        time.sleep(0.01)
    h.executor.shutdown()
    assert h.executor.status()["running_jobs"] == []


# ---- concurrency + de-duplication ---------------------------------------------------------------------
def test_concurrency_limit_blocks_extra_queries_without_touching_aws():
    h = Harness(make_insights_config(insights_max_concurrent=1))
    _start_running(h)
    with pytest.raises(ConcurrencyLimit, match="Already running 1"):
        h.executor.run(plan_for(h.cfg, preset="timeouts"))        # no stubs queued: any AWS call would fail
    assert h.executor.slots.in_use == 1


def test_identical_concurrent_request_shares_the_leader_result():
    h = Harness()
    plan = plan_for(h.cfg)
    vp = h.validator.validate(plan)
    flight, leader = h.executor.inflight.begin(vp.cache_key)      # act as the leader
    assert leader
    result = {}

    def follower():
        result["out"] = h.executor.run(plan)

    t = threading.Thread(target=follower)
    t.start()
    time.sleep(0.05)
    assert t.is_alive()                                           # waiting on the leader, no AWS calls
    sentinel = _fake_outcome(h, vp)                               # a completed outcome to hand over
    h.executor.inflight.finish(vp.cache_key, result=sentinel)
    t.join(2)
    assert result["out"].deduplicated is True and result["out"].state == "complete"


def _fake_outcome(h, vp):
    from aws_cw_mcp.insights.results import InsightsOutcome
    return InsightsOutcome(state="complete", validated=vp, rows=[], estimated_bytes=1, actual_bytes=1)


def test_leader_failure_propagates_to_waiting_follower():
    h = Harness()
    plan = plan_for(h.cfg)
    vp = h.validator.validate(plan)
    flight, _ = h.executor.inflight.begin(vp.cache_key)
    box = {}

    def follower():
        try:
            h.executor.run(plan)
        except Exception as exc:  # noqa: BLE001
            box["exc"] = exc

    t = threading.Thread(target=follower)
    t.start()
    time.sleep(0.05)
    h.executor.inflight.finish(vp.cache_key, error=ConcurrencyLimit("boom"))
    t.join(2)
    assert isinstance(box["exc"], ConcurrencyLimit)
    assert plan_cache_key(plan) == vp.cache_key
