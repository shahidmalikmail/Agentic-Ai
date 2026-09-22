"""Shared fixtures. No real AWS access: clients are botocore-Stubber backed and use
obviously fake credentials that never leave the process."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import boto3
import pytest
from botocore.stub import Stubber

from aws_cw_mcp.config import Config
from aws_cw_mcp.utils.timerange import TimeRange

NOW = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)
TR = TimeRange(NOW - timedelta(hours=1), NOW)


def make_config(**over) -> Config:
    base = dict(aws_region="us-east-1", cache_ttl_seconds=60)
    base.update(over)
    return Config(**base)


def make_client(service: str):
    return boto3.client(service, region_name="us-east-1",
                        aws_access_key_id="testing", aws_secret_access_key="testing")


@pytest.fixture
def cfg():
    return make_config()


@pytest.fixture
def logs_stub():
    client = make_client("logs")
    with Stubber(client) as stub:
        yield client, stub
        stub.assert_no_pending_responses()


@pytest.fixture
def cw_stub():
    client = make_client("cloudwatch")
    with Stubber(client) as stub:
        yield client, stub
        stub.assert_no_pending_responses()


class FakeClients:
    """Stands in for AwsClients in tool-level tests."""

    def __init__(self, logs=None, cloudwatch=None, identity=None):
        self._logs, self._cw = logs, cloudwatch
        self._identity = identity or {"account": "123456789012", "arn": "arn:aws:iam::123456789012:role/test"}

    def logs(self):
        return self._logs

    def cloudwatch(self):
        return self._cw

    def identity(self):
        return self._identity

    def verify_account(self):
        return self._identity


def parse(out: str) -> dict:
    return json.loads(out)


# =====================================================================================
# Phase 2A (Logs Insights) fixtures. Still no AWS: Stubber + fake clock + network block.
# =====================================================================================
import random
import socket

from aws_cw_mcp.aws.insights_client import InsightsApi, InsightsGate, attach_gate
from aws_cw_mcp.insights.executor import InsightsExecutor
from aws_cw_mcp.insights.planner import build_plan
from aws_cw_mcp.insights.plans import KIND_COUNT_OVER_TIME
from aws_cw_mcp.insights.registry import ApprovedQueryRegistry, OwnedQueryRegistry
from aws_cw_mcp.insights.validator import Validator
from aws_cw_mcp.utils.errors import NotFoundError

ACCOUNT = "926266574832"
GROUP = "/aws/app/one"


@pytest.fixture(autouse=True)
def _block_real_network(monkeypatch):
    """No unit test may open a non-loopback connection (AWS is never contacted)."""
    real = socket.socket.connect

    def guard(self, addr, *a, **k):
        host = addr[0] if isinstance(addr, tuple) else str(addr)
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise RuntimeError(f"NON-LOOPBACK NETWORK ACCESS ATTEMPTED IN A UNIT TEST: {addr!r}")
        return real(self, addr, *a, **k)

    monkeypatch.setattr(socket.socket, "connect", guard)


class FakeClock:
    def __init__(self, start: float = 1000.0):
        self.t = start

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        self.t += max(0.0, seconds)

    def advance(self, seconds: float) -> None:
        self.t += seconds


def make_insights_config(**over) -> Config:
    base = dict(insights_enabled=True, insights_profile="ob-aws-cloudwatch-insights", aws_account_id=ACCOUNT,
                aws_profile="ob-aws-cloudwatch")
    base.update(over)
    return make_config(**base)


def plan_for(cfg, kind=KIND_COUNT_OVER_TIME, groups=(GROUP,), lookback="1h", preset="errors", **kw):
    return build_plan(cfg, kind=kind, log_groups=list(groups), lookback=lookback, preset=preset, now=NOW, **kw)


class FakeCatalog:
    def __init__(self, groups=(GROUP,), retention=30):
        self.groups = {g: retention for g in groups}

    def check(self, names):
        missing = [n for n in names if n not in self.groups]
        if missing:
            raise NotFoundError("Log group(s) not found or not visible: " + ", ".join(missing))
        return {n: self.groups[n] for n in names}


class FakeInsightsClients:
    """Provides the surface InsightsApi needs, backed by two gated, Stubber-controlled real boto clients."""

    def __init__(self, approved, owned, start_client, read_client):
        self.approved, self.owned = approved, owned
        self._start, self._read = start_client, read_client

    def begin_client(self):
        return self._start

    def read_client(self):
        return self._read

    def verify(self):
        return {"account": ACCOUNT, "arn": f"arn:aws:iam::{ACCOUNT}:user/cloud-watch-insights-review"}


def cells(**row):
    return [{"field": k, "value": str(v)} for k, v in row.items()]


class Harness:
    """Full Insights stack (gate, api, validator, executor) over Stubber-backed clients and a fake clock."""

    def __init__(self, cfg=None, groups=(GROUP,), retention=30):
        self.cfg = cfg or make_insights_config()
        self.clock = FakeClock()
        self.approved = ApprovedQueryRegistry(60, self.clock.now)
        self.owned = OwnedQueryRegistry()
        self.gate = InsightsGate(self.approved, self.owned)
        self.start_client = make_client("logs")
        self.read_client = make_client("logs")
        for c in (self.start_client, self.read_client):
            attach_gate(c, self.gate)
        self.start_stub = Stubber(self.start_client)
        self.read_stub = Stubber(self.read_client)
        self.start_stub.activate()
        self.read_stub.activate()
        self.clients = FakeInsightsClients(self.approved, self.owned, self.start_client, self.read_client)
        self.api = InsightsApi(self.clients)
        self.validator = Validator(self.cfg, self.approved)
        self.catalog = FakeCatalog(groups, retention)
        self.executor = InsightsExecutor(self.cfg, self.api, self.catalog, self.validator,
                                         clock=self.clock.now, sleep=self.clock.sleep, rng=random.Random(0))

    # -- stub helpers ---------------------------------------------------------------
    def start_ok(self, query_id, expected=None):
        self.start_stub.add_response("start_query", {"queryId": query_id}, expected)

    def start_error(self, code, message="boom"):
        self.start_stub.add_client_error("start_query", code, message)

    def results(self, status, rows=None, bytes_scanned=None, next_token=None):
        resp = {"status": status, "results": [cells(**r) for r in (rows or [])]}
        if bytes_scanned is not None:
            resp["statistics"] = {"bytesScanned": float(bytes_scanned), "recordsMatched": 1.0,
                                  "recordsScanned": 10.0}
        if next_token:
            resp["nextToken"] = next_token
        self.read_stub.add_response("get_query_results", resp)

    def stop_ok(self):
        self.read_stub.add_response("stop_query", {"success": True})

    def estimate_flow(self, est_bytes=1_000_000, query_id="est-1"):
        """start(estimate) + one Complete poll returning the estimate."""
        self.start_ok(query_id)
        self.results("Complete", [{"estimatedBytes": est_bytes}])

    def run_flow(self, rows, actual=2_000_000, query_id="q-1", est_bytes=1_000_000, running_polls=0):
        """estimate + start + optional Running polls + Complete poll + final fetch."""
        self.estimate_flow(est_bytes)
        self.start_ok(query_id)
        for _ in range(running_polls):
            self.results("Running", bytes_scanned=1000)
        self.results("Complete", bytes_scanned=actual)              # poll (max_items=1)
        self.results("Complete", rows, bytes_scanned=actual)        # final fetch

    def done(self):
        self.start_stub.assert_no_pending_responses()
        self.read_stub.assert_no_pending_responses()


@pytest.fixture
def harness():
    h = Harness()
    yield h
    h.start_stub.deactivate()
    h.read_stub.deactivate()
