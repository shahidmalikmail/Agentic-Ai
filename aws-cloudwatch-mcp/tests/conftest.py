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
