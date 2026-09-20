"""Structural read-only guarantees."""
import re
from pathlib import Path

import boto3
import pytest

from aws_cw_mcp.aws.client import READ_ONLY_OPERATIONS, WRITE_VERBS, AwsClients, assert_read_only
from aws_cw_mcp.utils.errors import AccountMismatch, ReadOnlyViolation
from conftest import make_config

SRC = Path(__file__).resolve().parents[1] / "src" / "aws_cw_mcp"


def test_allowlist_contains_no_write_verbs():
    for op in READ_ONLY_OPERATIONS:
        assert not op.startswith(WRITE_VERBS), op


@pytest.mark.parametrize("op", ["PutMetricData", "DeleteLogGroup", "CreateLogGroup", "PutRetentionPolicy",
                                "DeleteAlarms", "PutMetricAlarm", "SetAlarmState", "StartQuery",
                                "TerminateInstances", "UpdateWebACL", "Publish", "SendEmail"])
def test_write_operations_blocked(op):
    with pytest.raises(ReadOnlyViolation):
        assert_read_only(op)


def _clients(monkeypatch):
    session = boto3.session.Session(aws_access_key_id="testing", aws_secret_access_key="testing",
                                    region_name="us-east-1")
    monkeypatch.setattr(AwsClients, "identity",
                        lambda self: {"account": "926266574832", "arn": "arn:aws:iam::926266574832:user/x"})
    return AwsClients(make_config(aws_account_id="926266574832"), session=session)


@pytest.mark.parametrize("service,call,kwargs", [
    ("logs", "delete_log_group", {"logGroupName": "x"}),
    ("logs", "put_retention_policy", {"logGroupName": "x", "retentionInDays": 1}),
    ("logs", "create_log_group", {"logGroupName": "x"}),
    ("cloudwatch", "delete_alarms", {"AlarmNames": ["a"]}),
    ("cloudwatch", "set_alarm_state", {"AlarmName": "a", "StateValue": "OK", "StateReason": "r"}),
    ("cloudwatch", "put_metric_data", {"Namespace": "N", "MetricData": []}),
])
def test_real_client_blocks_writes_before_any_network(service, call, kwargs, monkeypatch):
    """The before-call guard raises before the request is signed or sent."""
    client = _clients(monkeypatch).client(service)
    with pytest.raises(ReadOnlyViolation):
        getattr(client, call)(**kwargs)


def test_account_pin_mismatch_refuses(monkeypatch):
    clients = AwsClients(make_config(aws_account_id="111111111111"),
                         session=boto3.session.Session(aws_access_key_id="t", aws_secret_access_key="t",
                                                       region_name="us-east-1"))
    monkeypatch.setattr(AwsClients, "identity", lambda self: {"account": "222222222222", "arn": "x"})
    with pytest.raises(AccountMismatch):
        clients.logs()


def test_no_generic_execute_tool_and_all_tools_declared_readonly():
    import asyncio

    from aws_cw_mcp.server import build_tools, create_server
    from aws_cw_mcp.runtime import Runtime
    from conftest import FakeClients

    cfg = make_config()
    names = set(build_tools(Runtime(cfg, FakeClients())))
    assert names == {"aws_health_check", "aws_discover_log_groups", "aws_search_logs",
                     "aws_list_log_streams", "aws_get_log_events", "aws_list_metrics",
                     "aws_get_metrics", "aws_get_alarms", "aws_get_alarm_history"}
    assert not any(re.search(r"exec|run|call|invoke|command", n) for n in names)

    mcp = create_server(cfg, Runtime(cfg, FakeClients()))
    tools = asyncio.run(mcp.list_tools())
    listed = tools.tools if hasattr(tools, "tools") else tools
    assert {t.name for t in listed} == names
    for t in listed:
        ann = t.annotations
        assert ann is not None
        ro = getattr(ann, "read_only_hint", getattr(ann, "readOnlyHint", None))
        destructive = getattr(ann, "destructive_hint", getattr(ann, "destructiveHint", None))
        assert ro is True and destructive is False


def test_source_has_no_unsafe_constructs():
    """Static guard: no subprocess/eval/exec/print/stdout writes or write-style boto calls."""
    bad = re.compile(r"\bsubprocess\b|os\.system|\beval\(|\bexec\(|\bprint\(|sys\.stdout|"
                     r"\.(put|delete|create|update|set|start|stop|terminate|modify|publish|send|"
                     r"invoke|attach|detach|tag|untag)_[a-z_]+\(|getattr\(\s*self\._c|getattr\(\s*client")
    offenders = []
    for path in SRC.rglob("*.py"):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            if bad.search(line):
                offenders.append(f"{path.name}:{n}: {line.strip()}")
    assert not offenders, offenders


def test_source_never_reads_credential_env_vars_for_use():
    text = "\n".join(p.read_text(encoding="utf-8") for p in SRC.rglob("*.py"))
    assert "aws_access_key_id=" not in text.lower().replace(" ", "")
    assert "aws_secret_access_key=" not in text.lower().replace(" ", "")
