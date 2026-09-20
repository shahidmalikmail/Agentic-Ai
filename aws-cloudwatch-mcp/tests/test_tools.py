"""Tool-level behaviour: JSON envelope, error surfacing, no invented data."""
import json

import pytest
from botocore.exceptions import ReadTimeoutError
from botocore.stub import Stubber

from aws_cw_mcp.runtime import Runtime
from aws_cw_mcp.server import build_tools
from conftest import FakeClients, make_client, make_config, parse


def _tools(logs=None, cw=None, **cfg):
    return build_tools(Runtime(make_config(**cfg), FakeClients(logs=logs, cloudwatch=cw)))


def test_health_check_reports_identity_and_limits_without_credentials():
    out = _tools()["aws_health_check"]()
    d = parse(out)
    assert d["status"] == "ok" and d["read_only"] is True
    assert d["FACT"]["aws_account"] == "123456789012"
    assert "GetLogEvents" in d["FACT"]["allowed_aws_operations"]
    assert "testing" not in out and "secret" not in out.lower()


def test_access_denied_becomes_unavailable_not_invented_data():
    client = make_client("logs")
    with Stubber(client) as stub:
        stub.add_client_error("describe_log_groups", "AccessDeniedException",
                              "User: arn:aws:sts::1:assumed-role/r/i is not authorized to perform: "
                              "logs:DescribeLogGroups")
        d = parse(_tools(logs=client)["aws_discover_log_groups"](keyword="waf"))
    assert d["status"] == "error" and d["error"]["kind"] == "access_denied"
    assert "No CloudWatch data is currently available" in d["summary"]
    assert d["FACT"] == {}
    assert "logs:DescribeLogGroups" in d["error"]["hint"] or "DescribeLogGroups" in d["error"]["hint"]


def test_throttling_reported():
    client = make_client("cloudwatch")
    with Stubber(client) as stub:
        stub.add_client_error("describe_alarms", "ThrottlingException", "Rate exceeded")
        d = parse(_tools(cw=client)["aws_get_alarms"]())
    assert d["error"]["kind"] == "throttled"


def test_timeout_reported():
    class Slow:
        def filter_log_events(self, **kw):
            raise ReadTimeoutError(endpoint_url="https://logs.us-east-1.amazonaws.com")
    d = parse(_tools(logs=Slow())["aws_search_logs"](log_groups=["/g"], lookback="15m"))
    assert d["error"]["kind"] == "timeout"


def test_invalid_input_is_a_clean_error_not_an_exception():
    t = _tools(logs=make_client("logs"))
    d = parse(t["aws_search_logs"](log_groups=["/g"], lookback="48h"))
    assert d["error"]["kind"] == "invalid_input" and "exceeds" in d["error"]["message"]
    d = parse(t["aws_search_logs"](log_groups=["/g"], lookback="soon"))
    assert d["error"]["kind"] == "invalid_input"


def test_unexpected_exception_does_not_leak_details():
    class Broken:
        def describe_log_groups(self, **kw):
            raise RuntimeError("internal password=hunter2 /etc/secret")
    out = _tools(logs=Broken())["aws_discover_log_groups"]()
    d = parse(out)
    assert d["error"]["kind"] == "internal_error" and "hunter2" not in out and "/etc/secret" not in out


def test_recommendations_always_labelled_and_envelope_shape():
    from aws_cw_mcp.models.results import ToolResult
    d = ToolResult("t", "ok", "s", recommendations=["Review the threshold"]).to_dict()
    assert d["RECOMMENDATION"][0].startswith("RECOMMENDATION (human decision required; nothing was executed)")
    assert {"FACT", "ANALYSIS", "RECOMMENDATION", "read_only", "notice"} <= set(d)


def test_search_logs_end_to_end_json():
    client = make_client("logs")
    with Stubber(client) as stub:
        stub.add_response("filter_log_events", {"events": [
            {"timestamp": 1_700_000_000_000, "message": "ERROR Authorization: Bearer abcdefgh12345678",
             "logStreamName": "s"}]})
        out = _tools(logs=client)["aws_search_logs"](log_groups=["/app/ts-app"], filter_pattern="ERROR",
                                                     lookback="1h")
    assert "abcdefgh12345678" not in out
    assert json.loads(out)["FACT"]["count"] == 1


def test_get_metrics_tool_rejects_range_over_config_max():
    d = parse(_tools(cw=make_client("cloudwatch"), max_metric_time_range_hours=24)["aws_get_metrics"](
        metrics=[{"namespace": "AWS/EC2", "metric_name": "CPUUtilization"}], lookback="7d"))
    assert d["error"]["kind"] == "invalid_input"


def test_alarm_history_tool_default_window():
    client = make_client("cloudwatch")
    with Stubber(client) as stub:
        stub.add_response("describe_alarm_history", {"AlarmHistoryItems": []})
        d = parse(_tools(cw=client)["aws_get_alarm_history"](alarm_name="a1"))
    assert d["status"] == "empty" and d["meta"]["time_range"]["seconds"] == 86400


def test_log_formatter_redacts_secrets_and_targets_stderr(capsys):
    import logging

    from aws_cw_mcp.server import _configure_logging

    _configure_logging("INFO")
    logging.getLogger("aws-cloudwatch-mcp").warning("boom password=hunter2 AKIAIOSFODNN7EXAMPLE")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "hunter2" not in captured.err and "AKIAIOSFODNN7EXAMPLE" not in captured.err
