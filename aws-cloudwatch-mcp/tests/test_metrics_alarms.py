from datetime import datetime, timedelta, timezone

import pytest

from aws_cw_mcp.aws.cloudwatch import AlarmsService, MetricsService
from aws_cw_mcp.utils.errors import InputError
from aws_cw_mcp.utils.timerange import TimeRange
from conftest import NOW, TR, make_config

Q = {"namespace": "AWS/EC2", "metric_name": "CPUUtilization", "stat": "Average",
     "dimensions": {"InstanceId": "i-0abc"}}


def _pts(n, base=10.0):
    return ([NOW - timedelta(minutes=n - i) for i in range(n)], [base + i for i in range(n)])


# ------------------------------------------------------------ list_metrics
def test_list_metrics_requires_filter(cw_stub, cfg):
    with pytest.raises(InputError, match="not allowed"):
        MetricsService(cw_stub[0], cfg).list_metrics()


def test_list_metrics_paginates_and_caches(cw_stub, cfg):
    client, stub = cw_stub
    m = lambda n: {"Namespace": "AWS/EC2", "MetricName": n,  # noqa: E731
                   "Dimensions": [{"Name": "InstanceId", "Value": "i-1"}]}
    stub.add_response("list_metrics", {"Metrics": [m("CPUUtilization")], "NextToken": "x"})
    stub.add_response("list_metrics", {"Metrics": [m("NetworkIn")]})
    svc = MetricsService(client, cfg)
    res = svc.list_metrics(namespace="AWS/EC2")
    assert [x["metric_name"] for x in res.facts["metrics"]] == ["CPUUtilization", "NetworkIn"]
    assert svc.list_metrics(namespace="AWS/EC2").meta["cached"] is True


def test_list_metrics_empty_says_may_not_be_published(cw_stub, cfg):
    client, stub = cw_stub
    stub.add_response("list_metrics", {"Metrics": []})
    res = MetricsService(client, cfg).list_metrics(namespace="CWAgent", metric_name="mem_used_percent")
    assert res.status == "empty" and "not publish" in res.summary


# ------------------------------------------------------------- get_metrics
def test_get_metrics_stats_and_datapoints(cw_stub, cfg):
    client, stub = cw_stub
    ts, vals = _pts(60)
    stub.add_response("get_metric_data", {"MetricDataResults": [
        {"Id": "m0", "Label": "l", "Timestamps": ts, "Values": vals, "StatusCode": "Complete"}]})
    res = MetricsService(client, cfg).get_metrics([Q], TR)
    s = res.facts["metrics"][0]
    assert s["stats"]["max"] == 69.0 and s["stats"]["latest"] == 69.0 and s["stats"]["count"] == 60
    assert s["period_seconds"] == 60 and len(s["datapoints"]) == 60
    assert res.status == "ok" and "not per-request latency" in res.analysis[0]


def test_get_metrics_pagination_merges_and_downsamples(cw_stub):
    client, stub = cw_stub
    t1, v1 = _pts(30)
    t2, v2 = _pts(30, 100)
    stub.add_response("get_metric_data", {"MetricDataResults": [
        {"Id": "m0", "Label": "l", "Timestamps": t1, "Values": v1}], "NextToken": "n"})
    stub.add_response("get_metric_data", {"MetricDataResults": [
        {"Id": "m0", "Label": "l", "Timestamps": t2, "Values": v2}]})
    res = MetricsService(client, make_config(max_datapoints_returned=20)).get_metrics([Q], TR)
    s = res.facts["metrics"][0]
    assert s["stats"]["count"] == 60 and s["datapoints_downsampled_every"] == 3
    assert len(s["datapoints"]) == 20


def test_get_metrics_no_data_is_reported_not_invented(cw_stub, cfg):
    client, stub = cw_stub
    stub.add_response("get_metric_data", {"MetricDataResults": [
        {"Id": "m0", "Label": "l", "Timestamps": [], "Values": []}]})
    res = MetricsService(client, cfg).get_metrics(
        [{"namespace": "CWAgent", "metric_name": "mem_used_percent"}], TR)
    assert res.status == "empty" and "No metric data is currently available" in res.summary
    assert any("may not be published" in w for w in res.warnings)


def test_get_metrics_partial_when_one_series_empty(cw_stub, cfg):
    client, stub = cw_stub
    ts, vals = _pts(5)
    stub.add_response("get_metric_data", {"MetricDataResults": [
        {"Id": "m0", "Label": "a", "Timestamps": ts, "Values": vals},
        {"Id": "m1", "Label": "b", "Timestamps": [], "Values": []}]})
    res = MetricsService(client, cfg).get_metrics(
        [Q, {"namespace": "CWAgent", "metric_name": "mem_used_percent"}], TR)
    assert res.status == "partial"


def test_get_metrics_period_selection_and_limits(cw_stub):
    client, stub = cw_stub
    svc = MetricsService(client, make_config(max_query_results=1000))
    day = TimeRange(NOW - timedelta(days=1), NOW)
    assert svc._choose_period(day.seconds, None) == 300
    assert svc._choose_period(3600, None) == 60
    with pytest.raises(InputError, match="multiple of 60"):
        svc._choose_period(3600, 45)
    with pytest.raises(InputError, match="more than"):
        svc._choose_period(30 * 86400, 60)


def test_get_metrics_validation(cw_stub, cfg):
    svc = MetricsService(cw_stub[0], make_config(max_metric_queries=2))
    with pytest.raises(InputError, match="Unsupported stat"):
        svc.get_metrics([{**Q, "stat": "Average; DROP"}], TR)
    with pytest.raises(InputError, match="At most 2"):
        svc.get_metrics([Q, Q, Q], TR)
    with pytest.raises(InputError):
        svc.get_metrics([], TR)
    with pytest.raises(InputError, match="Invalid namespace"):
        svc.get_metrics([{"namespace": "", "metric_name": "x"}], TR)
    with pytest.raises(InputError):
        svc.get_metrics(["not-a-dict"], TR)


def test_get_metrics_percentile_stat_accepted(cw_stub, cfg):
    client, stub = cw_stub
    stub.add_response("get_metric_data", {"MetricDataResults": [
        {"Id": "m0", "Label": "l", "Timestamps": [NOW], "Values": [1.0]}]})
    assert MetricsService(client, cfg).get_metrics([{**Q, "stat": "p99"}], TR).status == "ok"


# ------------------------------------------------------------------ alarms
def _alarm(name, state, **kw):
    return {"AlarmName": name, "StateValue": state, "StateReason": kw.get("reason", "r password=abc"),
            "StateUpdatedTimestamp": NOW, "Namespace": "AWS/ApplicationELB",
            "MetricName": "HTTPCode_Target_5XX_Count", "Threshold": 10.0, "Period": 60,
            "EvaluationPeriods": 3, "ComparisonOperator": "GreaterThanThreshold",
            "Statistic": "Sum", "ActionsEnabled": True,
            "AlarmActions": ["arn:aws:sns:us-east-1:123456789012:topic"]}


def test_get_alarms_counts_sanitizes_and_hides_actions(cw_stub, cfg):
    client, stub = cw_stub
    stub.add_response("describe_alarms", {
        "MetricAlarms": [_alarm("a1", "ALARM"), _alarm("a2", "OK"), _alarm("a3", "INSUFFICIENT_DATA")],
        "CompositeAlarms": [{"AlarmName": "c1", "StateValue": "OK", "AlarmRule": "ALARM(a1)",
                             "StateUpdatedTimestamp": NOW, "ActionsEnabled": False}]})
    res = AlarmsService(client, cfg).get_alarms()
    assert res.facts["state_counts"] == {"ALARM": 1, "OK": 2, "INSUFFICIENT_DATA": 1}
    text = res.to_json()
    assert "abc" not in text and "arn:aws:sns" not in text
    assert any("INSUFFICIENT_DATA" in a and "not proof" in a for a in res.analysis)


def test_get_alarms_pagination_and_empty(cw_stub, cfg):
    client, stub = cw_stub
    stub.add_response("describe_alarms", {"MetricAlarms": [_alarm("a1", "OK")], "NextToken": "n"})
    stub.add_response("describe_alarms", {"MetricAlarms": [_alarm("a2", "OK")]})
    assert len(AlarmsService(client, cfg).get_alarms().facts["alarms"]) == 2
    stub.add_response("describe_alarms", {"MetricAlarms": []})
    res = AlarmsService(client, cfg).get_alarms(state="alarm")
    assert res.status == "empty" and "No CloudWatch alarms" in res.summary


def test_get_alarms_invalid_state(cw_stub, cfg):
    with pytest.raises(InputError):
        AlarmsService(cw_stub[0], cfg).get_alarms(state="BROKEN")


def _hist(state, minute):
    import json
    return {"AlarmName": "a1", "Timestamp": NOW - timedelta(minutes=minute),
            "HistoryItemType": "StateUpdate", "HistorySummary": f"Alarm updated to {state}",
            "HistoryData": json.dumps({"newState": {"stateValue": state}})}


def test_alarm_history_flapping_analysis(cw_stub, cfg):
    client, stub = cw_stub
    items = [_hist("ALARM" if i % 2 == 0 else "OK", i) for i in range(12)]
    items.append({"AlarmName": "a1", "Timestamp": NOW, "HistoryItemType": "StateUpdate",
                  "HistorySummary": "bad", "HistoryData": "{not json"})
    stub.add_response("describe_alarm_history", {"AlarmHistoryItems": items})
    res = AlarmsService(client, cfg).get_history("a1", TR)
    assert res.facts["transitions_to_alarm"] == 6
    assert any("flapping" in a for a in res.analysis)


def test_alarm_history_empty_and_bad_type(cw_stub, cfg):
    client, stub = cw_stub
    stub.add_response("describe_alarm_history", {"AlarmHistoryItems": []})
    assert AlarmsService(client, cfg).get_history("a1", TR).status == "empty"
    with pytest.raises(InputError):
        AlarmsService(client, cfg).get_history("a1", TR, history_type="Nope")
