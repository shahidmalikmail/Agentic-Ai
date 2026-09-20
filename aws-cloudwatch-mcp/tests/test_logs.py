import pytest

from aws_cw_mcp.aws.logs import LogsService
from aws_cw_mcp.utils.errors import InputError
from conftest import TR, make_config


def _groups(*names):
    return {"logGroups": [{"logGroupName": n, "creationTime": 1_700_000_000_000, "storedBytes": 10,
                           **({"retentionInDays": 30} if not n.endswith("noret") else {})}
                          for n in names]}


def _ev(ts, msg, stream="s1"):
    return {"timestamp": ts, "message": msg, "logStreamName": stream, "eventId": "1"}


def _gev(ts, msg):  # GetLogEvents events carry no stream/id fields
    return {"timestamp": ts, "message": msg}


# --------------------------------------------------------------- discovery
def test_discover_paginates_filters_and_caches(logs_stub, cfg):
    client, stub = logs_stub
    stub.add_response("describe_log_groups", {**_groups("/aws/eks/c1/cluster", "/app/ts-app"), "nextToken": "t"})
    stub.add_response("describe_log_groups", _groups("/aws/waf/x-noret", "/hcl/commerce/prod"))
    svc = LogsService(client, cfg)
    res = svc.discover(category="hcl_commerce")
    names = [g["name"] for g in res.facts["log_groups"]]
    assert names == ["/app/ts-app", "/hcl/commerce/prod"]
    assert res.status == "ok" and res.meta["scanned_groups"] == 4
    assert any("NAMES only" in a for a in res.analysis)
    # second call served from cache: Stubber would raise on an unexpected API call
    res2 = svc.discover(keyword="waf")
    assert [g["name"] for g in res2.facts["log_groups"]] == ["/aws/waf/x-noret"]
    assert any("no retention" in a for a in res2.analysis)


def test_discover_respects_allowlist(logs_stub):
    client, stub = logs_stub
    stub.add_response("describe_log_groups", _groups("/aws/eks/a", "/aws/waf/b", "/other/c"))
    svc = LogsService(client, make_config(log_group_allowlist=("/aws/eks/*", "/aws/waf/*")))
    names = [g["name"] for g in svc.discover().facts["log_groups"]]
    assert names == ["/aws/eks/a", "/aws/waf/b"]


def test_discover_empty_is_honest(logs_stub, cfg):
    client, stub = logs_stub
    stub.add_response("describe_log_groups", {"logGroups": []})
    res = LogsService(client, cfg).discover(keyword="nothing")
    assert res.status == "empty" and "No CloudWatch log groups matched" in res.summary
    assert res.facts == {"log_groups": []}


def test_discover_page_cap_reports_truncation(logs_stub):
    client, stub = logs_stub
    for _ in range(2):
        stub.add_response("describe_log_groups", {**_groups("/a"), "nextToken": "more"})
    res = LogsService(client, make_config(max_pages=2)).discover()
    assert res.status == "partial" and any("more log groups" in w for w in res.warnings)


def test_discover_unknown_category(logs_stub, cfg):
    with pytest.raises(InputError, match="Unknown category"):
        LogsService(logs_stub[0], cfg).discover(category="nope")


# ------------------------------------------------------------------ search
def test_search_sanitizes_sorts_and_reports(logs_stub, cfg):
    client, stub = logs_stub
    stub.add_response("filter_log_events", {"events": [
        _ev(1_700_000_002_000, "ERROR db password=hunter2 timeout"),
        _ev(1_700_000_001_000, "ERROR connection refused")]},
        expected_params={"logGroupName": "/app/ts-app", "startTime": TR.start_ms, "endTime": TR.end_ms,
                         "limit": 200, "filterPattern": "ERROR"})
    res = LogsService(client, cfg).search(["/app/ts-app"], TR, filter_pattern="ERROR")
    msgs = [e["message"] for e in res.facts["events"]]
    assert msgs[0] == "ERROR connection refused" and "hunter2" not in msgs[1]
    assert res.status == "ok" and "_ts" not in res.facts["events"][0]


def test_search_follows_pagination_until_limit(logs_stub):
    client, stub = logs_stub
    stub.add_response("filter_log_events", {"events": [_ev(1, "a"), _ev(2, "b")], "nextToken": "n1"})
    stub.add_response("filter_log_events", {"events": [_ev(3, "c"), _ev(4, "d")], "nextToken": "n2"})
    res = LogsService(client, make_config(max_log_results=3)).search(["/g"], TR)
    assert [e["message"] for e in res.facts["events"]] == ["a", "b", "c"]
    assert res.status == "partial" and any("sample" in w for w in res.warnings)


def test_search_empty_pages_do_not_loop_forever(logs_stub):
    client, stub = logs_stub
    for _ in range(3):
        stub.add_response("filter_log_events", {"events": [], "nextToken": "n"})
    res = LogsService(client, make_config(max_pages=3)).search(["/g"], TR)
    assert res.status == "empty" and "No log events matched" in res.summary
    assert res.meta["per_group"]["/g"]["more_available"] is True


def test_search_partial_failure_keeps_other_groups(logs_stub, cfg):
    client, stub = logs_stub
    stub.add_client_error("filter_log_events", "AccessDeniedException", "not authorized")
    stub.add_response("filter_log_events", {"events": [_ev(1, "ok line")]})
    res = LogsService(client, cfg).search(["/denied", "/fine"], TR)
    assert res.status == "partial" and len(res.facts["events"]) == 1
    assert res.meta["per_group"]["/denied"]["error"]["kind"] == "access_denied"


def test_search_all_groups_fail_raises(logs_stub, cfg):
    from botocore.exceptions import ClientError
    client, stub = logs_stub
    stub.add_client_error("filter_log_events", "ResourceNotFoundException")
    with pytest.raises(ClientError):
        LogsService(client, cfg).search(["/missing"], TR)


def test_search_malformed_messages(logs_stub, cfg):
    client, stub = logs_stub
    stub.add_response("filter_log_events", {"events": [
        {"timestamp": 5, "message": " "}, {"timestamp": 4}, {"timestamp": 6, "message": "\x00\x01 binary �"},
        {"timestamp": 7, "message": "x" * 5000}, {"timestamp": 8, "message": "{not json"}]})
    res = LogsService(client, cfg).search(["/g"], TR)
    assert len(res.facts["events"]) == 5
    assert len(res.facts["events"][3]["message"]) < 900


def test_search_response_budget(logs_stub):
    client, stub = logs_stub
    stub.add_response("filter_log_events", {"events": [_ev(i, "y" * 500) for i in range(1, 11)]})
    res = LogsService(client, make_config(max_response_chars=2000)).search(["/g"], TR)
    assert len(res.facts["events"]) < 10 and any("budget" in w for w in res.warnings)


def test_search_validation(logs_stub):
    client, _ = logs_stub
    svc = LogsService(client, make_config(log_group_allowlist=("/aws/*",), max_log_groups_per_query=2))
    with pytest.raises(InputError, match="outside LOG_GROUP_ALLOWLIST"):
        svc.search(["/other/x"], TR)
    with pytest.raises(InputError, match="At most 2"):
        svc.search(["/aws/a", "/aws/b", "/aws/c"], TR)
    with pytest.raises(InputError, match="Invalid log group"):
        svc.search(["/aws/a; drop"], TR)
    with pytest.raises(InputError):
        svc.search([], TR)
    with pytest.raises(InputError, match="filter_pattern"):
        svc.search(["/aws/a"], TR, filter_pattern="x" * 2000)


def test_search_limit_clamped_to_config(logs_stub):
    client, stub = logs_stub
    stub.add_response("filter_log_events", {"events": []},
                      expected_params={"logGroupName": "/g", "startTime": TR.start_ms,
                                       "endTime": TR.end_ms, "limit": 10})
    LogsService(client, make_config(max_log_results=10)).search(["/g"], TR, limit=99999)


# ----------------------------------------------------------- streams/events
def test_list_streams(logs_stub, cfg):
    client, stub = logs_stub
    stub.add_response("describe_log_streams", {"logStreams": [
        {"logStreamName": "pod-1", "lastEventTimestamp": 1_700_000_000_000}]},
        expected_params={"logGroupName": "/g", "limit": 25, "orderBy": "LastEventTime", "descending": True})
    res = LogsService(client, cfg).list_streams("/g")
    assert res.facts["streams"][0]["name"] == "pod-1"


def test_list_streams_empty(logs_stub, cfg):
    client, stub = logs_stub
    stub.add_response("describe_log_streams", {"logStreams": []})
    assert LogsService(client, cfg).list_streams("/g").status == "empty"


def test_get_events_pages_backward_and_stops_on_repeated_token(logs_stub, cfg):
    client, stub = logs_stub
    stub.add_response("get_log_events", {"events": [_gev(3, "c"), _gev(4, "d")], "nextBackwardToken": "b1"})
    stub.add_response("get_log_events", {"events": [_gev(1, "a"), _gev(2, "b")], "nextBackwardToken": "b1"})
    res = LogsService(client, cfg).get_events("/g", "s", TR)
    assert [e["message"] for e in res.facts["events"]] == ["a", "b", "c", "d"]
    assert res.status == "ok"


def test_get_events_empty_and_bad_stream(logs_stub, cfg):
    client, stub = logs_stub
    stub.add_response("get_log_events", {"events": []})
    assert LogsService(client, cfg).get_events("/g", "s", TR).status == "empty"
    with pytest.raises(InputError):
        LogsService(client, cfg).get_events("/g", "bad:stream*", TR)
