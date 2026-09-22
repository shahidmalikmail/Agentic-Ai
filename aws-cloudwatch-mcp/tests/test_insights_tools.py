"""The seven Insights MCP tools end-to-end (through the real gate/executor over Stubber), registration and safety."""
import asyncio
import inspect
import json
from datetime import datetime, timedelta, timezone

import pytest

from aws_cw_mcp.runtime import Runtime
from aws_cw_mcp.server import INSIGHTS_TOOL_NAMES, build_instructions, build_tools, create_server
from aws_cw_mcp.utils.errors import IdentityConflict, InsightsDisabled
from conftest import ACCOUNT, GROUP, FakeClients, Harness, make_config, make_insights_config, parse

PHASE1_TOOLS = {"aws_health_check", "aws_discover_log_groups", "aws_search_logs", "aws_list_log_streams",
                "aws_get_log_events", "aws_list_metrics", "aws_get_metrics", "aws_get_alarms",
                "aws_get_alarm_history"}


def _bin_rows():
    """Bins inside the plan's window (tools use the real clock: last hour, floored to the minute)."""
    end = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    fmt = "%Y-%m-%d %H:%M:%S.000"
    return [{"bin(1m)": (end - timedelta(minutes=20)).strftime(fmt), "matches": 3},
            {"bin(1m)": (end - timedelta(minutes=10)).strftime(fmt), "matches": 12}]


def tools_for(h):
    rt = Runtime(h.cfg, FakeClients(), insights_clients=h.clients, insights_executor=h.executor)
    return build_tools(rt), rt


# ------------------------------------------------------------------ enabled / disabled
def test_insights_is_disabled_by_default_and_phase1_tool_set_is_unchanged():
    cfg = make_config()
    rt = Runtime(cfg, FakeClients())
    assert set(build_tools(rt)) == PHASE1_TOOLS
    with pytest.raises(InsightsDisabled):
        rt.insights
    with pytest.raises(InsightsDisabled):
        rt.insights_clients
    assert "insights" not in parse(build_tools(rt)["aws_health_check"]())["FACT"]      # Phase 1 output identical
    assert "UNTRUSTED" not in build_instructions(cfg)


def test_enabled_adds_exactly_the_seven_approved_tools():
    h = Harness()
    tools, _ = tools_for(h)
    assert set(tools) == PHASE1_TOOLS | INSIGHTS_TOOL_NAMES
    assert INSIGHTS_TOOL_NAMES == {"aws_insights_estimate_scan", "aws_insights_count_over_time", "aws_insights_count_by",
                                   "aws_insights_sample_events", "aws_insights_get_results",
                                   "aws_insights_cancel_query", "aws_insights_budget_status"}
    assert "UNTRUSTED" in build_instructions(h.cfg)


def test_mcp_registration_lists_sixteen_tools_with_correct_annotations():
    h = Harness()
    _, rt = tools_for(h)
    mcp = create_server(h.cfg, rt)
    listed = asyncio.run(mcp.list_tools())
    listed = listed.tools if hasattr(listed, "tools") else listed
    assert {t.name for t in listed} == PHASE1_TOOLS | INSIGHTS_TOOL_NAMES
    for t in listed:
        a = t.annotations
        ro = getattr(a, "read_only_hint", getattr(a, "readOnlyHint", None))
        destructive = getattr(a, "destructive_hint", getattr(a, "destructiveHint", None))
        idem = getattr(a, "idempotent_hint", getattr(a, "idempotentHint", None))
        assert ro is True and destructive is False
        assert idem is (t.name not in INSIGHTS_TOOL_NAMES)             # queries are billed: not idempotent


FORBIDDEN_PARAMS = {"query", "query_string", "querystring", "expression", "regex", "pattern", "filter", "fields",
                    "command", "action", "api", "operation", "service", "query_id", "queryid", "function", "sql", "ppl",
                    "language", "profile", "account", "region", "kwargs", "params", "parameters"}


def test_no_insights_tool_accepts_a_query_string_api_name_action_regex_or_raw_query_id():
    h = Harness()
    tools, rt = tools_for(h)
    mcp = create_server(h.cfg, rt)
    listed = asyncio.run(mcp.list_tools())
    listed = listed.tools if hasattr(listed, "tools") else listed
    for t in listed:
        if t.name not in INSIGHTS_TOOL_NAMES:
            continue
        schema = getattr(t, "input_schema", None) or getattr(t, "inputSchema", {})
        names = {n.lower() for n in schema.get("properties", {})}
        assert not (names & FORBIDDEN_PARAMS), (t.name, names & FORBIDDEN_PARAMS)
    handle_tools = {"aws_insights_get_results", "aws_insights_cancel_query"}
    for name in handle_tools:
        assert list(inspect.signature(tools[name]).parameters) == ["query_handle"]


# ------------------------------------------------------------------ tools end-to-end
def test_budget_status_makes_no_aws_call_and_reports_limits():
    h = Harness()
    d = parse(tools_for(h)[0]["aws_insights_budget_status"]())
    assert d["status"] == "ok"
    f = d["FACT"]
    assert f["budget"]["total_bytes"] == 20 * (1 << 30) and f["concurrency"] == {"in_use": 0, "limit": 2}
    assert f["limits"]["max_log_groups"] == 5 and f["limits"]["max_result_rows"] == 200
    assert f["limits"]["wait_seconds"] == 40 and f["limits"]["app_deadline_seconds"] == 180
    assert "errors" in f["limits"]["presets"] and f["running_jobs"] == []
    h.done()


def test_estimate_scan_reports_size_verdict_and_never_starts_the_real_query():
    h = Harness()
    h.estimate_flow(123_456)
    d = parse(tools_for(h)[0]["aws_insights_estimate_scan"](log_groups=[GROUP], preset="errors"))
    assert d["status"] == "ok" and d["FACT"]["estimated_bytes"] == 123_456
    assert d["FACT"]["verdict"]["allowed"] is True and d["FACT"]["query_preview"].endswith("by bin(1m)")
    assert "approximate" in " ".join(d["warnings"])
    h.done()


def test_estimate_scan_over_cap_is_reported_with_a_recommendation_not_an_error():
    h = Harness()
    h.estimate_flow(3 * (1 << 30))
    d = parse(tools_for(h)[0]["aws_insights_estimate_scan"](log_groups=[GROUP], preset="errors"))
    assert d["status"] == "ok" and d["FACT"]["verdict"]["allowed"] is False
    assert "REFUSED" in d["ANALYSIS"][0]
    assert d["RECOMMENDATION"][0].startswith("RECOMMENDATION (human decision required; nothing was executed)")
    h.done()


def test_estimate_scan_notes_when_range_exceeds_retention():
    h = Harness(retention=1)
    h.estimate_flow(10)
    d = parse(tools_for(h)[0]["aws_insights_estimate_scan"](log_groups=[GROUP], preset="errors", lookback="48h"))
    assert any("retains 1 days" in a for a in d["ANALYSIS"])
    assert d["FACT"]["scope"]["extended_range"] is True
    h.done()


def test_count_over_time_full_flow_and_bin_label():
    h = Harness()
    h.run_flow(_bin_rows())
    d = parse(tools_for(h)[0]["aws_insights_count_over_time"](log_groups=[GROUP], preset="errors", lookback="1h", bin="1m"))
    assert d["status"] == "ok" and d["FACT"]["series_stats"]["total"] == 15
    assert d["FACT"]["query"]["match"]["presets"] == ["errors"]
    h.done()


def test_count_by_full_flow_defaults_and_status_codes():
    h = Harness()
    h.run_flow([{"@log": "926266574832:/aws/app/one", "matches": 7}])
    d = parse(tools_for(h)[0]["aws_insights_count_by"](log_groups=[GROUP], preset="errors"))
    assert d["FACT"]["dimension"] == "log_group" and d["FACT"]["ranked"][0]["count"] == 7
    h2 = Harness()
    h2.run_flow([{"status": "503", "matches": 4}, {"status": "404", "matches": 1}])
    d2 = parse(tools_for(h2)[0]["aws_insights_count_by"](log_groups=[GROUP], dimension="status_code",
                                                         status_codes=[503, 404, 502], preset=None))
    assert [r["label"] for r in d2["FACT"]["ranked"]] == ["503", "404"]


def test_sample_events_full_flow():
    h = Harness()
    h.run_flow([{"@timestamp": "2026-09-20 11:00:00.000", "@log": "1:/x", "@message": "connection refused"}])
    d = parse(tools_for(h)[0]["aws_insights_sample_events"](log_groups=[GROUP], contains=["connection refused"], limit=3))
    assert d["FACT"]["untrusted_log_content"] is True and d["FACT"]["events"][0]["@message"] == "connection refused"


def test_running_handle_get_results_and_cancel_through_the_tools():
    h = Harness(make_insights_config(insights_wait_seconds=3))
    tools, _ = tools_for(h)
    h.estimate_flow(1000)
    h.start_ok("q-1")
    for _ in range(12):
        h.results("Running", bytes_scanned=1)
    d = parse(tools["aws_insights_count_over_time"](log_groups=[GROUP], preset="errors"))
    h.read_stub._queue.clear()
    assert d["status"] == "partial" and d["FACT"]["query_handle"].startswith("qh_")
    handle = d["FACT"]["query_handle"]
    assert "q-1" not in json.dumps(d)                                   # AWS queryId never exposed
    h.stop_ok()
    c = parse(tools["aws_insights_cancel_query"](query_handle=handle))
    assert c["status"] == "ok" and c["FACT"]["state"] == "cancelled" and c["FACT"]["reason"] == "user"
    again = parse(tools["aws_insights_get_results"](query_handle=handle))
    assert again["status"] == "empty" and "cancelled" in again["summary"]


def test_get_results_completes_a_pending_query():
    h = Harness(make_insights_config(insights_wait_seconds=3))
    tools, _ = tools_for(h)
    h.estimate_flow(1000)
    h.start_ok("q-1")
    for _ in range(12):
        h.results("Running", bytes_scanned=1)
    handle = parse(tools["aws_insights_count_over_time"](log_groups=[GROUP], preset="errors"))["FACT"]["query_handle"]
    h.read_stub._queue.clear()
    h.results("Complete", bytes_scanned=50)
    h.results("Complete", _bin_rows(), bytes_scanned=50)
    d = parse(tools["aws_insights_get_results"](query_handle=handle))
    assert d["status"] == "ok" and d["FACT"]["series_stats"]["total"] == 15
    h.done()


# ------------------------------------------------------------------ errors are structured, never raised or invented
@pytest.mark.parametrize("call,kwargs,kind", [
    ("aws_insights_count_over_time", {"log_groups": [GROUP], "preset": "nope"}, "query_rejected"),
    ("aws_insights_count_over_time", {"log_groups": [GROUP]}, "query_rejected"),                       # no match criterion
    ("aws_insights_count_over_time", {"log_groups": [GROUP], "preset": "errors", "bin": "2m"}, "query_rejected"),
    ("aws_insights_count_over_time", {"log_groups": [GROUP], "preset": "errors", "lookback": "soon"}, "invalid_input"),
    ("aws_insights_count_over_time", {"log_groups": [GROUP], "preset": "errors", "lookback": "8d"}, "invalid_input"),
    ("aws_insights_count_over_time", {"log_groups": ["/aws/x;drop"], "preset": "errors"}, "query_rejected"),
    ("aws_insights_count_over_time", {"log_groups": [GROUP], "contains": ['x" | join y']}, "query_rejected"),
    ("aws_insights_count_over_time", {"log_groups": [GROUP], "preset": "errors", "status_codes": ["abc"]}, "query_rejected"),
    ("aws_insights_count_by", {"log_groups": [GROUP], "dimension": "secret_field", "preset": "errors"}, "query_rejected"),
    ("aws_insights_count_by", {"log_groups": [GROUP], "dimension": "status_code", "preset": "errors"}, "query_rejected"),
    ("aws_insights_sample_events", {"log_groups": [GROUP], "preset": "errors", "limit": 500}, "query_rejected"),
    ("aws_insights_estimate_scan", {"log_groups": [GROUP], "preset": "errors", "kind": "raw_sql"}, "query_rejected"),
    ("aws_insights_get_results", {"query_handle": "q-1"}, "invalid_input"),
    ("aws_insights_cancel_query", {"query_handle": "qh_unknown"}, "invalid_input"),
    ("aws_insights_count_over_time", {"log_groups": ["/aws/app/missing"], "preset": "errors"}, "not_found"),
])
def test_bad_input_returns_a_structured_error_and_makes_no_aws_call(call, kwargs, kind):
    h = Harness()
    d = parse(tools_for(h)[0][call](**kwargs))
    assert d["status"] == "error" and d["error"]["kind"] == kind and d["FACT"] == {}
    h.done()


def test_error_output_never_echoes_the_unsafe_literal():
    h = Harness()
    secret = 'SuperSecretTerm999" | join x password=hunter2'
    out = tools_for(h)[0]["aws_insights_count_over_time"](log_groups=[GROUP], contains=[secret])
    assert "SuperSecretTerm999" not in out and "hunter2" not in out


def test_access_denied_on_start_is_reported_with_iam_guidance():
    h = Harness()
    h.start_error("AccessDeniedException", "User is not authorized to perform: logs:StartQuery")
    d = parse(tools_for(h)[0]["aws_insights_count_over_time"](log_groups=[GROUP], preset="errors"))
    assert d["error"]["kind"] == "access_denied" and "IAM-REQUIRED-PHASE1" in d["error"]["hint"]
    assert "No CloudWatch data is currently available" in d["summary"]


def test_cost_guard_refusal_is_a_structured_error_with_numbers():
    h = Harness()
    h.estimate_flow(5 * (1 << 30))
    d = parse(tools_for(h)[0]["aws_insights_count_over_time"](log_groups=[GROUP], preset="errors"))
    assert d["error"]["kind"] == "cost_guard" and "per-query cap" in d["error"]["message"]
    assert d["summary"].startswith("The request failed (cost_guard)")


def test_aws_query_failure_is_reported_verbatim():
    h = Harness()
    h.estimate_flow(10)
    h.start_ok("q-1")
    h.results("Failed")
    d = parse(tools_for(h)[0]["aws_insights_count_over_time"](log_groups=[GROUP], preset="errors"))
    assert d["error"]["kind"] == "query_failed" and "Failed" in d["error"]["message"]


# ------------------------------------------------------------------ account / profile separation at the tool layer
def test_health_check_reports_dedicated_insights_identity_without_running_a_query():
    h = Harness()
    d = parse(tools_for(h)[0]["aws_health_check"]())
    ins = d["FACT"]["insights"]
    assert d["status"] == "ok" and ins["enabled"] is True and ins["verified"] is True
    assert ins["profile"] == "ob-aws-cloudwatch-insights" and ins["account"] == ACCOUNT
    assert ins["distinct_from_phase1_identity"] is True and ins["principal_type"] == "iam-user"
    assert sorted(ins["allowed_operations"]) == ["GetQueryResults", "StartQuery", "StopQuery"]
    assert d["FACT"]["profile"] == "ob-aws-cloudwatch" and d["FACT"]["pinned_account"] == ACCOUNT   # Phase 1 facts intact
    h.done()


def test_health_check_survives_an_insights_identity_problem_and_reports_it():
    h = Harness()

    class Broken:
        approved, owned = h.approved, h.owned

        def verify(self):
            raise IdentityConflict("The Insights profile resolves to the SAME principal as the Phase 1 profile.")

    rt = Runtime(h.cfg, FakeClients(), insights_clients=Broken(), insights_executor=h.executor)
    d = parse(build_tools(rt)["aws_health_check"]())
    assert d["status"] == "ok" and d["FACT"]["aws_account"]                      # Phase 1 health still reported
    assert d["FACT"]["insights"]["verified"] is False and d["FACT"]["insights"]["error"]["kind"] == "identity_conflict"


def test_insights_tools_fail_cleanly_when_disabled_at_runtime():
    rt = Runtime(make_config(), FakeClients())
    tools = {n: f for n, f in __import__("aws_cw_mcp.tools.insights_tools", fromlist=["x"]).build_tools(rt).items()}
    d = parse(tools["aws_insights_budget_status"]())
    assert d["status"] == "error" and d["error"]["kind"] == "insights_disabled"


# ------------------------------------------------------------------ laziness: status is local, catalog uses Phase 1
def test_budget_status_builds_the_real_executor_without_any_aws_client_or_call(monkeypatch):
    """A real Runtime (no injected executor): status must not create ANY boto client or touch AWS."""
    import boto3
    from aws_cw_mcp.aws.client import AwsClients

    def forbidden(*a, **k):
        raise AssertionError("an AWS client was created for a local-only status call")

    monkeypatch.setattr(AwsClients, "client", forbidden)
    monkeypatch.setattr(boto3.session.Session, "client", forbidden)
    cfg = make_insights_config()
    rt = Runtime(cfg, AwsClients(cfg, session=boto3.session.Session(aws_access_key_id="t", aws_secret_access_key="t",
                                                                    region_name="us-east-1")))
    d = parse(build_tools(rt)["aws_insights_budget_status"]())
    assert d["status"] == "ok" and d["FACT"]["budget"]["used_bytes"] == 0
    rt._insights.shutdown()


def test_logs_group_catalog_is_lazy_and_reports_retention_and_missing_groups():
    from aws_cw_mcp.insights.scope import LogsGroupCatalog
    from aws_cw_mcp.utils.errors import NotFoundError

    calls = {"provider": 0}

    class FakeLogs:
        def list_group_records(self, prefix):
            return [{"name": "/aws/app/one", "retention_days": 30}, {"name": "/aws/app/one2", "retention_days": None}]

    def provider():
        calls["provider"] += 1
        return FakeLogs()

    cat = LogsGroupCatalog(provider)
    assert calls["provider"] == 0                                   # nothing created at construction
    assert cat.check(["/aws/app/one", "/aws/app/one2"]) == {"/aws/app/one": 30, "/aws/app/one2": None}
    with pytest.raises(NotFoundError, match="not found"):
        cat.check(["/aws/app/missing"])                             # a prefix match alone is not existence
