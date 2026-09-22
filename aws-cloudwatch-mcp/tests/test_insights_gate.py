"""The boto-level gate and the dedicated Insights identity, using REAL botocore clients (fake creds, no network).

Blocked calls must raise BEFORE any request is signed or sent (the network-block fixture enforces that).
"""
import json

import boto3
import pytest
from botocore.exceptions import ClientError, ProfileNotFound
from botocore.stub import Stubber

from aws_cw_mcp.aws.client import AwsClients, assert_read_only
from aws_cw_mcp.aws.insights_client import (INSIGHTS_OPERATIONS, InsightsApi, InsightsClients, InsightsGate,
                                            attach_gate)
from aws_cw_mcp.config import ConfigError
from aws_cw_mcp.insights.plans import request_fingerprint
from aws_cw_mcp.insights.registry import ApprovedQueryRegistry, OwnedQueryRegistry
from aws_cw_mcp.utils.errors import AccountMismatch, IdentityConflict, ReadOnlyViolation
from conftest import ACCOUNT, FakeClock, make_client, make_config, make_insights_config

GROUP = "/aws/app/one"
Q = 'filter (@message like "x") | limit 5'
INSIGHTS_ARN = f"arn:aws:iam::{ACCOUNT}:user/cloud-watch-insights-review"
PHASE1_ARN = f"arn:aws:iam::{ACCOUNT}:user/cloud-watch-log-review"
START = dict(queryString=Q, logGroupNames=[GROUP], startTime=100, endTime=200, limit=5, queryLanguage="CWLI")


@pytest.fixture
def gated():
    clock = FakeClock()
    approved, owned = ApprovedQueryRegistry(60, clock.now), OwnedQueryRegistry()
    gate = InsightsGate(approved, owned)
    client = make_client("logs")
    attach_gate(client, gate)
    return client, gate, approved, owned, clock


def fp(**over):
    p = {**START, **over}
    return request_fingerprint(p["queryString"], p["logGroupNames"], p["startTime"], p["endTime"], p["limit"])


# ----------------------------------------------------------- Phase 1 / other operations are refused
@pytest.mark.parametrize("call,kwargs", [
    ("describe_log_groups", {}), ("describe_log_streams", {"logGroupName": "x"}),
    ("filter_log_events", {"logGroupName": "x"}), ("get_log_events", {"logGroupName": "x", "logStreamName": "s"}),
    ("delete_log_group", {"logGroupName": "x"}), ("create_log_group", {"logGroupName": "x"}),
    ("put_retention_policy", {"logGroupName": "x", "retentionInDays": 1}),
    ("describe_queries", {}), ("get_log_record", {"logRecordPointer": "p"}),
    ("get_log_group_fields", {"logGroupName": "x"}), ("put_query_definition", {"name": "n", "queryString": "q"}),
])
def test_insights_client_refuses_every_other_operation(gated, call, kwargs):
    client, *_ = gated
    with pytest.raises(ReadOnlyViolation, match="only permits"):
        getattr(client, call)(**kwargs)


def test_only_three_operations_are_insights_operations():
    assert INSIGHTS_OPERATIONS == {"StartQuery", "GetQueryResults", "StopQuery"}


# ----------------------------------------------------------- StartQuery approval
def test_unapproved_start_is_blocked_before_network(gated):
    client, *_ = gated
    with pytest.raises(ReadOnlyViolation, match="not approved"):
        client.start_query(**START)


@pytest.mark.parametrize("change", [{"queryString": Q + " "}, {"logGroupNames": ["/aws/app/two"]},
                                    {"startTime": 101}, {"endTime": 201}, {"limit": 6}])
def test_any_change_after_approval_is_blocked(gated, change):
    client, gate, approved, *_ = gated
    approved.approve(fp())
    with pytest.raises(ReadOnlyViolation, match="not approved"):
        client.start_query(**{**START, **change})


@pytest.mark.parametrize("params,match", [
    ({**START, "queryLanguage": "SQL"}, "CWLI"),
    ({**START, "queryLanguage": "PPL"}, "CWLI"),
    ({k: v for k, v in START.items() if k != "limit"}, "explicit limit"),      # a real query needs its limit
    ({k: v for k, v in START.items() if k != "queryLanguage"}, "unexpected or missing"),
    ({**START, "logGroupIdentifiers": ["arn:aws:logs:us-east-1:1:log-group:x"]}, "unexpected or missing"),
    ({**{k: v for k, v in START.items() if k != "logGroupNames"}, "logGroupName": GROUP}, "unexpected or missing"),
])
def test_startquery_parameter_shape_is_strict(gated, params, match):
    client, gate, approved, *_ = gated
    approved.approve(fp())
    with pytest.raises(ReadOnlyViolation, match=match):
        client.start_query(**params)


def test_source_command_smuggled_into_an_approved_shape_still_needs_its_own_approval(gated):
    client, gate, approved, *_ = gated
    approved.approve(fp())
    smuggled = 'source logGroups(namePrefix: ["/"]) | limit 5'
    with pytest.raises(ReadOnlyViolation, match="not approved"):
        client.start_query(**{**START, "queryString": smuggled})


def test_approved_request_passes_the_gate_once_then_replay_is_blocked(gated):
    client, gate, approved, owned, _ = gated
    approved.approve(fp())
    with Stubber(client) as stub:
        stub.add_response("start_query", {"queryId": "q-1"})
        stub.add_response("start_query", {"queryId": "would-be-duplicate"})   # ready, but must never be used
        assert client.start_query(**START)["queryId"] == "q-1"
        with pytest.raises(ReadOnlyViolation, match="not approved"):
            client.start_query(**START)                        # approval was consumed at before-call
        assert len(stub._queue) == 1                           # the duplicate response was not consumed
    assert len(approved) == 0


def test_approval_expires_after_ttl(gated):
    client, gate, approved, owned, clock = gated
    approved.approve(fp())
    clock.advance(61)
    with pytest.raises(ReadOnlyViolation, match="not approved"):
        client.start_query(**START)


class _Model:
    def __init__(self, name):
        self.name = name


def test_before_call_detects_a_body_that_differs_from_the_approved_request():
    approved, owned = ApprovedQueryRegistry(), OwnedQueryRegistry()
    gate = InsightsGate(approved, owned)
    approved.approve(fp())
    ctx = {"insights_fingerprint": fp()}
    tampered = json.dumps({**START, "queryString": 'source x | limit 5'})
    with pytest.raises(ReadOnlyViolation, match="differs"):
        gate.before_call(model=_Model("StartQuery"), params={"body": tampered}, context=ctx)
    assert approved.is_approved(fp())                          # a blocked send does not burn the approval


def test_before_call_rejects_missing_context_bad_body_and_wrong_language():
    approved = ApprovedQueryRegistry()
    gate = InsightsGate(approved, OwnedQueryRegistry())
    approved.approve(fp())
    ok_body = json.dumps(START)
    with pytest.raises(ReadOnlyViolation, match="missing approval context"):
        gate.before_call(model=_Model("StartQuery"), params={"body": ok_body}, context={})
    for body in ("not json", None, "{}", json.dumps({"queryString": Q})):
        with pytest.raises(ReadOnlyViolation, match="could not be verified"):
            gate.before_call(model=_Model("StartQuery"), params={"body": body}, context={"insights_fingerprint": fp()})
    with pytest.raises(ReadOnlyViolation, match="differs"):
        gate.before_call(model=_Model("StartQuery"), params={"body": json.dumps({**START, "queryLanguage": "SQL"})},
                         context={"insights_fingerprint": fp()})
    gate.before_call(model=_Model("StartQuery"), params={"body": ok_body.encode()},   # bytes body accepted
                     context={"insights_fingerprint": fp()})
    assert not approved.is_approved(fp())                      # consumed exactly once


def test_before_call_refuses_other_operations():
    gate = InsightsGate(ApprovedQueryRegistry(), OwnedQueryRegistry())
    with pytest.raises(ReadOnlyViolation):
        gate.before_call(model=_Model("DescribeLogGroups"), params={}, context={})


# ----------------------------------------------------------- owned queries only
def test_unowned_query_ids_cannot_be_polled_or_stopped(gated):
    client, *_ = gated
    with pytest.raises(ReadOnlyViolation, match="not started by this server"):
        client.get_query_results(queryId="someone-elses-query")
    with pytest.raises(ReadOnlyViolation, match="not started by this server"):
        client.stop_query(queryId="someone-elses-query")


def test_owned_query_ids_pass_and_unexpected_parameters_do_not(gated):
    client, gate, approved, owned, _ = gated
    owned.add("q-1")
    with Stubber(client) as stub:
        stub.add_response("get_query_results", {"status": "Running", "results": []})
        stub.add_response("stop_query", {"success": True})
        assert client.get_query_results(queryId="q-1", maxItems=5)["status"] == "Running"
        assert client.stop_query(queryId="q-1")["success"] is True
    with pytest.raises(ReadOnlyViolation, match="unexpected request parameters"):
        client.stop_query(queryId="q-1", extra="x")
    with pytest.raises(ReadOnlyViolation, match="unexpected request parameters"):
        client.get_query_results(queryId="q-1", other=1)


def test_api_wrapper_records_and_forgets_owned_ids():
    approved, owned = ApprovedQueryRegistry(), OwnedQueryRegistry()
    gate = InsightsGate(approved, owned)
    start, read = make_client("logs"), make_client("logs")
    for c in (start, read):
        attach_gate(c, gate)

    class Clients:
        def __init__(self):
            self.approved, self.owned = approved, owned

        def begin_client(self):
            return start

        def read_client(self):
            return read

    api = InsightsApi(Clients())
    approved.approve(fp())
    with Stubber(start) as s:
        s.add_response("start_query", {"queryId": "q-9"})
        assert api.begin_query(query=Q, group_names=[GROUP], start_s=100, end_s=200, limit=5) == "q-9"
    assert owned.contains("q-9")
    api.forget("q-9")
    assert not owned.contains("q-9")


# ----------------------------------------------------------- Phase 1 client cannot run Insights operations
@pytest.mark.parametrize("op", ["StartQuery", "GetQueryResults", "StopQuery"])
def test_insights_operations_are_not_on_the_phase1_allow_list(op):
    with pytest.raises(ReadOnlyViolation):
        assert_read_only(op)


def test_real_phase1_client_refuses_insights_calls(monkeypatch):
    session = boto3.session.Session(aws_access_key_id="testing", aws_secret_access_key="testing",
                                    region_name="us-east-1")
    monkeypatch.setattr(AwsClients, "identity", lambda self: {"account": ACCOUNT, "arn": PHASE1_ARN})
    logs = AwsClients(make_config(aws_account_id=ACCOUNT), session=session).logs()
    with pytest.raises(ReadOnlyViolation):
        logs.start_query(**START)
    with pytest.raises(ReadOnlyViolation):
        logs.get_query_results(queryId="q")
    with pytest.raises(ReadOnlyViolation):
        logs.stop_query(queryId="q")


# ----------------------------------------------------------- dedicated identity, account pin, separation
def _session(profile_creds=None):
    return boto3.session.Session(aws_access_key_id="testing", aws_secret_access_key="testing", region_name="us-east-1")


def _clients(cfg=None, phase1=PHASE1_ARN):
    cfg = cfg or make_insights_config()
    return InsightsClients(cfg, lambda: {"account": ACCOUNT, "arn": phase1}, session=_session())


def _sts(clients, account=ACCOUNT, arn=INSIGHTS_ARN):
    stub = Stubber(clients._sts())
    stub.add_response("get_caller_identity", {"Account": account, "Arn": arn, "UserId": "AIDAEXAMPLE"})
    return stub


def test_correct_account_and_distinct_principal_is_accepted():
    c = _clients()
    with _sts(c):
        ident = c.verify()
        assert ident == {"account": ACCOUNT, "arn": INSIGHTS_ARN}
        assert c.verify() is ident or c.verify() == ident      # cached: no second STS call needed


def test_wrong_account_is_rejected_and_stays_rejected_without_new_sts_calls():
    c = _clients()
    with _sts(c, account="111122223333"):
        with pytest.raises(AccountMismatch, match="Refusing to query"):
            c.verify()
        with pytest.raises(AccountMismatch):
            c.begin_client()
        with pytest.raises(AccountMismatch):
            c.read_client()


def test_same_principal_as_phase1_is_an_identity_conflict():
    c = _clients(phase1=INSIGHTS_ARN)
    with _sts(c):
        with pytest.raises(IdentityConflict, match="SAME principal"):
            c.verify()


def test_expected_arn_pin():
    ok = _clients(make_insights_config(insights_expected_arn=INSIGHTS_ARN))
    with _sts(ok):
        assert ok.verify()["arn"] == INSIGHTS_ARN
    bad = _clients(make_insights_config(insights_expected_arn=f"arn:aws:iam::{ACCOUNT}:user/someone-else"))
    with _sts(bad):
        with pytest.raises(IdentityConflict, match="EXPECTED_ARN"):
            bad.verify()


def test_missing_account_pin_refuses():
    c = _clients(make_insights_config(aws_account_id=None))
    with pytest.raises(ConfigError, match="AWS_ACCOUNT_ID"):
        c.verify()


def test_insights_sts_client_cannot_call_anything_but_get_caller_identity():
    c = _clients()
    with pytest.raises(ReadOnlyViolation):
        c._sts().get_session_token()
    with pytest.raises(ReadOnlyViolation):
        c._sts().assume_role(RoleArn=f"arn:aws:iam::{ACCOUNT}:role/x", RoleSessionName="sess")


def test_start_client_has_no_retries_and_read_client_may_retry():
    c = _clients()
    with _sts(c):
        start, read = c.begin_client(), c.read_client()
    assert start is not read
    # botocore normalises max_attempts (retries) into total_max_attempts (= retries + 1)
    assert start.meta.config.retries["total_max_attempts"] == 1          # StartQuery: exactly one attempt, ever
    assert read.meta.config.retries["total_max_attempts"] == 4           # idempotent reads: 3 retries
    for client in (start, read):
        with pytest.raises(ReadOnlyViolation):
            client.describe_log_groups()                        # gated in both directions


def test_gated_clients_share_the_approval_and_ownership_registries():
    c = _clients()
    with _sts(c):
        start = c.begin_client()
    c.approved.approve(fp())
    with Stubber(start) as stub:
        stub.add_response("start_query", {"queryId": "q-77"})
        start.start_query(**START)
    api = InsightsApi(c)
    c.owned.add("q-77")
    assert c.owned.contains("q-77") and api.approved is c.approved


def test_dedicated_profile_is_used_and_is_separate_from_phase1(tmp_path, monkeypatch):
    creds = tmp_path / "credentials"
    creds.write_text("[ob-aws-cloudwatch]\naws_access_key_id = AKIAPHASE1FAKEFAKE12\naws_secret_access_key = fake1\n"
                     "[ob-aws-cloudwatch-insights]\naws_access_key_id = AKIAINSIGHTSFAKE123\n"
                     "aws_secret_access_key = fake2\n")
    conf = tmp_path / "config"
    conf.write_text("[profile ob-aws-cloudwatch]\nregion = us-east-1\n"
                    "[profile ob-aws-cloudwatch-insights]\nregion = us-east-1\n")
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(conf))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    cfg = make_insights_config()
    p1 = AwsClients(cfg)._get_session()
    ins = InsightsClients(cfg, lambda: {})._get_session()
    assert p1.profile_name == "ob-aws-cloudwatch" and ins.profile_name == "ob-aws-cloudwatch-insights"
    assert p1.get_credentials().access_key != ins.get_credentials().access_key


def test_missing_insights_profile_and_unknown_profile(tmp_path, monkeypatch):
    with pytest.raises(ConfigError, match="AWS_INSIGHTS_PROFILE"):
        InsightsClients(make_insights_config(insights_profile=None), lambda: {})._get_session()
    (tmp_path / "credentials").write_text("")
    (tmp_path / "config").write_text("")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    with pytest.raises(ProfileNotFound):
        InsightsClients(make_insights_config(insights_profile="does-not-exist"), lambda: {})._get_session()
