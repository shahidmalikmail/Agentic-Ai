"""Phase 1 stays in AWS_REGION (us-east-1). AWS_INSIGHTS_REGION is a separate setting: the validated PROD
configuration uses us-east-1 (where the PROD log groups are); a DIFFERENT region (ap-southeast-1 is used below only as an
example, via OTHER_REGION) must remain supported. Same account (926266574832), distinct identities. No AWS access."""
import json

import boto3
import pytest
from botocore.stub import Stubber

from aws_cw_mcp.aws.client import AwsClients
from aws_cw_mcp.aws.insights_client import InsightsClients
from aws_cw_mcp.config import ConfigError, load_config
from aws_cw_mcp.runtime import Runtime
from aws_cw_mcp.server import build_tools
from aws_cw_mcp.utils.errors import AccountMismatch
from conftest import ACCOUNT, GROUP, FakeClients, Harness, make_client, make_config, make_insights_config, parse, plan_for

BASE = {"AWS_REGION": "us-east-1", "AWS_PROFILE": "ob-aws-cloudwatch", "AWS_ACCOUNT_ID": ACCOUNT}
INSIGHTS_ON = {"INSIGHTS_ENABLED": "true", "AWS_INSIGHTS_PROFILE": "ob-aws-cloudwatch-insights"}
INSIGHTS_ARN = f"arn:aws:iam::{ACCOUNT}:user/cloud-watch-insights-review"
PHASE1_ARN = f"arn:aws:iam::{ACCOUNT}:user/cloud-watch-log-review"
OTHER_REGION = "ap-southeast-1"


def cfg(**extra):
    return load_config({**BASE, **extra}, require_account_id=True)


def split_config(**over):
    return make_insights_config(aws_region="us-east-1", insights_region=OTHER_REGION, **over)


# ------------------------------------------------------------------ configuration
def test_phase1_region_is_unchanged_by_the_insights_region():
    c = cfg(**INSIGHTS_ON, AWS_INSIGHTS_REGION=OTHER_REGION)
    assert c.aws_region == "us-east-1"                        # Phase 1
    assert c.insights_region == OTHER_REGION and c.insights_effective_region == OTHER_REGION
    assert c.aws_account_id == ACCOUNT and c.aws_profile == "ob-aws-cloudwatch"
    assert c.insights_profile == "ob-aws-cloudwatch-insights"


def test_insights_region_defaults_to_the_phase1_region_for_backward_compatibility():
    c = cfg(**INSIGHTS_ON)
    assert c.insights_region is None and c.insights_effective_region == "us-east-1"
    assert load_config({"AWS_REGION": "eu-west-1"}).insights_effective_region == "eu-west-1"   # follows AWS_REGION


def test_blank_insights_region_behaves_as_unset():
    assert cfg(AWS_INSIGHTS_REGION="  ").insights_effective_region == "us-east-1"


@pytest.mark.parametrize("bad", ["ap_southeast_1", "Asia", "ap-southeast", "1", "us-east-1; rm -rf", "ap-southeast-1x"])
def test_invalid_insights_region_is_rejected(bad):
    with pytest.raises(ConfigError, match="AWS_INSIGHTS_REGION"):
        cfg(AWS_INSIGHTS_REGION=bad)


def test_the_validated_configuration_uses_us_east_1_for_both_phases():
    """PROD CloudWatch log groups are in us-east-1, so Insights runs there too (same account, distinct identity)."""
    c = load_config({"AWS_REGION": "us-east-1", "AWS_INSIGHTS_REGION": "us-east-1", "AWS_PROFILE": "ob-aws-cloudwatch",
                     "AWS_INSIGHTS_PROFILE": "ob-aws-cloudwatch-insights", "AWS_ACCOUNT_ID": "926266574832",
                     "INSIGHTS_ENABLED": "true"}, require_account_id=True)
    assert (c.aws_region, c.insights_effective_region, c.aws_account_id) == ("us-east-1", "us-east-1", "926266574832")
    assert (c.aws_profile, c.insights_profile) == ("ob-aws-cloudwatch", "ob-aws-cloudwatch-insights")


def test_a_different_insights_region_remains_supported_for_the_future():
    c = load_config({"AWS_REGION": "us-east-1", "AWS_INSIGHTS_REGION": "ap-southeast-1", "AWS_PROFILE": "ob-aws-cloudwatch",
                     "AWS_INSIGHTS_PROFILE": "ob-aws-cloudwatch-insights", "AWS_ACCOUNT_ID": "926266574832",
                     "INSIGHTS_ENABLED": "true"}, require_account_id=True)
    assert (c.aws_region, c.insights_effective_region, c.aws_account_id) == ("us-east-1", "ap-southeast-1", "926266574832")


def test_the_documented_configuration_matches_the_validated_region():
    """README / .env.example must show us-east-1 as the intended Insights region."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    readme = (root / "README.md").read_text(encoding="utf-8")
    assert '"AWS_INSIGHTS_REGION": "us-east-1"' in readme and '"AWS_INSIGHTS_REGION": "ap-southeast-1"' not in readme
    env = (root / ".env.example").read_text(encoding="utf-8")
    assert "AWS_INSIGHTS_REGION=us-east-1" in env and "AWS_INSIGHTS_REGION=ap-southeast-1" not in env


def test_phase1_only_configuration_is_unaffected_when_insights_is_off():
    c = cfg(AWS_INSIGHTS_REGION=OTHER_REGION)                          # variable present but Insights disabled
    assert c.insights_enabled is False and c.aws_region == "us-east-1"


# ------------------------------------------------------------------ clients use different regions
def _fake_session(region="us-east-1"):
    return boto3.session.Session(aws_access_key_id="testing", aws_secret_access_key="testing", region_name=region)


def test_phase1_clients_stay_in_us_east_1_and_insights_clients_use_ap_southeast_1():
    c = split_config()
    phase1 = AwsClients(c, session=_fake_session())
    assert phase1._build("logs").meta.region_name == "us-east-1"
    assert phase1._build("cloudwatch").meta.region_name == "us-east-1"
    ins = InsightsClients(c, lambda: {"account": ACCOUNT, "arn": PHASE1_ARN}, session=_fake_session())
    sts = Stubber(ins._sts())
    sts.add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": INSIGHTS_ARN, "UserId": "AIDAX"})
    with sts:
        start, read = ins.begin_client(), ins.read_client()
    assert start.meta.region_name == OTHER_REGION and read.meta.region_name == OTHER_REGION and ins._sts().meta.region_name == OTHER_REGION


def test_insights_endpoint_is_regional():
    ins = InsightsClients(split_config(), lambda: {}, session=_fake_session())
    assert "ap-southeast-1" in ins._logs("x", max_attempts=0, mode="standard").meta.endpoint_url


def test_default_insights_region_equals_phase1_region_in_the_clients():
    c = make_insights_config()                                  # no insights_region
    ins = InsightsClients(c, lambda: {}, session=_fake_session())
    assert ins._logs("x", max_attempts=0, mode="standard").meta.region_name == "us-east-1"


def test_profile_sessions_carry_their_own_regions(tmp_path, monkeypatch):
    (tmp_path / "credentials").write_text(
        "[ob-aws-cloudwatch]\naws_access_key_id = AKIAPHASE1FAKEFAKE12\naws_secret_access_key = a\n"
        "[ob-aws-cloudwatch-insights]\naws_access_key_id = AKIAINSIGHTSFAKE123\naws_secret_access_key = b\n")
    (tmp_path / "config").write_text("[profile ob-aws-cloudwatch]\nregion = us-east-1\n"
                                     "[profile ob-aws-cloudwatch-insights]\nregion = us-east-1\n")
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_REGION"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    c = split_config()
    assert AwsClients(c)._get_session().region_name == "us-east-1"
    assert InsightsClients(c, lambda: {})._get_session().region_name == OTHER_REGION          # explicit config wins over the profile file


# ------------------------------------------------------------------ same account, distinct identity, pin enforced
def _identity(clients, account=ACCOUNT, arn=INSIGHTS_ARN):
    stub = Stubber(clients._sts())
    stub.add_response("get_caller_identity", {"Account": account, "Arn": arn, "UserId": "AIDAX"})
    return stub


def test_account_pin_still_verified_for_the_insights_region():
    ins = InsightsClients(split_config(), lambda: {"account": ACCOUNT, "arn": PHASE1_ARN}, session=_fake_session())
    with _identity(ins):
        assert ins.verify() == {"account": ACCOUNT, "arn": INSIGHTS_ARN}


def test_wrong_account_in_the_insights_region_is_refused_before_any_client_is_returned():
    ins = InsightsClients(split_config(), lambda: {"account": ACCOUNT, "arn": PHASE1_ARN}, session=_fake_session())
    with _identity(ins, account="111122223333"):
        with pytest.raises(AccountMismatch):
            ins.begin_client()
        with pytest.raises(AccountMismatch):
            ins.read_client()


def test_identity_must_still_be_distinct_from_phase1_across_regions():
    from aws_cw_mcp.utils.errors import IdentityConflict
    ins = InsightsClients(split_config(), lambda: {"account": ACCOUNT, "arn": INSIGHTS_ARN}, session=_fake_session())
    with _identity(ins):
        with pytest.raises(IdentityConflict):
            ins.verify()


# ------------------------------------------------------------------ the log-group catalog follows the INSIGHTS region
def test_insights_catalog_uses_the_phase1_identity_but_the_insights_region(monkeypatch):
    seen = []

    def fake_logs(self):
        seen.append((self._config.aws_region, self._config.aws_profile, self._config.aws_account_id))
        return make_client("logs")

    monkeypatch.setattr(AwsClients, "logs", fake_logs)
    c = split_config()
    rt = Runtime(c, FakeClients(logs=make_client("logs")))
    regional = rt.insights_logs
    assert seen == [(OTHER_REGION, "ob-aws-cloudwatch", ACCOUNT)]     # Phase 1 profile, Insights region, same account pin
    assert regional is not rt.logs
    assert regional._cfg.aws_region == OTHER_REGION and rt.logs._cfg.aws_region == "us-east-1"   # Phase 1 LogsService untouched
    assert rt.insights_logs is regional                        # cached


def test_when_regions_are_equal_the_catalog_reuses_the_phase1_logs_service():
    rt = Runtime(make_insights_config(), FakeClients(logs=make_client("logs")))
    assert rt.insights_logs is rt.logs


# ------------------------------------------------------------------ reporting
def test_health_check_reports_both_regions():
    h = Harness(split_config())
    rt = Runtime(h.cfg, FakeClients(), insights_clients=h.clients, insights_executor=h.executor)
    d = parse(build_tools(rt)["aws_health_check"]())
    assert d["FACT"]["region"] == "us-east-1"                                 # Phase 1 fact unchanged
    ins = d["FACT"]["insights"]
    assert ins["region"] == OTHER_REGION and ins["phase1_region"] == "us-east-1" and ins["account"] == ACCOUNT
    assert d["FACT"]["pinned_account"] == ACCOUNT


def test_insights_results_and_status_report_the_insights_region():
    h = Harness(split_config())
    tools = build_tools(Runtime(h.cfg, FakeClients(), insights_clients=h.clients, insights_executor=h.executor))
    st = parse(tools["aws_insights_budget_status"]())
    assert st["FACT"]["limits"]["insights_region"] == OTHER_REGION and st["FACT"]["limits"]["phase1_region"] == "us-east-1"
    h.estimate_flow(1234)
    est = parse(tools["aws_insights_estimate_scan"](log_groups=[GROUP], preset="errors"))
    assert est["FACT"]["scope"]["region"] == OTHER_REGION
    h.run_flow([{"bin(1m)": "2026-01-01 00:00:00.000", "matches": 1}], query_id="q-2")
    from aws_cw_mcp.insights.results import outcome_to_result
    out = h.executor.run(plan_for(h.cfg, preset="timeouts"))
    assert outcome_to_result("t", out, h.cfg).to_dict()["FACT"]["scope"]["region"] == OTHER_REGION


def test_phase1_health_check_output_has_no_region_change_when_insights_is_off():
    rt = Runtime(make_config(), FakeClients())
    d = parse(build_tools(rt)["aws_health_check"]())
    assert d["FACT"]["region"] == "us-east-1" and "insights" not in d["FACT"]
