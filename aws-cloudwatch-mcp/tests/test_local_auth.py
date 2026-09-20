"""Local Windows deployment model: named AWS CLI profile + pinned account, no SSH/bastion.

No real AWS calls are made. The profile files contain obviously fake, test-only keys in a
temp directory; STS is answered by botocore's Stubber.
"""
import json
import logging
import os
import re
from pathlib import Path

import pytest
from botocore.exceptions import ProfileNotFound
from botocore.stub import Stubber

from aws_cw_mcp.aws.client import READ_ONLY_OPERATIONS, AwsClients, principal_type, warn_if_static_credentials
from aws_cw_mcp.config import ConfigError, load_config, load_dotenv_file
from aws_cw_mcp.runtime import Runtime
from aws_cw_mcp.server import build_tools, main
from aws_cw_mcp.utils.errors import AccountMismatch, describe_exception
from conftest import make_config, parse

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "ob-aws-cloudwatch"
ACCOUNT = "926266574832"
USER_ARN = f"arn:aws:iam::{ACCOUNT}:user/cloud-watch-log-review"
FAKE_KEY = "AKIAFAKEFAKEFAKE1234"
FAKE_SECRET = "FakeSecretValueForTestsOnly/0123456789abcdef"

CRED_ENV = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
            "AWS_DEFAULT_PROFILE")


@pytest.fixture
def profile_env(tmp_path, monkeypatch):
    """Point the AWS SDK at a temp credentials/config file that defines the test profile."""
    creds = tmp_path / "credentials"
    creds.write_text(f"[{PROFILE}]\naws_access_key_id = {FAKE_KEY}\naws_secret_access_key = {FAKE_SECRET}\n")
    conf = tmp_path / "config"
    conf.write_text(f"[profile {PROFILE}]\nregion = us-east-1\n")
    for k in CRED_ENV:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(conf))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")  # never probe IMDS in tests
    return tmp_path


def _cfg(**over):
    return make_config(aws_profile=PROFILE, aws_account_id=ACCOUNT, **over)


def _identity(account=ACCOUNT, arn=USER_ARN):
    return {"Account": account, "Arn": arn, "UserId": "AIDAEXAMPLEEXAMPLE"}


# ------------------------------------------------------------ 1. profile accepted
def test_aws_profile_is_read_from_environment():
    c = load_config({"AWS_PROFILE": PROFILE, "AWS_REGION": "us-east-1", "AWS_ACCOUNT_ID": ACCOUNT})
    assert (c.aws_profile, c.aws_region, c.aws_account_id) == (PROFILE, "us-east-1", ACCOUNT)


def test_named_profile_is_used_through_boto3_session(profile_env):
    session = AwsClients(_cfg())._get_session()
    assert session.profile_name == PROFILE
    assert session.get_credentials().access_key == FAKE_KEY


def test_profile_wins_over_stray_credential_env_vars(profile_env, monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAENVENVENVENV0000")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "env-secret-should-not-be-used")
    creds = AwsClients(_cfg())._get_session().get_credentials()
    assert creds.access_key == FAKE_KEY


def test_unknown_profile_is_a_clear_configuration_error(profile_env):
    with pytest.raises(ProfileNotFound) as exc:
        AwsClients(make_config(aws_profile="does-not-exist", aws_account_id=ACCOUNT)).client("sts")
    info = describe_exception(exc.value)
    assert info.kind == "configuration" and info.code == "ProfileNotFound"


# ------------------------------------------------ 2. account id required for real runs
def test_account_id_required_for_real_execution():
    env = {"AWS_REGION": "us-east-1", "AWS_PROFILE": PROFILE}
    with pytest.raises(ConfigError, match="AWS_ACCOUNT_ID is required"):
        load_config(env, require_account_id=True)
    assert load_config({**env, "AWS_ACCOUNT_ID": ACCOUNT}, require_account_id=True).aws_account_id == ACCOUNT


def test_main_refuses_to_start_without_account_id(monkeypatch, tmp_path):
    empty_env_file = tmp_path / "empty.env"
    empty_env_file.write_text("")
    monkeypatch.setenv("AWS_CW_MCP_ENV_FILE", str(empty_env_file))
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.delenv("AWS_ACCOUNT_ID", raising=False)
    with pytest.raises(SystemExit) as exc:
        main()
    assert "AWS_ACCOUNT_ID" in str(exc.value)


def test_clients_refuse_aws_calls_when_pin_missing(profile_env):
    clients = AwsClients(make_config(aws_profile=PROFILE, aws_account_id=None))
    with pytest.raises(ConfigError, match="AWS_ACCOUNT_ID"):
        clients.logs()
    with pytest.raises(ConfigError):
        clients.cloudwatch()


def test_env_file_mechanism_still_works(tmp_path):
    f = tmp_path / "custom.env"
    f.write_text(f"AWS_PROFILE={PROFILE}\nAWS_REGION=us-east-1\nAWS_ACCOUNT_ID={ACCOUNT}\n")
    keys = ("AWS_PROFILE", "AWS_REGION", "AWS_ACCOUNT_ID")
    saved = {k: os.environ.pop(k, None) for k in keys}
    try:
        os.environ["AWS_CW_MCP_ENV_FILE"] = str(f)
        load_dotenv_file()
        c = load_config(require_account_id=True)
        assert (c.aws_profile, c.aws_account_id) == (PROFILE, ACCOUNT)
    finally:
        os.environ.pop("AWS_CW_MCP_ENV_FILE", None)
        for k in keys:
            os.environ.pop(k, None)
            if saved[k] is not None:
                os.environ[k] = saved[k]


# --------------------------------------------------------- 3. correct account accepted
def test_correct_account_is_accepted_and_health_check_reports_safe_metadata(profile_env):
    clients = AwsClients(_cfg())
    with Stubber(clients.client("sts")) as sts:
        sts.add_response("get_caller_identity", _identity())
        out = build_tools(Runtime(_cfg(), clients))["aws_health_check"]()
        assert clients.logs() is not None  # verified once; no second STS call needed
    d = parse(out)
    assert d["status"] == "ok"
    f = d["FACT"]
    assert f["aws_account"] == ACCOUNT and f["principal_type"] == "iam-user"
    assert f["account_verified_against_pin"] is True and f["region"] == "us-east-1"
    assert f["profile"] == PROFILE and f["pinned_account"] == ACCOUNT


def test_principal_type_helper():
    assert principal_type(USER_ARN) == "iam-user"
    assert principal_type(f"arn:aws:sts::{ACCOUNT}:assumed-role/r/s") == "assumed-role"
    assert principal_type(f"arn:aws:iam::{ACCOUNT}:root") == "root"
    assert principal_type(None) == "unknown"


# ------------------------------------------------------- 4. wrong account rejected
def test_wrong_account_is_rejected_and_stays_rejected(profile_env):
    clients = AwsClients(_cfg())
    with Stubber(clients.client("sts")) as sts:
        sts.add_response("get_caller_identity", _identity(account="111122223333"))
        with pytest.raises(AccountMismatch, match="Refusing to query"):
            clients.logs()
        with pytest.raises(AccountMismatch):  # cached identity, still refused, no new STS call
            clients.cloudwatch()


def test_wrong_account_blocks_every_tool_before_any_data_call(profile_env):
    clients = AwsClients(_cfg())
    tools = build_tools(Runtime(_cfg(), clients))
    with Stubber(clients.client("sts")) as sts:
        sts.add_response("get_caller_identity", _identity(account="111122223333"))
        results = [parse(tools["aws_health_check"]()),
                   parse(tools["aws_get_alarms"]()),
                   parse(tools["aws_discover_log_groups"](keyword="x")),
                   parse(tools["aws_list_metrics"](namespace="AWS/EC2"))]
    for d in results:
        assert d["status"] == "error" and d["error"]["kind"] == "account_mismatch"
        assert d["FACT"] == {}


# ------------------------------------------------------------ 5. no credentials logged
def test_no_credentials_in_output_logs_or_errors(profile_env, caplog, capsys, monkeypatch):
    monkeypatch.setenv("AWS_SESSION_TOKEN", "FwoGZXIvYXdzSESSIONTOKENVALUE123")
    caplog.set_level(logging.DEBUG)
    clients = AwsClients(_cfg())
    tools = build_tools(Runtime(_cfg(), clients))
    warn_if_static_credentials()
    with Stubber(clients.client("sts")) as sts:
        sts.add_response("get_caller_identity", _identity())
        outputs = [tools["aws_health_check"]()]
    outputs.append(tools["aws_search_logs"](log_groups=["/g"], lookback="banana"))  # error path
    captured = capsys.readouterr()
    blob = "\n".join(outputs) + captured.out + captured.err + caplog.text
    for secret in (FAKE_KEY, FAKE_SECRET, "SESSIONTOKENVALUE", "AKIAENV"):
        assert secret not in blob
    for field in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
        assert field not in blob
    assert captured.out == ""  # nothing but MCP frames may ever reach stdout


def test_static_credential_warning_never_prints_values(caplog, monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIAENVENVENVENV0000")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "env-secret-value")
    caplog.set_level(logging.WARNING)
    warn_if_static_credentials()
    assert "credential environment variables" in caplog.text
    assert "AKIAENV" not in caplog.text and "env-secret-value" not in caplog.text


# ------------------------------------------------------ 6. no SSH / bastion dependency
def test_no_ssh_or_bastion_code_or_dependencies():
    pattern = re.compile(r"\b(ssh|asyncssh|paramiko|fabric|bastion)\b", re.I)
    offenders = []
    for path in (ROOT / "src").rglob("*.py"):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.name}:{n}")
    assert not offenders, offenders
    for name in ("requirements.txt", "requirements-dev.txt", "pyproject.toml"):
        assert not re.search(r"paramiko|asyncssh|fabric", (ROOT / name).read_text(), re.I), name
    assert not (ROOT / "scripts").exists()


def test_no_instance_profile_or_imds_usage_in_source():
    text = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "src").rglob("*.py")).lower()
    assert "169.254.169.254" not in text and "instanceprofile" not in text.replace("_", "")


# --------------------------------------------- config files contain no credentials
def _active_lines(path: Path):
    return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")]


def test_env_example_has_profile_region_account_and_no_credentials():
    active = _active_lines(ROOT / ".env.example")
    assert "AWS_PROFILE=ob-aws-cloudwatch" in active
    assert "AWS_REGION=us-east-1" in active
    assert f"AWS_ACCOUNT_ID={ACCOUNT}" in active
    joined = "\n".join(active).upper()
    for forbidden in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        assert forbidden not in joined
    assert not re.search(r"\bAKIA[A-Z0-9]{16}\b", (ROOT / ".env.example").read_text())


def test_readme_claude_desktop_config_is_valid_and_local():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```json\n(.*?)```", text, re.S)
    cfgs = [json.loads(b) for b in blocks if '"mcpServers"' in b]
    assert cfgs, "README must contain a Claude Desktop config"
    server = cfgs[0]["mcpServers"]["aws-cloudwatch"]
    assert server["command"].replace("\\", "/").endswith("aws-cloudwatch-mcp/venv/Scripts/python.exe")
    assert server["args"] == ["-m", "aws_cw_mcp"]
    assert server["env"] == {"AWS_PROFILE": PROFILE, "AWS_REGION": "us-east-1", "AWS_ACCOUNT_ID": ACCOUNT}


# ------------------------------- IAM doc stays consistent with the code's real API use
def test_iam_doc_and_policy_cover_every_allowed_operation():
    doc = (ROOT / "docs" / "IAM-REQUIRED-PHASE1.md").read_text(encoding="utf-8")
    policy = json.loads((ROOT / "docs" / "iam-policy-phase1.json").read_text(encoding="utf-8"))
    granted = {a for st in policy["Statement"] for a in st["Action"]}
    prefix = {"GetCallerIdentity": "sts", "ListMetrics": "cloudwatch", "GetMetricData": "cloudwatch",
              "GetMetricStatistics": "cloudwatch", "DescribeAlarms": "cloudwatch",
              "DescribeAlarmHistory": "cloudwatch"}
    for op in READ_ONLY_OPERATIONS:
        action = f"{prefix.get(op, 'logs')}:{op}"
        assert action in doc, action
        if not action.startswith("sts:"):
            assert action in granted, action  # nothing the code calls is missing from the policy
    for action in ("logs:StartQuery", "logs:GetQueryResults", "logs:StopQuery"):
        assert action in doc                  # Phase 2 documented ...
        assert action not in granted          # ... but not granted in the Phase 1 policy
    assert not ({"StartQuery", "GetQueryResults", "StopQuery"} & READ_ONLY_OPERATIONS)  # ... nor in code
