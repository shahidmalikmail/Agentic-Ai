"""AWS session/client layer.

* Credentials come ONLY from the standard boto3 provider chain. In the local
  deployment that is the named AWS CLI profile (AWS_PROFILE=ob-aws-cloudwatch),
  passed to boto3.Session(profile_name=...). Nothing here reads, stores or logs
  credentials.
* Before ANY non-STS client is handed out, sts:GetCallerIdentity must return the
  account in AWS_ACCOUNT_ID. A missing pin or a mismatch refuses every AWS call.
* Every client gets a `before-call` guard that refuses any API operation that is
  not on READ_ONLY_OPERATIONS. Adding a new operation is a deliberate code change
  that shows up in review; there is no generic "call any AWS API" path.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Optional

import boto3
from botocore.config import Config as BotoConfig

from aws_cw_mcp.config import Config, ConfigError
from aws_cw_mcp.utils.errors import AccountMismatch, ReadOnlyViolation

logger = logging.getLogger("aws-cloudwatch-mcp")

# Phase 1 allow-list. Grow it per phase, each addition reviewed as read-only.
READ_ONLY_OPERATIONS = frozenset({
    # STS (identity check; needs no IAM permission)
    "GetCallerIdentity",
    # CloudWatch Logs
    "DescribeLogGroups", "DescribeLogStreams", "FilterLogEvents", "GetLogEvents",
    # CloudWatch metrics / alarms
    "ListMetrics", "GetMetricData",
    "DescribeAlarms", "DescribeAlarmHistory",
})

# Verbs that indicate a mutating API. Used by tests to make sure the allow-list
# never contains one, and by the guard as a second, independent check.
WRITE_VERBS = ("Put", "Delete", "Create", "Update", "Set", "Start", "Stop", "Enable", "Disable",
               "Tag", "Untag", "Associate", "Disassociate", "Attach", "Detach", "Modify", "Reboot",
               "Terminate", "Run", "Register", "Deregister", "Publish", "Send", "Invoke", "Cancel",
               "Add", "Remove", "Import", "Export", "Kill", "Reset", "Apply", "Authorize", "Revoke")


def assert_read_only(operation_name: str) -> None:
    if operation_name not in READ_ONLY_OPERATIONS or operation_name.startswith(WRITE_VERBS):
        raise ReadOnlyViolation(
            f"Blocked AWS operation {operation_name!r}: not on the read-only allow-list.")


def _guard(model, **kwargs) -> None:
    assert_read_only(model.name)


class AwsClients:
    """Lazily creates guarded boto3 clients from the default credential chain."""

    def __init__(self, config: Config, session: Optional[boto3.session.Session] = None):
        self._config = config
        self._session = session
        self._clients: dict = {}
        self._lock = threading.Lock()
        self._account_verified = False
        self._identity: Optional[dict] = None

    def _get_session(self) -> boto3.session.Session:
        if self._session is None:
            self._session = boto3.session.Session(
                profile_name=self._config.aws_profile, region_name=self._config.aws_region)
        return self._session

    def _build(self, service: str):
        cfg = BotoConfig(
            region_name=self._config.aws_region,
            retries={"mode": "adaptive", "max_attempts": self._config.api_max_attempts},
            connect_timeout=self._config.api_connect_timeout,
            read_timeout=self._config.api_read_timeout,
            user_agent_extra="aws-cloudwatch-mcp/readonly",
        )
        client = self._get_session().client(service, config=cfg)
        client.meta.events.register("before-call.*.*", _guard)
        return client

    def client(self, service: str):
        with self._lock:
            if service not in self._clients:
                self._clients[service] = self._build(service)
            client = self._clients[service]
        if service != "sts":
            self.verify_account()
        return client

    def identity(self) -> dict:
        """sts:GetCallerIdentity (cached). Contains account/ARN, never credentials."""
        if self._identity is None:
            resp = self.client("sts").get_caller_identity()
            self._identity = {"account": resp.get("Account"), "arn": resp.get("Arn")}
        return self._identity

    def verify_account(self) -> dict:
        """Refuse to continue unless the active identity is in the pinned account.

        Raises ConfigError if AWS_ACCOUNT_ID is not configured, AccountMismatch on a wrong
        account. A failure is never cached as success, so every later call is refused too.
        """
        expected = self._config.aws_account_id
        if not expected:
            raise ConfigError("AWS_ACCOUNT_ID is not set; refusing to run AWS operations "
                              "without an account pin.")
        ident = self.identity()
        if not self._account_verified:
            actual = ident.get("account")
            if actual != expected:
                raise AccountMismatch(
                    f"Credentials resolve to account {actual}, but AWS_ACCOUNT_ID is pinned to "
                    f"{expected}. Refusing to query.")
            self._account_verified = True
        return ident

    def logs(self):
        return self.client("logs")

    def cloudwatch(self):
        return self.client("cloudwatch")


def principal_type(arn: Optional[str]) -> str:
    """Safe identity metadata derived from an ARN: iam-user, assumed-role, root, ..."""
    if not arn or ":" not in arn:
        return "unknown"
    resource = arn.split(":", 5)[-1]
    if resource == "root":
        return "root"
    kind = resource.split("/", 1)[0]
    return {"user": "iam-user"}.get(kind, kind or "unknown")


def warn_if_static_credentials() -> None:
    """Log (never the values) when credential env vars are set.

    With an explicit profile boto3 ignores these variables, but stray keys in the
    environment are still worth flagging."""
    if any(os.environ.get(k) for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")):
        logger.warning("AWS credential environment variables are set. This server authenticates "
                       "through the named profile only; remove them from the environment / .env.")
