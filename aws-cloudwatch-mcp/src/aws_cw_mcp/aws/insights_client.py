"""Logs Insights AWS access: the ONLY module that calls StartQuery / GetQueryResults / StopQuery.

Three independent protections live here:

1. A dedicated session/profile (AWS_INSIGHTS_PROFILE) with its own pinned-account and identity checks.
   It is distinct from the Phase 1 identity, and must not resolve to the same principal.
2. InsightsGate on the Insights `logs` clients: only these three operations are permitted (Phase 1
   operations such as DescribeLogGroups are REFUSED here), StartQuery must carry a fingerprint that the
   validator approved (single use), and GetQueryResults/StopQuery only accept queryIds that this process
   started. Checked at `before-parameter-build` (caller's parameters) and again at `before-call` (the
   serialized body), so nothing can change between the two.
3. StartQuery uses a client that makes exactly ONE attempt (botocore max_attempts=0 -> total 1): it has no
   idempotency token, so a retry after a timeout could create a duplicate billed query.
"""
from __future__ import annotations

import json
import logging
import re
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

import boto3

from aws_cw_mcp.aws.client import make_boto_config
from aws_cw_mcp.config import Config, ConfigError
from aws_cw_mcp.insights.plans import QUERY_LANGUAGE, request_fingerprint
from aws_cw_mcp.insights.registry import ApprovedQueryRegistry, OwnedQueryRegistry
from aws_cw_mcp.utils.errors import AccountMismatch, IdentityConflict, ReadOnlyViolation

logger = logging.getLogger("aws-cloudwatch-mcp")

INSIGHTS_OPERATIONS = frozenset({"StartQuery", "GetQueryResults", "StopQuery"})
_START_KEYS = frozenset({"queryString", "startTime", "endTime", "logGroupNames", "queryLanguage"})  # + optional "limit"
_ESTIMATE_STAGE = re.compile(r"(?:^|\|)\s*estimate\s*(?=\||$)")
_ESTIMATE_LAST = re.compile(r"\|\s*estimate\s*$")
_RESULTS_KEYS = frozenset({"queryId", "maxItems", "nextToken"})


def _context_of(kwargs) -> dict:
    ctx = kwargs.get("context")
    return ctx if isinstance(ctx, dict) else {}


class InsightsGate:
    """Event handlers registered on the Insights logs clients (see attach_gate)."""

    def __init__(self, approved: ApprovedQueryRegistry, owned: OwnedQueryRegistry):
        self.approved = approved
        self.owned = owned

    # -- before-parameter-build: sees the caller's parameters ---------------------------------
    def before_parameter_build(self, params=None, model=None, **kwargs) -> None:
        op = getattr(model, "name", "")
        if op not in INSIGHTS_OPERATIONS:
            raise ReadOnlyViolation(f"Blocked AWS operation {op!r}: the Insights client only permits "
                                    "StartQuery, GetQueryResults and StopQuery.")
        params = params or {}
        if op == "StartQuery":
            keys = set(params)
            has_limit = "limit" in keys
            if keys - {"limit"} != _START_KEYS:
                raise ReadOnlyViolation("Blocked StartQuery: unexpected or missing request parameters.")
            # `| estimate` must be the FINAL command; AWS applies an API `limit` as a trailing stage, so an
            # estimate request must carry NO limit, and a real query MUST carry one.
            q = params["queryString"]
            stages = len(_ESTIMATE_STAGE.findall(q)) if isinstance(q, str) else 0
            is_estimate = isinstance(q, str) and bool(_ESTIMATE_LAST.search(q)) and stages == 1
            if stages and not is_estimate:
                raise ReadOnlyViolation("Blocked StartQuery: 'estimate' must be the single, final command.")
            if is_estimate and has_limit:
                raise ReadOnlyViolation("Blocked StartQuery: an estimate request must not carry an API limit "
                                        "(it would be applied after the estimate command).")
            if not is_estimate and not has_limit:
                raise ReadOnlyViolation("Blocked StartQuery: a real query request must carry an explicit limit.")
            if params["queryLanguage"] != QUERY_LANGUAGE:
                raise ReadOnlyViolation("Blocked StartQuery: only the CWLI query language is permitted.")
            names = params["logGroupNames"]
            if not isinstance(names, (list, tuple)) or not names:
                raise ReadOnlyViolation("Blocked StartQuery: logGroupNames is required.")
            fp = request_fingerprint(params["queryString"], names, params["startTime"], params["endTime"],
                                     params.get("limit"))
            if not self.approved.is_approved(fp):
                raise ReadOnlyViolation("Blocked StartQuery: the request was not approved by the validator "
                                        "(or its approval expired).")
            _context_of(kwargs)["insights_fingerprint"] = fp
            return
        keys = set(params)
        if op == "GetQueryResults" and not (keys <= _RESULTS_KEYS and "queryId" in keys):
            raise ReadOnlyViolation("Blocked GetQueryResults: unexpected request parameters.")
        if op == "StopQuery" and keys != {"queryId"}:
            raise ReadOnlyViolation("Blocked StopQuery: unexpected request parameters.")
        if not self.owned.contains(params.get("queryId")):
            raise ReadOnlyViolation(f"Blocked {op}: the queryId was not started by this server.")

    # -- before-call: sees the serialized request just before it is sent ------------------------
    def before_call(self, model=None, params=None, **kwargs) -> None:
        op = getattr(model, "name", "")
        if op not in INSIGHTS_OPERATIONS:
            raise ReadOnlyViolation(f"Blocked AWS operation {op!r}.")
        if op != "StartQuery":
            return
        expected = _context_of(kwargs).get("insights_fingerprint")
        if not expected:
            raise ReadOnlyViolation("Blocked StartQuery: missing approval context.")
        body = (params or {}).get("body")
        if isinstance(body, (bytes, bytearray)):
            body = body.decode("utf-8", "replace")
        try:
            sent = json.loads(body)
            fp = request_fingerprint(sent["queryString"], sent["logGroupNames"], sent["startTime"],
                                     sent["endTime"], sent.get("limit"))
        except (TypeError, ValueError, KeyError):
            raise ReadOnlyViolation("Blocked StartQuery: the outgoing request could not be verified.") from None
        if fp != expected or sent.get("queryLanguage") != QUERY_LANGUAGE:
            raise ReadOnlyViolation("Blocked StartQuery: the outgoing request differs from the approved one.")
        if not self.approved.consume(fp):
            raise ReadOnlyViolation("Blocked StartQuery: approval already used or expired (approvals are single-use).")


def attach_gate(client, gate: InsightsGate) -> None:
    client.meta.events.register("before-parameter-build.*.*", gate.before_parameter_build)
    client.meta.events.register("before-call.*.*", gate.before_call)


def _sts_only_guard(model, **kwargs) -> None:
    if model.name != "GetCallerIdentity":
        raise ReadOnlyViolation(f"Blocked AWS operation {model.name!r} on the Insights identity client.")


class InsightsClients:
    """Dedicated Insights session: own profile, own STS identity, gated logs clients."""

    def __init__(self, config: Config, phase1_identity: Callable[[], dict],
                 session: Optional[boto3.session.Session] = None,
                 approved: Optional[ApprovedQueryRegistry] = None,
                 owned: Optional[OwnedQueryRegistry] = None):
        self._config = config
        self._phase1_identity = phase1_identity
        self._session = session
        self.approved = approved or ApprovedQueryRegistry()
        self.owned = owned or OwnedQueryRegistry()
        self.gate = InsightsGate(self.approved, self.owned)
        self._clients: dict = {}
        self._identity: Optional[dict] = None
        self._verified = False
        self._lock = threading.RLock()

    def _get_session(self) -> boto3.session.Session:
        if self._session is None:
            if not self._config.insights_profile:
                raise ConfigError("AWS_INSIGHTS_PROFILE is not set")
            self._session = boto3.session.Session(profile_name=self._config.insights_profile,
                                                  region_name=self._config.insights_effective_region)
        return self._session

    def _sts(self):
        with self._lock:
            if "sts" not in self._clients:
                c = self._get_session().client(
                    "sts", config=make_boto_config(self._config, region=self._config.insights_effective_region))
                c.meta.events.register("before-call.*.*", _sts_only_guard)
                self._clients["sts"] = c
            return self._clients["sts"]

    def _logs(self, name: str, *, max_attempts: int, mode: str):
        with self._lock:
            if name not in self._clients:
                c = self._get_session().client(
                    "logs", config=make_boto_config(self._config, max_attempts=max_attempts, mode=mode,
                                                    region=self._config.insights_effective_region))
                attach_gate(c, self.gate)
                self._clients[name] = c
            return self._clients[name]

    def identity(self) -> dict:
        with self._lock:
            if self._identity is None:
                resp = self._sts().get_caller_identity()
                self._identity = {"account": resp.get("Account"), "arn": resp.get("Arn")}
            return self._identity

    def verify(self) -> dict:
        """Refuse unless: pinned account matches, principal differs from Phase 1, expected ARN (if pinned)
        matches. Failures are never cached as success."""
        cfg = self._config
        if not cfg.aws_account_id:
            raise ConfigError("AWS_ACCOUNT_ID is not set; refusing to run Insights without an account pin.")
        ident = self.identity()
        with self._lock:
            if self._verified:
                return ident
            if ident.get("account") != cfg.aws_account_id:
                raise AccountMismatch(f"The Insights profile resolves to account {ident.get('account')}, but "
                                      f"AWS_ACCOUNT_ID is pinned to {cfg.aws_account_id}. Refusing to query.")
            phase1 = self._phase1_identity() or {}
            if phase1.get("arn") and phase1.get("arn") == ident.get("arn"):
                raise IdentityConflict("The Insights profile resolves to the SAME principal as the Phase 1 "
                                       "profile. Insights requires its own dedicated identity.")
            if cfg.insights_expected_arn and ident.get("arn") != cfg.insights_expected_arn:
                raise IdentityConflict("The Insights principal does not match AWS_INSIGHTS_EXPECTED_ARN.")
            self._verified = True
            return ident

    def begin_client(self):
        self.verify()
        return self._logs("logs_start", max_attempts=0, mode="standard")   # exactly ONE attempt for StartQuery

    def read_client(self):
        self.verify()
        return self._logs("logs_read", max_attempts=3, mode="standard")    # idempotent calls may retry (3 retries)


@dataclass
class QueryPage:
    status: str
    rows: list = field(default_factory=list)
    statistics: dict = field(default_factory=dict)
    next_token: Optional[str] = None

    @property
    def bytes_scanned(self) -> int:
        try:
            return int(float(self.statistics.get("bytesScanned") or 0))
        except (TypeError, ValueError):
            return 0


class InsightsApi:
    """Thin wrapper over the three query APIs. Method names deliberately avoid AWS's write-style verbs
    so static scans can keep flagging any other module that calls them directly."""

    def __init__(self, clients):
        self._clients = clients

    def begin_query(self, *, query: str, group_names, start_s: int, end_s: int,
                    limit: Optional[int] = None) -> str:
        """limit=None (estimate) omits the API `limit` parameter entirely."""
        client = self._clients.begin_client()
        kwargs = dict(queryString=query, logGroupNames=list(group_names), startTime=int(start_s),
                      endTime=int(end_s), queryLanguage=QUERY_LANGUAGE)
        if limit is not None:
            kwargs["limit"] = int(limit)
        resp = client.start_query(**kwargs)
        query_id = resp["queryId"]
        self._clients.owned.add(query_id)
        return query_id

    def fetch_results(self, query_id: str, *, max_items: Optional[int] = None,
                      next_token: Optional[str] = None) -> QueryPage:
        client = self._clients.read_client()
        kwargs = {"queryId": query_id}
        if max_items is not None:
            kwargs["maxItems"] = int(max_items)
        if next_token:
            kwargs["nextToken"] = next_token
        resp = client.get_query_results(**kwargs)
        rows = []
        for result in resp.get("results", []) or []:
            row = {}
            for cell in result:
                name = cell.get("field")
                if name and name != "@ptr":           # @ptr would allow GetLogRecord; never exposed
                    row[name] = cell.get("value")
            rows.append(row)
        return QueryPage(status=resp.get("status", "Unknown"), rows=rows,
                         statistics=dict(resp.get("statistics") or {}), next_token=resp.get("nextToken"))

    def cancel_query(self, query_id: str) -> bool:
        client = self._clients.read_client()
        resp = client.stop_query(queryId=query_id)
        return bool(resp.get("success"))

    def forget(self, query_id: str) -> None:
        self._clients.owned.discard(query_id)

    @property
    def approved(self) -> ApprovedQueryRegistry:
        return self._clients.approved
