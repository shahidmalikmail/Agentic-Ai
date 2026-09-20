from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import (ClientError, ConnectTimeoutError, EndpointConnectionError,
                                 NoCredentialsError, ReadTimeoutError)

from aws_cw_mcp.config import ConfigError, load_config
from aws_cw_mcp.utils.cache import TTLCache
from aws_cw_mcp.utils.errors import InputError, describe_exception
from aws_cw_mcp.utils.sanitize import sanitize_obj, sanitize_text
from aws_cw_mcp.utils.stats import percentile, summarize
from aws_cw_mcp.utils.timerange import resolve_range

NOW = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)


# ------------------------------------------------------------------ config
def test_config_defaults():
    c = load_config({"AWS_REGION": "us-east-1"})
    assert c.aws_region == "us-east-1" and c.max_log_results == 200 and c.log_group_allowlist == ()


def test_config_requires_region():
    with pytest.raises(ConfigError, match="AWS_REGION"):
        load_config({})


def test_config_rejects_bad_region_and_account():
    with pytest.raises(ConfigError):
        load_config({"AWS_REGION": "not a region"})
    with pytest.raises(ConfigError, match="12-digit"):
        load_config({"AWS_REGION": "us-east-1", "AWS_ACCOUNT_ID": "123"})


def test_config_allowlist_and_ints():
    c = load_config({"AWS_REGION": "eu-west-1", "LOG_GROUP_ALLOWLIST": " /aws/eks/* , /aws/waf/* ,",
                     "MAX_LOG_RESULTS": "50", "AWS_ACCOUNT_ID": "123456789012"})
    assert c.log_group_allowlist == ("/aws/eks/*", "/aws/waf/*") and c.max_log_results == 50


def test_config_hard_ceilings_and_garbage():
    with pytest.raises(ConfigError, match="ceiling"):
        load_config({"AWS_REGION": "us-east-1", "MAX_LOG_RESULTS": "999999"})
    with pytest.raises(ConfigError, match="integer"):
        load_config({"AWS_REGION": "us-east-1", "MAX_PAGES": "lots"})
    with pytest.raises(ConfigError):
        load_config({"AWS_REGION": "us-east-1", "MAX_PAGES": "0"})


# ---------------------------------------------------------------- sanitize
@pytest.mark.parametrize("raw,secret", [
    ("key AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE"),
    ("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"),
    ("password=hunter2 next", "hunter2"),
    ('{"db_password": "s3cr3tValue", "x": 1}', "s3cr3tValue"),
    ("Authorization: Bearer abcdef1234567890", "abcdef1234567890"),
    ("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.SflKxwRJSMeKKF2QT4fwpM", "eyJhbGci"),
    ("jdbc://admin:P4ssw0rd@db.internal:5432/x", "P4ssw0rd"),
    ("Cookie: session=abc123; other=zzz", "abc123"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----", "MIIBOg"),
    ("AWS_SESSION_TOKEN=FwoGZXIvYXdzEXAMPLETOKEN", "FwoGZXIvYXdz"),
])
def test_sanitize_redacts(raw, secret):
    out = sanitize_text(raw)
    assert secret not in out and "REDACTED" in out


def test_sanitize_keeps_ordinary_text():
    s = "ERROR Unexpected token in JSON at position 4; authentication failure for user bob"
    assert sanitize_text(s) == s


def test_sanitize_truncates_and_recurses():
    assert sanitize_text("x" * 50, 10).startswith("x" * 10 + "...[truncated 40")
    assert sanitize_obj({"a": ["password=abc"], "n": 3})["a"] == ["password=[REDACTED]"]


# --------------------------------------------------------------- timerange
def test_resolve_lookback_and_default():
    tr = resolve_range(lookback="6h", start=None, end=None, default_minutes=60, max_hours=24, now=NOW)
    assert tr.end == NOW and tr.end - tr.start == timedelta(hours=6)
    tr = resolve_range(lookback=None, start=None, end=None, default_minutes=15, max_hours=24, now=NOW)
    assert tr.seconds == 900


def test_resolve_start_end_and_z_suffix():
    tr = resolve_range(lookback=None, start="2026-09-20T10:00:00Z", end="2026-09-20T11:00:00Z",
                       default_minutes=60, max_hours=24, now=NOW)
    assert tr.seconds == 3600


def test_resolve_enforces_max_and_validity():
    with pytest.raises(InputError, match="exceeds"):
        resolve_range(lookback="48h", start=None, end=None, default_minutes=60, max_hours=24, now=NOW)
    with pytest.raises(InputError):
        resolve_range(lookback="banana", start=None, end=None, default_minutes=60, max_hours=24, now=NOW)
    with pytest.raises(InputError):
        resolve_range(lookback=None, start="2026-09-20T11:00:00Z", end="2026-09-20T10:00:00Z",
                      default_minutes=60, max_hours=24, now=NOW)
    with pytest.raises(InputError):
        resolve_range(lookback=None, start=None, end="2026-09-20T10:00:00Z",
                      default_minutes=60, max_hours=24, now=NOW)


# ------------------------------------------------------------------ errors
def _ce(code, op="FilterLogEvents"):
    return ClientError({"Error": {"Code": code, "Message": "boom"}}, op)


@pytest.mark.parametrize("exc,kind", [
    (_ce("AccessDeniedException"), "access_denied"),
    (_ce("ResourceNotFoundException"), "not_found"),
    (_ce("ThrottlingException"), "throttled"),
    (_ce("ExpiredTokenException"), "credentials"),
    (_ce("InvalidParameterException"), "invalid_request"),
    (_ce("SomethingElse"), "aws_error"),
    (NoCredentialsError(), "credentials"),
    (ReadTimeoutError(endpoint_url="https://x"), "timeout"),
    (ConnectTimeoutError(endpoint_url="https://x"), "timeout"),
    (EndpointConnectionError(endpoint_url="https://x"), "network"),
    (InputError("bad"), "invalid_input"),
    (RuntimeError("oops secret=abc"), "internal_error"),
])
def test_describe_exception(exc, kind):
    info = describe_exception(exc)
    assert info.kind == kind
    assert "abc" not in info.message  # internal errors never echo raw exception text


def test_access_denied_names_operation():
    assert "FilterLogEvents" in describe_exception(_ce("AccessDeniedException")).hint


# ------------------------------------------------------------- cache/stats
def test_cache_ttl_and_no_error_caching():
    t = [0.0]
    cache = TTLCache(10, clock=lambda: t[0])
    calls = []
    f = lambda: calls.append(1) or len(calls)  # noqa: E731
    assert cache.get_or_set("k", f) == (1, False)
    assert cache.get_or_set("k", f) == (1, True)
    t[0] = 11
    assert cache.get_or_set("k", f) == (2, False)

    def boom():
        raise RuntimeError
    with pytest.raises(RuntimeError):
        cache.get_or_set("e", boom)
    assert cache.get_or_set("e", lambda: 5) == (5, False)


def test_cache_disabled_when_ttl_zero():
    cache = TTLCache(0)
    assert cache.get_or_set("k", lambda: 1) == (1, False)
    assert cache.get_or_set("k", lambda: 2) == (2, False)


def test_percentiles():
    vals = list(range(1, 101))
    assert percentile(vals, 50) == pytest.approx(50.5)
    assert percentile(vals, 99) == pytest.approx(99.01)
    assert percentile([7], 95) == 7
    assert summarize([]) == {"count": 0}
    assert summarize([1, 2, 3])["max"] == 3
