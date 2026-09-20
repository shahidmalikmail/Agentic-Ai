"""Regression tests for the log formatter's sanitization scope.

Bug found during real-AWS validation: botocore's benign line
"botocore.credentials: Found credentials in shared credentials file" came out as
"[REDACTED] credentials in shared ..." because the logger-name header was sanitized too.
Fix: sanitize only the message body and traceback text; keep redacting real secrets there.
"""
import logging
import sys

import pytest

from aws_cw_mcp.server import _SanitizingFormatter, _configure_logging

FMT_HEADER = "%(asctime)s %(levelname)s %(name)s: %(message)s"
BOTOCORE_MSG = "Found credentials in shared credentials file: ~/.aws/credentials"


def _record(name="botocore.credentials", msg=BOTOCORE_MSG, args=None, level=logging.INFO,
            exc_info=None, stack_info=None):
    return logging.LogRecord(name, level, __file__, 1, msg, args, exc_info, sinfo=stack_info)


def _format(**kw):
    return _SanitizingFormatter(FMT_HEADER).format(_record(**kw))


# ------------------------------------------------------- the exact regression
def test_botocore_found_credentials_message_is_not_mangled():
    out = _format()
    assert out.endswith("INFO botocore.credentials: Found credentials in shared credentials file: "
                        "~/.aws/credentials")
    assert "REDACTED" not in out


def test_botocore_message_through_the_real_configured_handler(capsys):
    _configure_logging("INFO")
    logging.getLogger("botocore.credentials").info(BOTOCORE_MSG)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "botocore.credentials: Found credentials in shared credentials file" in captured.err
    assert "REDACTED" not in captured.err


def test_header_fields_are_never_sanitized():
    # logger names containing credential-like words must survive intact
    for name in ("botocore.credentials", "app.password", "x.secret_token"):
        out = _format(name=name, msg="plain benign message")
        assert f"INFO {name}: plain benign message" in out, out


# ----------------------------- real secrets in the MESSAGE BODY are still redacted
@pytest.mark.parametrize("msg,secret", [
    ("login failed password=hunter2 for user bob", "hunter2"),
    ("using key AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"),
    ("Authorization: Bearer abcdef1234567890", "abcdef1234567890"),
    ("AWS_SESSION_TOKEN=FwoGZXIvYXdzSESSIONTOKENVALUE", "SESSIONTOKENVALUE"),
    ("db url jdbc://admin:P4ssw0rd@db.internal/x", "P4ssw0rd"),
    ("Cookie: session=abc123", "abc123"),
])
def test_secrets_in_message_body_are_still_redacted(msg, secret):
    out = _format(msg=msg)
    assert secret not in out and "REDACTED" in out
    assert out.count("INFO botocore.credentials: ") == 1  # header intact


def test_secret_in_a_message_that_mentions_credentials_is_redacted_but_words_kept():
    out = _format(msg="Found credentials in file, credentials: s3cr3tvalue")
    assert "s3cr3tvalue" not in out
    assert out.count("Found credentials in file") == 1


def test_secrets_passed_as_format_args_are_redacted():
    out = _format(msg="request failed: %s (attempt %d)", args=("password=hunter2", 3))
    assert "hunter2" not in out and "attempt 3" in out


# -------------------------------------------------------------- tracebacks
def test_traceback_text_is_sanitized_but_still_shown():
    try:
        raise RuntimeError("boom password=hunter2 AKIAIOSFODNN7EXAMPLE")
    except RuntimeError:
        out = _format(name="aws-cloudwatch-mcp", msg="tool failed", exc_info=sys.exc_info())
    assert "Traceback (most recent call last)" in out and "RuntimeError" in out
    assert "hunter2" not in out and "AKIAIOSFODNN7EXAMPLE" not in out


def test_stack_info_is_sanitized():
    out = _format(msg="ctx", stack_info="Stack (most recent call last):\n  token=abc123secret")
    assert "abc123secret" not in out and "Stack (most recent call last)" in out


# ------------------------------------------------------------- no side effects
def test_formatting_does_not_mutate_the_shared_record():
    rec = _record(msg="failed %s", args=("password=hunter2",))
    _SanitizingFormatter(FMT_HEADER).format(rec)
    assert rec.msg == "failed %s" and rec.args == ("password=hunter2",)
    assert rec.exc_text is None and rec.stack_info is None
