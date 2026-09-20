"""Error classification: turn AWS/botocore failures into explicit, honest results."""
from __future__ import annotations

from dataclasses import dataclass

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    NoCredentialsError,
    NoRegionError,
    PartialCredentialsError,
    ProfileNotFound,
    ReadTimeoutError,
)

from aws_cw_mcp.config import ConfigError
from aws_cw_mcp.utils.sanitize import sanitize_text


class ToolError(Exception):
    """Base for expected, user-presentable errors."""
    kind = "error"


class InputError(ToolError):
    """The caller supplied an invalid argument."""
    kind = "invalid_input"


class ReadOnlyViolation(ToolError):
    """An AWS operation outside the read-only allow-list was attempted."""
    kind = "read_only_violation"


class AccountMismatch(ToolError):
    kind = "account_mismatch"


@dataclass(frozen=True)
class ErrorInfo:
    kind: str
    code: str
    message: str
    hint: str = ""

    def as_dict(self) -> dict:
        d = {"kind": self.kind, "code": self.code, "message": self.message}
        if self.hint:
            d["hint"] = self.hint
        return d


_ACCESS = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError",
           "UnauthorizedAccess", "NotAuthorized"}
_NOT_FOUND = {"ResourceNotFoundException", "ResourceNotFound", "NoSuchEntity", "NotFound",
              "NoSuchBucket", "ResourceNotFoundFault"}
_THROTTLE = {"ThrottlingException", "Throttling", "ThrottledException", "TooManyRequestsException",
             "RequestLimitExceeded", "LimitExceededException", "ServiceUnavailable",
             "ServiceUnavailableException", "RequestThrottled", "SlowDown", "Throttled"}
_CREDS = {"ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId",
          "UnrecognizedClientException", "InvalidSignatureException", "SignatureDoesNotMatch",
          "AuthFailure", "InvalidToken"}
_INVALID = {"InvalidParameterException", "InvalidParameterValue", "InvalidParameterValueException",
            "ValidationError", "ValidationException", "MalformedQueryString", "InvalidNextToken",
            "InvalidParameterCombination", "InvalidFormat", "MissingParameter"}


def describe_exception(exc: BaseException) -> ErrorInfo:
    if isinstance(exc, ToolError):
        return ErrorInfo(exc.kind, type(exc).__name__, sanitize_text(str(exc), 1000))
    if isinstance(exc, ConfigError):
        return ErrorInfo("configuration", "ConfigError", sanitize_text(str(exc), 1000))
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        code = err.get("Code", "Unknown")
        msg = sanitize_text(err.get("Message", str(exc)), 600)
        op = getattr(exc, "operation_name", "") or "the operation"
        if code in _ACCESS:
            return ErrorInfo("access_denied", code, msg,
                             f"The IAM identity lacks permission for {op}. No data was returned. "
                             "See docs/IAM-REQUIRED-PHASE1.md for the required read-only permissions.")
        if code in _NOT_FOUND:
            return ErrorInfo("not_found", code, msg,
                             "The resource does not exist in this account/region, or is spelled differently.")
        if code in _THROTTLE:
            return ErrorInfo("throttled", code, msg,
                             "AWS throttled the request after automatic retries. "
                             "Retry later or narrow the query.")
        if code in _CREDS:
            return ErrorInfo("credentials", code, msg,
                             "AWS credentials are invalid or expired. Check the AWS CLI profile (aws sts get-caller-identity --profile <name>).")
        if code in _INVALID:
            return ErrorInfo("invalid_request", code, msg)
        return ErrorInfo("aws_error", code, msg)
    if isinstance(exc, (NoCredentialsError, PartialCredentialsError)):
        return ErrorInfo("credentials", type(exc).__name__,
                         "No usable AWS credentials found via the standard provider chain.",
                         "Set AWS_PROFILE to a configured AWS CLI profile (aws configure --profile <name>). "
                         "Never put access keys in source code or .env.")
    if isinstance(exc, ProfileNotFound):
        return ErrorInfo("configuration", "ProfileNotFound", sanitize_text(str(exc), 300))
    if isinstance(exc, NoRegionError):
        return ErrorInfo("configuration", "NoRegionError", "No AWS region configured (set AWS_REGION).")
    if isinstance(exc, (ReadTimeoutError, ConnectTimeoutError)):
        return ErrorInfo("timeout", type(exc).__name__, "The AWS API call timed out.",
                         "Retry, or narrow the time range / filters.")
    if isinstance(exc, EndpointConnectionError):
        return ErrorInfo("network", "EndpointConnectionError",
                         "Could not reach the AWS endpoint (network/VPC endpoint/region problem).")
    if isinstance(exc, BotoCoreError):
        return ErrorInfo("aws_error", type(exc).__name__, sanitize_text(str(exc), 400))
    return ErrorInfo("internal_error", type(exc).__name__,
                     "Unexpected internal error; details are in the server's stderr log.")
