"""SSH transport to the bastion host, with a read-only command guard.

This module is intentionally the ONLY place that opens a network
connection to the bastion and executes remote commands. Every command
passed through `BastionSSHClient.run()` is checked against an allow-list
of read-only kubectl/aws subcommands before it is sent - this is a
defense-in-depth safety net independent of what kubernetes_monitor.py
chooses to run.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import paramiko

from app.config import BastionConfig

logger = logging.getLogger(__name__)


class BastionConnectionError(Exception):
    """Raised when the SSH connection to the bastion cannot be established."""


class ReadOnlyViolation(Exception):
    """Raised when a command does not match the read-only allow-list."""


class CommandTimeoutError(Exception):
    """Raised when a remote command exceeds its timeout."""


class RemoteCommandError(Exception):
    """Raised when a remote command exits non-zero."""


# Only these read-only subcommands may ever be executed on the bastion.
_ALLOWED_PATTERN = re.compile(
    r"^\s*("
    r"kubectl\s+(get|describe|top|version|cluster-info|explain|api-resources|api-versions)\b"
    r"|aws\s+(eks\s+(describe-cluster|list-clusters)|sts\s+get-caller-identity)\b"
    r")",
    re.IGNORECASE,
)

# Explicit deny-list as a second, independent guard against mutating verbs
# appearing anywhere in the command (including via shell chaining).
_FORBIDDEN_PATTERN = re.compile(
    r"\b(delete|scale|apply|patch|edit|replace|drain|cordon|uncordon|exec|cp|attach|"
    r"create|annotate|label|taint|rollout\s+(restart|undo)|set\s+(image|env)|expose)\b",
    re.IGNORECASE,
)

_SHELL_CHAIN_PATTERN = re.compile(r"[;&|`$]|\n")


@dataclass
class CommandResult:
    command: str
    stdout: str
    stderr: str
    exit_code: int

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def _validate_read_only(command: str) -> None:
    if _SHELL_CHAIN_PATTERN.search(command):
        raise ReadOnlyViolation(f"Command contains shell chaining/metacharacters, rejected: {command!r}")
    if _FORBIDDEN_PATTERN.search(command):
        raise ReadOnlyViolation(f"Command matches a forbidden mutating verb, rejected: {command!r}")
    if not _ALLOWED_PATTERN.match(command):
        raise ReadOnlyViolation(f"Command is not on the read-only allow-list, rejected: {command!r}")


class BastionSSHClient:
    """Context-managed SSH client for the bastion host."""

    def __init__(self, config: BastionConfig):
        self._config = config
        self._client: paramiko.SSHClient | None = None

    def __enter__(self) -> "BastionSSHClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def connect(self) -> None:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            connect_kwargs = dict(
                hostname=self._config.host,
                port=self._config.port,
                username=self._config.username,
                timeout=self._config.connect_timeout,
                banner_timeout=self._config.connect_timeout,
                auth_timeout=self._config.connect_timeout,
            )
            if self._config.key_path:
                connect_kwargs["key_filename"] = self._config.key_path
            elif self._config.password:
                connect_kwargs["password"] = self._config.password
            else:
                raise BastionConnectionError("No SSH key or password configured for bastion auth")

            client.connect(**connect_kwargs)
        except (paramiko.SSHException, OSError) as exc:
            raise BastionConnectionError(f"Failed to connect to bastion {self._config.host}: {exc}") from exc

        self._client = client
        logger.info("[SSH] Connected to bastion")

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def run(self, command: str, timeout: int | None = None) -> CommandResult:
        if self._client is None:
            raise BastionConnectionError("SSH client is not connected")

        _validate_read_only(command)
        effective_timeout = timeout or self._config.command_timeout

        try:
            _stdin, stdout, stderr = self._client.exec_command(command, timeout=effective_timeout)
            exit_code = stdout.channel.recv_exit_status()
            out_text = stdout.read().decode("utf-8", errors="replace")
            err_text = stderr.read().decode("utf-8", errors="replace")
        except paramiko.SSHException as exc:
            raise CommandTimeoutError(f"Command timed out or failed on bastion: {command!r} ({exc})") from exc
        except OSError as exc:
            raise CommandTimeoutError(f"Command timed out on bastion: {command!r} ({exc})") from exc

        return CommandResult(command=command, stdout=out_text, stderr=err_text, exit_code=exit_code)

    def run_or_raise(self, command: str, timeout: int | None = None) -> CommandResult:
        result = self.run(command, timeout=timeout)
        if not result.ok:
            raise RemoteCommandError(
                f"Command failed (exit {result.exit_code}): {command!r} stderr={result.stderr.strip()!r}"
            )
        return result
