"""SSH transport to the bastion host.

This module is the ONLY place that opens a network connection and runs a
remote command. Every command passed to `run_kubectl()` is re-validated
against a strict read-only allow-list here, independent of the fact that
server.py only ever builds commands from a fixed set of tools. This is a
defense-in-depth safety net, not the primary control.
"""
from __future__ import annotations

import logging
import re
import shlex
import socket
from dataclasses import dataclass

import paramiko

from config import Config

logger = logging.getLogger(__name__)


class BastionConnectionError(Exception):
    """Raised when the SSH connection to the bastion cannot be established."""


class ReadOnlyViolation(Exception):
    """Raised when a command does not match the read-only allow-list."""


class CommandTimeoutError(Exception):
    """Raised when a remote command exceeds its timeout."""


class RemoteCommandError(Exception):
    """Raised when a remote command exits non-zero."""


# Only these read-only kubectl subcommands may ever be executed: "get",
# "cluster-info", "version", "api-resources", "logs". This is intentionally
# narrower than the tool set even needs, so any bug in server.py's command
# construction still cannot reach a mutating verb.
_ALLOWED_PATTERN = re.compile(
    r"^kubectl\s+(get|cluster-info|version|api-resources|logs)\b", re.IGNORECASE
)

_FORBIDDEN_PATTERN = re.compile(
    r"\b(delete|apply|create|patch|edit|replace|scale|rollout|exec|port-forward|cp|"
    r"cordon|drain|uncordon|label|annotate|taint|expose|attach|debug|proxy|"
    r"set\s+(image|env)|auth\s+can-i)\b",
    re.IGNORECASE,
)

# kubectl commands built by server.py never need shell metacharacters.
_SHELL_METACHAR_PATTERN = re.compile(r"[;&|`$(){}<>\n\\]")

_PPK_HEADER = b"PuTTY-User-Key-File-"


def _validate_read_only(kubectl_command: str) -> None:
    if _SHELL_METACHAR_PATTERN.search(kubectl_command):
        raise ReadOnlyViolation(f"Command contains shell metacharacters, rejected: {kubectl_command!r}")
    if _FORBIDDEN_PATTERN.search(kubectl_command):
        raise ReadOnlyViolation(f"Command matches a forbidden mutating verb, rejected: {kubectl_command!r}")
    if not _ALLOWED_PATTERN.match(kubectl_command):
        raise ReadOnlyViolation(f"Command is not on the read-only allow-list, rejected: {kubectl_command!r}")


def _looks_like_putty_ppk(key_path: str) -> bool:
    try:
        with open(key_path, "rb") as f:
            header = f.read(len(_PPK_HEADER))
        return header == _PPK_HEADER
    except OSError:
        return False


@dataclass
class CommandResult:
    command: str
    stdout: str
    stderr: str
    exit_code: int

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class BastionSSHClient:
    """One-shot SSH connection per command. Simple and stateless."""

    def __init__(self, config: Config):
        self._config = config

    def run_kubectl(self, kubectl_command: str) -> CommandResult:
        _validate_read_only(kubectl_command)

        remote_command = (
            f"sudo -u {shlex.quote(self._config.kubernetes_user)} -H bash -lc "
            f"{shlex.quote(kubectl_command)}"
        )

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self._connect(client)
            try:
                _stdin, stdout, stderr = client.exec_command(
                    remote_command, timeout=self._config.command_timeout
                )
                exit_code = stdout.channel.recv_exit_status()
                out_text = stdout.read().decode("utf-8", errors="replace")
                err_text = stderr.read().decode("utf-8", errors="replace")
            except (socket.timeout, paramiko.SSHException) as exc:
                raise CommandTimeoutError(
                    f"kubectl command timed out after {self._config.command_timeout}s. "
                    "Check bastion load or VPN latency."
                ) from exc
        finally:
            client.close()

        logger.info("kubectl command completed: exit=%s", exit_code)
        return CommandResult(command=kubectl_command, stdout=out_text, stderr=err_text, exit_code=exit_code)

    def _connect(self, client: paramiko.SSHClient) -> None:
        cfg = self._config
        try:
            client.connect(
                hostname=cfg.bastion_host,
                port=cfg.bastion_port,
                username=cfg.bastion_user,
                key_filename=cfg.bastion_key_path,
                timeout=cfg.ssh_timeout,
                banner_timeout=cfg.ssh_timeout,
                auth_timeout=cfg.ssh_timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        except paramiko.SSHException as exc:
            if _looks_like_putty_ppk(cfg.bastion_key_path):
                raise BastionConnectionError(
                    "Paramiko could not load this key, and it looks like a PuTTY .ppk "
                    "file. Paramiko does not reliably support PPK format. Convert the "
                    "key to OpenSSH format with PuTTYgen (Conversions > Export OpenSSH "
                    "key) and point BASTION_KEY_PATH at the converted file."
                ) from exc
            raise BastionConnectionError(
                f"Failed to authenticate to bastion {cfg.bastion_host}: {exc}"
            ) from exc
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
            raise BastionConnectionError(
                f"Could not reach bastion {cfg.bastion_host}:{cfg.bastion_port} within "
                f"{cfg.ssh_timeout}s. Check that the VPN is connected and the host/port "
                f"are correct. ({exc})"
            ) from exc
