"""PROD-only configuration + read-only execution entrypoint for the
isolated eks-prod-commerce MCP server (P12A).

Builds exactly ONE BastionSSHClient, once, from prod_config.load_prod_config()
(unmodified - PROD_BASTION_* only) - the same isolation pattern prod_server.py
already uses for eks-prod-readonly. This module never imports config.py's
DEV/UAT loader and never imports kube_core.py (which itself triggers DEV/UAT
config loading at import time, per kube_core.py's own module-level
`config.load_configs()` call), so no DEV/UAT credential can ever end up in
this process, and this process's PROD credential can never end up in a
DEV/UAT process either.

Design note - surfaced for mentor review, not decided unilaterally (P12A
task instructions: "do not make a final decision ... unless the
implementation requires it"): this reuses the SAME PROD_BASTION_*
credential source (and same bastion/Kubernetes user) as eks-prod-readonly,
rather than introducing new PROD_COMMERCE_* environment variables or a
separate bastion account. Both processes remain exclusively PROD-scoped;
neither ever loads a DEV/UAT credential. This does not modify
prod_config.py, does not modify prod_server.py, and does not change what
credentials PROD infrastructure issues - it only builds a second,
independent BastionSSHClient instance (own process, own object) from the
same already-existing PROD_BASTION_* values. If a tighter blast-radius
boundary (dedicated PROD_COMMERCE_* credentials/bastion account) is wanted,
that is a separate, later decision requiring its own PROD infrastructure
change - not implemented here.

Every kubectl command run through this module still passes through the
existing, unmodified readonly_exec.run_readonly() ->
BastionSSHClient.run_kubectl() -> ssh_client._validate_read_only() chain -
the same read-only trust boundary as every other tool in this repository,
standard, Commerce, or PROD-readonly.
"""
from __future__ import annotations

from prod_config import load_prod_config
from readonly_exec import run_readonly
from ssh_client import BastionSSHClient

# Distinct from eks-prod-readonly's "prod" tag so a response can always be
# told apart by which PROD MCP server produced it.
TAG = "prod-commerce"

# Built once, at import time, exactly like prod_server.py's _prod_ssh -
# never rebuilt per-call, never parameterized by caller input.
_prod_commerce_config = load_prod_config()
_prod_commerce_ssh = BastionSSHClient(_prod_commerce_config)


def run_prod_commerce_readonly(kubectl_command: str) -> str:
    """Run one read-only kubectl command against PROD through the single
    dedicated PROD Commerce BastionSSHClient. Thin wrapper over
    readonly_exec.run_readonly() so prod_commerce_tools.py never touches an
    SSH client, a Config object, or any credential value directly."""
    return run_readonly(_prod_commerce_ssh, kubectl_command, tag=TAG)
