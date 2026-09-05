"""Read-only Windows environment and dev-tool version inspection tools."""

from __future__ import annotations

import os
import shutil
import subprocess

_SECRET_HINTS = ("KEY", "SECRET", "TOKEN", "PASSWORD", "PWD", "CREDENTIAL", "AUTH")


def get_environment_variables() -> str:
    """List environment variables, with likely-sensitive values redacted."""
    try:
        lines = []
        for name, value in sorted(os.environ.items()):
            if any(hint in name.upper() for hint in _SECRET_HINTS):
                value = "***REDACTED***"
            lines.append(f"{name}={value}")

        return "\n".join(lines)

    except Exception as e:
        return f"Error: {e}"


def get_path_entries() -> str:
    """List PATH directories and whether each currently exists."""
    try:
        entries = os.environ.get("PATH", "").split(os.pathsep)
        lines = [f"{'OK' if os.path.isdir(p) else 'MISSING'} - {p}" for p in entries if p]
        return "\n".join(lines) if lines else "PATH is empty."

    except Exception as e:
        return f"Error: {e}"


def get_tool_versions() -> str:
    """Return installed versions of common dev tools (python, node, npm, git)."""
    tools = {
        "python": ["--version"],
        "node": ["--version"],
        "npm": ["--version"],
        "git": ["--version"],
    }

    lines = []
    for exe, args in tools.items():
        path = shutil.which(exe)
        if not path:
            lines.append(f"{exe}: not found")
            continue

        try:
            result = subprocess.run([path] + args, capture_output=True, text=True, timeout=5)
            output = (result.stdout or result.stderr).strip()
            lines.append(f"{exe}: {output}")
        except Exception as e:
            lines.append(f"{exe}: error ({e})")

    return "\n".join(lines)
