"""
Read-only Windows network diagnostic tools.

Subprocess calls here use fixed argument lists (no shell=True, no string
concatenation into a shell command) and validate any user-supplied host
value against an allow-list pattern before it is ever passed to a
subprocess, to prevent command/argument injection.
"""

from __future__ import annotations

import re
import socket
import subprocess

import psutil

_HOST_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.\-:]{0,253})$")


def _validate_host(host: str) -> str:
    host = host.strip()
    if not host or not _HOST_PATTERN.match(host):
        raise ValueError(f"Invalid host/IP: '{host}'")
    return host


def get_network_info() -> str:
    """Return hostname, local IP addresses, and network adapter status."""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        lines = [f"Hostname: {hostname}", f"Local IP: {local_ip}", "", "Adapters:"]

        stats = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            is_up = stats[name].isup if name in stats else "unknown"
            ip_list = [a.address for a in addrs if a.family == socket.AF_INET]
            lines.append(f"- {name} | up={is_up} | IPv4: {', '.join(ip_list) or 'none'}")

        return "\n".join(lines)

    except Exception as e:
        return f"Error: {e}"


def get_dns_info() -> str:
    """Return configured DNS servers per adapter (via 'ipconfig /all', fixed args)."""
    try:
        result = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        lines = result.stdout.splitlines()
        relevant = []
        capture_next = False

        for line in lines:
            stripped = line.strip()
            if "Adapter" in line and ":" in line:
                relevant.append(line.strip())
            if "DNS Servers" in line:
                relevant.append(stripped)
                capture_next = True
                continue
            if capture_next and stripped and ":" not in stripped:
                relevant.append(stripped)
            else:
                capture_next = False

        return "\n".join(relevant) if relevant else "No DNS configuration found."

    except Exception as e:
        return f"Error: {e}"


def ping_host(host: str, count: int = 4) -> str:
    """Ping a host or IP address (fixed-argument subprocess, validated host)."""
    try:
        host = _validate_host(host)
        count = max(1, min(int(count), 10))

        result = subprocess.run(
            ["ping", "-n", str(count), host],
            capture_output=True,
            text=True,
            timeout=count * 3 + 5,
        )
        return result.stdout or result.stderr

    except ValueError as e:
        return f"Error: {e}"
    except subprocess.TimeoutExpired:
        return f"Ping to {host} timed out."
    except Exception as e:
        return f"Error: {e}"


def check_port(host: str, port: int, timeout: float = 2.0) -> str:
    """Check whether a TCP port on a host is open (pure socket connect, no subprocess)."""
    try:
        host = _validate_host(host)
        port = int(port)
        if not (0 < port < 65536):
            return f"Error: invalid port {port}"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(max(0.5, min(timeout, 10.0)))
            result = sock.connect_ex((host, port))

        return f"{host}:{port} is {'OPEN' if result == 0 else 'CLOSED/unreachable'}"

    except ValueError as e:
        return f"Error: {e}"
    except Exception as e:
        return f"Error: {e}"


def get_routing_info() -> str:
    """Return the local routing table (via 'route print', fixed no-argument command)."""
    try:
        result = subprocess.run(
            ["route", "print"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout or result.stderr

    except Exception as e:
        return f"Error: {e}"
