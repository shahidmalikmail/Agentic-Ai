"""Read-only Windows system information tools."""

from __future__ import annotations

import datetime
import platform
import socket

import psutil


def get_os_info() -> str:
    """Return OS name, version, build, architecture, and hostname."""
    try:
        return (
            f"Hostname: {socket.gethostname()}\n"
            f"OS: {platform.system()} {platform.release()}\n"
            f"Version: {platform.version()}\n"
            f"Architecture: {platform.machine()}\n"
            f"Processor: {platform.processor()}\n"
            f"Python: {platform.python_version()}"
        )
    except Exception as e:
        return f"Error: {e}"


def get_cpu_info() -> str:
    """Return CPU identity, core counts, and current utilization."""
    try:
        freq = psutil.cpu_freq()
        freq_line = f"{freq.current:.0f} MHz (max {freq.max:.0f} MHz)" if freq else "unavailable"

        return (
            f"Processor: {platform.processor()}\n"
            f"Physical cores: {psutil.cpu_count(logical=False)}\n"
            f"Logical cores: {psutil.cpu_count(logical=True)}\n"
            f"Frequency: {freq_line}\n"
            f"Current usage: {psutil.cpu_percent(interval=0.5):.1f}%"
        )
    except Exception as e:
        return f"Error: {e}"


def get_memory_info() -> str:
    """Return total, used, available RAM and swap usage."""
    try:
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        return (
            f"RAM Total: {mem.total / (1024**3):.2f} GB\n"
            f"RAM Used: {mem.used / (1024**3):.2f} GB ({mem.percent}%)\n"
            f"RAM Available: {mem.available / (1024**3):.2f} GB\n"
            f"Swap/Pagefile Total: {swap.total / (1024**3):.2f} GB\n"
            f"Swap/Pagefile Used: {swap.used / (1024**3):.2f} GB ({swap.percent}%)"
        )
    except Exception as e:
        return f"Error: {e}"


def get_uptime() -> str:
    """Return system boot time and elapsed uptime."""
    try:
        boot_ts = psutil.boot_time()
        boot_time = datetime.datetime.fromtimestamp(boot_ts)
        uptime = datetime.datetime.now() - boot_time

        days, rem = divmod(int(uptime.total_seconds()), 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _ = divmod(rem, 60)

        return (
            f"Boot time: {boot_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Uptime: {days}d {hours}h {minutes}m"
        )
    except Exception as e:
        return f"Error: {e}"
