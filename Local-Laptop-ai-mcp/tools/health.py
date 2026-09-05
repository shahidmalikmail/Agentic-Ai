"""Read-only laptop health snapshot: CPU, memory, disk, and battery."""

from __future__ import annotations

import shutil

import psutil

CPU_WARN_PCT = 90
MEM_WARN_PCT = 90
DISK_WARN_PCT = 90


def get_health_summary() -> str:
    """Return a quick CPU/memory/disk/battery health snapshot with a status flag."""
    try:
        cpu_pct = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()

        warnings = []
        if cpu_pct >= CPU_WARN_PCT:
            warnings.append(f"High CPU usage: {cpu_pct:.1f}%")
        if mem.percent >= MEM_WARN_PCT:
            warnings.append(f"High memory usage: {mem.percent:.1f}%")

        disk_lines = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = shutil.disk_usage(part.mountpoint)
                pct = usage.used / usage.total * 100 if usage.total else 0
                disk_lines.append(f"{part.device}: {pct:.1f}% used")
                if pct >= DISK_WARN_PCT:
                    warnings.append(f"High disk usage on {part.device}: {pct:.1f}%")
            except (PermissionError, OSError):
                continue

        battery = psutil.sensors_battery()
        battery_line = (
            f"Battery: {battery.percent:.0f}% ({'plugged in' if battery.power_plugged else 'on battery'})"
            if battery else "Battery: not available"
        )

        status = "Warning" if warnings else "Healthy"

        return (
            f"Status: {status}\n"
            f"CPU usage: {cpu_pct:.1f}%\n"
            f"Memory usage: {mem.percent:.1f}%\n"
            + "\n".join(disk_lines) + "\n"
            f"{battery_line}\n"
            + ("Warnings: " + "; ".join(warnings) if warnings else "No warnings.")
        )

    except Exception as e:
        return f"Error: {e}"
