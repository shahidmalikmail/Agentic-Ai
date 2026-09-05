"""Read-only Windows service inspection tools. No start/stop/restart control."""

from __future__ import annotations

import psutil


def list_services(status_filter: str = "") -> str:
    """List Windows services, optionally filtered by status (e.g. 'running', 'stopped')."""
    try:
        status_filter = status_filter.strip().lower()
        lines = []

        for service in psutil.win_service_iter():
            try:
                info = service.as_dict()
            except Exception:
                continue

            if status_filter and info.get("status", "").lower() != status_filter:
                continue

            lines.append(f"{info['name']} | {info.get('status')} | {info.get('display_name')}")

        return "\n".join(sorted(lines)) if lines else "No matching services found."

    except AttributeError:
        return "Error: Windows service enumeration is only available on Windows."
    except Exception as e:
        return f"Error: {e}"


def get_service_status(service_name: str) -> str:
    """Return detailed status for a single Windows service by name."""
    try:
        service = psutil.win_service_get(service_name)
        info = service.as_dict()

        return (
            f"Name: {info.get('name')}\n"
            f"Display name: {info.get('display_name')}\n"
            f"Status: {info.get('status')}\n"
            f"Start type: {info.get('start_type')}\n"
            f"PID: {info.get('pid')}\n"
            f"Binary path: {info.get('binpath')}\n"
            f"Description: {info.get('description')}"
        )

    except AttributeError:
        return "Error: Windows service enumeration is only available on Windows."
    except Exception as e:
        return f"Service not found or unavailable: {service_name} ({e})"
