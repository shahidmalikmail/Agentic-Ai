"""Read-only Windows Event Log inspection tools (via pywin32's win32evtlog API)."""

from __future__ import annotations

try:
    import win32evtlog
    import win32evtlogutil
    _PYWIN32_AVAILABLE = True
except ImportError:
    _PYWIN32_AVAILABLE = False

ALLOWED_LOGS = {"Application", "System"}
MAX_EVENTS = 100

_EVENT_TYPE_NAMES = {
    1: "Error",
    2: "Warning",
    4: "Information",
    8: "Audit Success",
    16: "Audit Failure",
}


def get_recent_events(log_name: str = "System", max_events: int = 20, level: str = "") -> str:
    """
    Return the most recent Windows Event Log entries for 'System' or
    'Application' (Security log is intentionally excluded). Optional
    `level` filter: 'error', 'warning', or 'information'.
    """
    if not _PYWIN32_AVAILABLE:
        return "Error: pywin32 is not installed. Run: pip install pywin32"

    if log_name not in ALLOWED_LOGS:
        return f"Error: log_name must be one of {sorted(ALLOWED_LOGS)}"

    max_events = max(1, min(int(max_events), MAX_EVENTS))
    level = level.strip().lower()

    try:
        handle = win32evtlog.OpenEventLog(None, log_name)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        results = []
        while len(results) < max_events:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            if not events:
                break

            for event in events:
                type_name = _EVENT_TYPE_NAMES.get(event.EventType, str(event.EventType))
                if level and level != type_name.lower():
                    continue

                try:
                    message = win32evtlogutil.SafeFormatMessage(event, log_name)
                except Exception:
                    message = "(message unavailable)"

                timestamp = event.TimeGenerated.Format() if event.TimeGenerated else "unknown"
                results.append(
                    f"[{timestamp}] {type_name} | Source: {event.SourceName} | "
                    f"{message.strip()[:300]}"
                )

                if len(results) >= max_events:
                    break

        win32evtlog.CloseEventLog(handle)

        return "\n".join(results) if results else f"No matching events found in '{log_name}'."

    except Exception as e:
        return f"Error reading '{log_name}' log: {e}"
