"""Read-only Windows process inspection tools. No process control (no kill/terminate)."""

from __future__ import annotations

import psutil

MAX_LIST_LIMIT = 100


def list_processes(limit: int = 20, sort_by: str = "memory") -> str:
    """List top running processes sorted by 'memory' or 'cpu'."""
    try:
        limit = max(1, min(limit, MAX_LIST_LIMIT))
        sort_by = sort_by.lower()

        procs = []
        for proc in psutil.process_iter(["pid", "name", "memory_percent", "cpu_percent"]):
            try:
                procs.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        key = "cpu_percent" if sort_by == "cpu" else "memory_percent"
        procs.sort(key=lambda p: p.get(key) or 0, reverse=True)
        procs = procs[:limit]

        lines = [
            f"PID {p['pid']:>6} | CPU {p.get('cpu_percent') or 0:5.1f}% | "
            f"MEM {p.get('memory_percent') or 0:5.1f}% | {p.get('name')}"
            for p in procs
        ]
        return "\n".join(lines) if lines else "No processes found."

    except Exception as e:
        return f"Error: {e}"


def find_process(name: str) -> str:
    """Find running processes whose name contains the given substring."""
    try:
        needle = name.lower()
        matches = []

        for proc in psutil.process_iter(["pid", "name", "status"]):
            try:
                if needle in (proc.info.get("name") or "").lower():
                    matches.append(f"PID {proc.info['pid']:>6} | {proc.info.get('status')} | {proc.info.get('name')}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return "\n".join(matches) if matches else f"No process found matching '{name}'"

    except Exception as e:
        return f"Error: {e}"


def get_process_info(pid: int) -> str:
    """Return detailed diagnostic info for a single process by PID."""
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            mem = proc.memory_info()
            created = proc.create_time()

        import datetime
        created_str = datetime.datetime.fromtimestamp(created).strftime("%Y-%m-%d %H:%M:%S")

        return (
            f"PID: {proc.pid}\n"
            f"Name: {proc.name()}\n"
            f"Status: {proc.status()}\n"
            f"CPU: {proc.cpu_percent(interval=0.2):.1f}%\n"
            f"Memory: {mem.rss / (1024**2):.2f} MB\n"
            f"Threads: {proc.num_threads()}\n"
            f"Executable: {proc.exe() if proc.pid != 0 else 'N/A'}\n"
            f"Started: {created_str}"
        )

    except psutil.NoSuchProcess:
        return f"No process found with PID {pid}"
    except psutil.AccessDenied:
        return f"Access denied reading process {pid}"
    except Exception as e:
        return f"Error: {e}"
