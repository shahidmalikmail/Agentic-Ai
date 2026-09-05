"""Read-only file system inspection tools, confined to safe roots."""

from __future__ import annotations

import datetime

from .security import iter_files, resolve_safe_path

READABLE_EXTENSIONS = {
    ".txt", ".log", ".json", ".yaml", ".yml", ".py", ".csv",
    ".ini", ".conf", ".cfg", ".md", ".xml", ".html", ".ps1",
}

MAX_READ_CHARS = 12000
MAX_SEARCH_MATCHES = 50


def list_folder(folder_path: str = ".") -> str:
    """List files and folders inside a folder (safe roots only)."""
    try:
        path = resolve_safe_path(folder_path)

        if not path.exists():
            return f"Path does not exist: {path}"
        if not path.is_dir():
            return f"This is not a folder: {path}"

        items = []
        for item in path.iterdir():
            items.append(f"[FOLDER] {item.name}" if item.is_dir() else f"[FILE] {item.name}")

        return "\n".join(sorted(items)) if items else "Folder is empty."

    except PermissionError as e:
        return str(e)
    except Exception as e:
        return f"Error: {e}"


def read_file(file_path: str) -> str:
    """Read a text file (safe roots + allow-listed extensions only)."""
    try:
        path = resolve_safe_path(file_path)

        if not path.exists():
            return f"File does not exist: {path}"
        if not path.is_file():
            return f"This is not a file: {path}"
        if path.suffix.lower() not in READABLE_EXTENSIONS:
            return f"File type {path.suffix} is not supported. Only text files can be read."

        content = path.read_text(encoding="utf-8", errors="replace")
        if len(content) > MAX_READ_CHARS:
            content = content[:MAX_READ_CHARS] + "\n\n[File truncated]"

        return f"File: {path}\n\n{content}"

    except PermissionError as e:
        return str(e)
    except Exception as e:
        return f"Error: {e}"


def file_exists(path_str: str) -> str:
    """Check whether a file or folder exists (safe roots only)."""
    try:
        path = resolve_safe_path(path_str)

        if not path.exists():
            return f"Does not exist: {path}"

        kind = "folder" if path.is_dir() else "file"
        return f"{path} exists ({kind})"

    except PermissionError as e:
        return str(e)
    except Exception as e:
        return f"Error: {e}"


def get_file_metadata(path_str: str) -> str:
    """Return size, timestamps, and type metadata for a file or folder."""
    try:
        path = resolve_safe_path(path_str)

        if not path.exists():
            return f"Path does not exist: {path}"

        stat = path.stat()

        def fmt(ts: float) -> str:
            return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

        return (
            f"Path: {path}\n"
            f"Type: {'folder' if path.is_dir() else 'file'}\n"
            f"Size: {stat.st_size} bytes\n"
            f"Created: {fmt(stat.st_ctime)}\n"
            f"Modified: {fmt(stat.st_mtime)}\n"
            f"Accessed: {fmt(stat.st_atime)}"
        )

    except PermissionError as e:
        return str(e)
    except Exception as e:
        return f"Error: {e}"


def search_in_files(folder_path: str, text: str, extensions: str = "") -> str:
    """
    Search for a text string inside files under a folder (safe roots only).
    `extensions` is an optional comma-separated allow-list, e.g. ".py,.log".
    """
    try:
        path = resolve_safe_path(folder_path)

        if not path.exists() or not path.is_dir():
            return f"Not a valid folder: {path}"

        allowed = {e.strip().lower() for e in extensions.split(",") if e.strip()} or READABLE_EXTENSIONS
        matches = []

        for item in iter_files(path):
            if len(matches) >= MAX_SEARCH_MATCHES:
                break
            if item.suffix.lower() not in allowed:
                continue

            try:
                for line_no, line in enumerate(item.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if text.lower() in line.lower():
                        matches.append(f"{item}:{line_no}: {line.strip()}")
                        if len(matches) >= MAX_SEARCH_MATCHES:
                            break
            except (PermissionError, OSError):
                continue

        if not matches:
            return f"No matches for '{text}' under {path}"

        return "\n".join(matches)

    except PermissionError as e:
        return str(e)
    except Exception as e:
        return f"Error: {e}"
