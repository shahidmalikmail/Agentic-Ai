"""Read-only disk and storage inspection tools."""

from __future__ import annotations

import fnmatch
import shutil

import psutil

from .security import iter_files, iter_paths, resolve_safe_path

MAX_LARGE_FILES = 25
MAX_SEARCH_RESULTS = 100


def list_drives() -> str:
    """List all mounted drives with filesystem type and free/used space."""
    try:
        lines = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = shutil.disk_usage(part.mountpoint)
                lines.append(
                    f"{part.device} ({part.fstype}) - "
                    f"Total: {usage.total / (1024**3):.2f} GB, "
                    f"Used: {usage.used / (1024**3):.2f} GB, "
                    f"Free: {usage.free / (1024**3):.2f} GB"
                )
            except (PermissionError, OSError):
                lines.append(f"{part.device} ({part.fstype}) - not accessible")

        return "\n".join(lines) if lines else "No drives found."

    except Exception as e:
        return f"Error: {e}"


def get_disk_usage(drive: str = "C:\\") -> str:
    """Show total, used, and free space for a drive (e.g. 'C:\\')."""
    try:
        total, used, free = shutil.disk_usage(drive)
        return (
            f"Drive: {drive}\n"
            f"Total: {total / (1024**3):.2f} GB\n"
            f"Used: {used / (1024**3):.2f} GB\n"
            f"Free: {free / (1024**3):.2f} GB"
        )
    except Exception as e:
        return f"Error: {e}"


def get_folder_size(folder_path: str) -> str:
    """Calculate the total size of files inside a folder (safe roots only)."""
    try:
        path = resolve_safe_path(folder_path)

        if not path.exists() or not path.is_dir():
            return f"Not a valid folder: {path}"

        total_size = 0
        file_count = 0
        for item in iter_files(path):
            try:
                total_size += item.stat().st_size
                file_count += 1
            except (PermissionError, OSError):
                pass

        return (
            f"Folder: {path}\n"
            f"Files: {file_count}\n"
            f"Total Size: {total_size / (1024**2):.2f} MB\n"
            f"Total Size: {total_size / (1024**3):.2f} GB"
        )

    except PermissionError as e:
        return str(e)
    except Exception as e:
        return f"Error: {e}"


def count_items(folder_path: str, recursive: bool = False) -> str:
    """Count files and subfolders inside a folder (safe roots only)."""
    try:
        path = resolve_safe_path(folder_path)

        if not path.exists() or not path.is_dir():
            return f"Not a valid folder: {path}"

        file_count = 0
        folder_count = 0

        if recursive:
            for _, is_dir in iter_paths(path):
                folder_count += is_dir
                file_count += not is_dir
        else:
            for item in path.iterdir():
                if item.is_dir():
                    folder_count += 1
                elif item.is_file():
                    file_count += 1

        scope = "recursive" if recursive else "top-level"
        return f"Folder: {path} ({scope})\nFiles: {file_count}\nFolders: {folder_count}"

    except PermissionError as e:
        return str(e)
    except Exception as e:
        return f"Error: {e}"


def find_large_files(folder_path: str, min_size_mb: float = 100.0, limit: int = 20) -> str:
    """Find the largest files under a folder above a minimum size (safe roots only)."""
    try:
        path = resolve_safe_path(folder_path)

        if not path.exists() or not path.is_dir():
            return f"Not a valid folder: {path}"

        limit = max(1, min(limit, MAX_LARGE_FILES))
        min_bytes = min_size_mb * 1024 * 1024

        found = []
        for item in iter_files(path):
            try:
                size = item.stat().st_size
                if size >= min_bytes:
                    found.append((size, item))
            except (PermissionError, OSError):
                continue

        found.sort(key=lambda pair: pair[0], reverse=True)
        found = found[:limit]

        if not found:
            return f"No files >= {min_size_mb} MB found under {path}"

        return "\n".join(f"{size / (1024**2):.2f} MB - {item}" for size, item in found)

    except PermissionError as e:
        return str(e)
    except Exception as e:
        return f"Error: {e}"


def search_files(folder_path: str, name_pattern: str) -> str:
    """Search for files/folders by name pattern (glob, e.g. '*.log') under a folder."""
    try:
        path = resolve_safe_path(folder_path)

        if not path.exists() or not path.is_dir():
            return f"Not a valid folder: {path}"

        results = []
        for item, _ in iter_paths(path):
            if fnmatch.fnmatch(item.name, name_pattern):
                results.append(str(item))
                if len(results) >= MAX_SEARCH_RESULTS:
                    break

        return "\n".join(results) if results else f"No matches for '{name_pattern}' under {path}"

    except PermissionError as e:
        return str(e)
    except Exception as e:
        return f"Error: {e}"
