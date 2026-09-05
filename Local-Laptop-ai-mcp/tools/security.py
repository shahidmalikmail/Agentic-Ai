"""
Path confinement for filesystem-facing tools.

All filesystem tools resolve the caller-supplied path and verify it falls
inside one of the configured "safe roots" before touching disk.

Safe roots can be overridden with the MCP_SAFE_ROOTS environment variable
(a list of paths separated by os.pathsep, i.e. ';' on Windows). When unset,
the default is the full C:\\ and D:\\ drives - read access is intentionally
broad, so the real control point for sensitive locations is the recursive
scan pruning below (EXCLUDED_DIR_NAMES / EXCLUDED_ABSOLUTE_DIRS) plus the
read_file extension allow-list in filesystem.py, not the safe-root boundary
itself. The current Windows user is always resolved dynamically
(Path.home()) - no username is hardcoded.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, List, Tuple

# Directory *names* skipped anywhere during recursive scans (find_large_files,
# search_files, search_in_files, get_folder_size, count_items). Matched
# case-insensitively since these are Windows paths.
EXCLUDED_DIR_NAMES = {
    ".venv", "venv", "env", "__pycache__", ".git", "node_modules",
    "$RECYCLE.BIN", "System Volume Information",
}

# Specific absolute system directories skipped during recursive scans,
# regardless of name matching above - these are large, low-value, and
# potentially sensitive OS/program trees that a diagnostic scan should never
# crawl into now that C:\ and D:\ are full safe roots. Matched
# case-insensitively. Non-recursive tools (list_folder, get_disk_usage)
# still work on these paths directly - only recursive descent is pruned.
EXCLUDED_ABSOLUTE_DIRS = {
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
}
_EXCLUDED_ABSOLUTE_NORMALIZED = {os.path.normcase(p) for p in EXCLUDED_ABSOLUTE_DIRS}
_EXCLUDED_DIR_NAMES_LOWER = {name.lower() for name in EXCLUDED_DIR_NAMES}

# Hard cap on items visited per recursive scan, so a very large safe root
# (a full drive) can't turn a diagnostic call into a long-running or
# effectively unbounded filesystem walk.
MAX_SCAN_ITEMS = 50000


def _is_excluded_absolute(path: Path) -> bool:
    return os.path.normcase(str(path)) in _EXCLUDED_ABSOLUTE_NORMALIZED


def _default_roots() -> List[Path]:
    roots: List[Path] = []

    for drive in ("C:/", "D:/"):
        path = Path(drive)
        if path.exists():
            roots.append(path.resolve())

    return roots


def _roots_from_env() -> List[Path] | None:
    raw = os.environ.get("MCP_SAFE_ROOTS")
    if not raw:
        return None

    roots = []
    for part in raw.split(os.pathsep):
        part = part.strip()
        if not part:
            continue
        path = Path(part)
        if path.exists():
            roots.append(path.resolve())

    return roots or None


SAFE_ROOTS: List[Path] = _roots_from_env() or _default_roots()


def resolve_safe_path(user_path: str) -> Path:
    """
    Resolve a user-supplied path and confirm it is inside an allowed
    safe root. Raises PermissionError if the path escapes every root.
    """

    candidate = Path(user_path).expanduser().resolve()

    for root in SAFE_ROOTS:
        if candidate == root or candidate.is_relative_to(root):
            return candidate

    allowed = ", ".join(str(r) for r in SAFE_ROOTS)
    raise PermissionError(
        f"Access denied: '{candidate}' is outside the allowed safe roots. "
        f"Allowed roots: {allowed}"
    )


def iter_paths(root: Path, max_items: int = MAX_SCAN_ITEMS) -> Iterator[Tuple[Path, bool]]:
    """
    Yield (path, is_dir) for every file and folder under root, pruning
    EXCLUDED_DIR_NAMES and stopping after max_items entries.
    """
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        dirnames[:] = [
            d for d in dirnames
            if d.lower() not in _EXCLUDED_DIR_NAMES_LOWER and not _is_excluded_absolute(base / d)
        ]

        for name in dirnames:
            yield base / name, True
            count += 1
            if count >= max_items:
                return

        for name in filenames:
            yield base / name, False
            count += 1
            if count >= max_items:
                return


def iter_files(root: Path, max_items: int = MAX_SCAN_ITEMS) -> Iterator[Path]:
    """Yield every file under root, pruning EXCLUDED_DIR_NAMES, capped at max_items."""
    for path, is_dir in iter_paths(root, max_items=max_items):
        if not is_dir:
            yield path
