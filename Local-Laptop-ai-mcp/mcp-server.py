from pathlib import Path
import shutil

from mcp.server.fastmcp import FastMCP


# Create MCP Server
mcp = FastMCP("Windows AI Server")


# =========================================================
# TOOL 1 - LIST FOLDER
# =========================================================

@mcp.tool()
def list_folder(folder_path: str = ".") -> str:
    """
    List files and folders inside a Windows folder.
    """

    try:
        path = Path(folder_path).resolve()

        if not path.exists():
            return f"Path does not exist: {path}"

        if not path.is_dir():
            return f"This is not a folder: {path}"

        items = []

        for item in path.iterdir():

            if item.is_dir():
                items.append(f"[FOLDER] {item.name}")
            else:
                items.append(f"[FILE] {item.name}")

        if not items:
            return "Folder is empty."

        return "\n".join(sorted(items))

    except Exception as e:
        return f"Error: {e}"


# =========================================================
# TOOL 2 - FILE SIZE
# =========================================================

@mcp.tool()
def get_file_size(file_path: str) -> str:
    """
    Get the size of a file.
    """

    try:
        path = Path(file_path).resolve()

        if not path.exists():
            return f"File does not exist: {path}"

        if not path.is_file():
            return f"This is not a file: {path}"

        size_bytes = path.stat().st_size
        size_mb = size_bytes / (1024 * 1024)

        return (
            f"File: {path}\n"
            f"Size: {size_bytes} bytes\n"
            f"Size: {size_mb:.2f} MB"
        )

    except Exception as e:
        return f"Error: {e}"


# =========================================================
# TOOL 3 - FOLDER SIZE
# =========================================================

@mcp.tool()
def get_folder_size(folder_path: str) -> str:
    """
    Calculate the total size of a folder.
    """

    try:
        path = Path(folder_path).resolve()

        if not path.exists():
            return f"Folder does not exist: {path}"

        if not path.is_dir():
            return f"This is not a folder: {path}"

        total_size = 0
        file_count = 0

        for item in path.rglob("*"):

            if item.is_file():

                try:
                    total_size += item.stat().st_size
                    file_count += 1

                except (PermissionError, OSError):
                    pass

        size_mb = total_size / (1024 * 1024)
        size_gb = total_size / (1024 * 1024 * 1024)

        return (
            f"Folder: {path}\n"
            f"Files: {file_count}\n"
            f"Size: {size_mb:.2f} MB\n"
            f"Size: {size_gb:.2f} GB"
        )

    except Exception as e:
        return f"Error: {e}"


# =========================================================
# TOOL 4 - READ FILE
# =========================================================

@mcp.tool()
def read_file(file_path: str) -> str:
    """
    Read a text file.
    """

    allowed_extensions = {
        ".txt",
        ".log",
        ".json",
        ".yaml",
        ".yml",
        ".py",
        ".csv",
        ".ini",
        ".conf",
        ".md",
        ".xml",
        ".html",
        ".ps1"
    }

    try:

        path = Path(file_path).resolve()

        if not path.exists():
            return f"File does not exist: {path}"

        if not path.is_file():
            return f"This is not a file: {path}"

        if path.suffix.lower() not in allowed_extensions:
            return (
                f"File type {path.suffix} is not supported. "
                "Only text files can be read."
            )

        content = path.read_text(
            encoding="utf-8",
            errors="replace"
        )

        # Prevent very large files being returned
        # to the LLM.
        if len(content) > 12000:

            content = content[:12000]

            content += "\n\n[File truncated]"

        return f"File: {path}\n\n{content}"

    except Exception as e:
        return f"Error: {e}"


# =========================================================
# TOOL 5 - DISK USAGE
# =========================================================

@mcp.tool()
def get_disk_usage(drive: str = "C:\\") -> str:
    """
    Show disk total, used and free space.
    """

    try:

        total, used, free = shutil.disk_usage(drive)

        total_gb = total / (1024 ** 3)
        used_gb = used / (1024 ** 3)
        free_gb = free / (1024 ** 3)

        return (
            f"Drive: {drive}\n"
            f"Total: {total_gb:.2f} GB\n"
            f"Used: {used_gb:.2f} GB\n"
            f"Free: {free_gb:.2f} GB"
        )

    except Exception as e:
        return f"Error: {e}"


# =========================================================
# START MCP SERVER
# =========================================================

if __name__ == "__main__":
    mcp.run()