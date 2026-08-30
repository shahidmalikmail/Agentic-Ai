from langchain_ollama import ChatOllama
from langchain_core.tools import tool
from langchain.agents import create_agent

from pathlib import Path


# =========================================================
# SYSTEM PROMPT
# =========================================================

SYSTEM_PROMPT = """
You are a Windows Computer Assistant.

You can help the user inspect their Windows laptop.

You can:
1. List files and folders
2. Read text files
3. Check file size
4. Check folder size

IMPORTANT:
- Do NOT delete files.
- Do NOT modify files.
- Do NOT rename files.
- Do NOT move files.
- Do NOT execute Windows commands.
- These tools are READ-ONLY.

Keep your answers simple and short.
"""


# =========================================================
# TOOL 1 - LIST FOLDER
# =========================================================

@tool
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

@tool
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

@tool
def get_folder_size(folder_path: str) -> str:
    """
    Calculate the total size of files inside a folder.
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
            f"Total Size: {size_mb:.2f} MB\n"
            f"Total Size: {size_gb:.2f} GB"
        )

    except Exception as e:

        return f"Error: {e}"


# =========================================================
# TOOL 4 - READ FILE
# =========================================================

@tool
def read_file(file_path: str) -> str:
    """
    Read an existing text file.
    """

    try:
        path = Path(file_path).resolve()

        if not path.exists():
            return f"File does not exist: {path}"

        if not path.is_file():
            return f"This is not a file: {path}"

        # Read the file
        content = path.read_text(
            encoding="utf-8",
            errors="replace"
        )

        # Don't send a huge file to the AI
        if len(content) > 12000:

            content = content[:12000]

            content += "\n\n[File truncated]"

        return (
            f"File: {path}\n\n"
            f"{content}"
        )

    except Exception as e:

        return f"Error: {e}"


# =========================================================
# CREATE LLM
# =========================================================

model = ChatOllama(
    model="minimax-m3:cloud",
    temperature=0.2
)


# =========================================================
# TOOLS
# =========================================================

tools = [
    list_folder,
    get_file_size,
    get_folder_size,
    read_file
]


# =========================================================
# CREATE AGENT
# =========================================================

agent = create_agent(
    model=model,
    tools=tools,
    system_prompt=SYSTEM_PROMPT
)


# =========================================================
# CHAT LOOP
# =========================================================

print("=" * 60)
print("Windows AI Assistant")
print("Type 'exit' to stop")
print("=" * 60)


while True:

    user_input = input("\nYou: ")

    if user_input.lower() == "exit":

        print("Goodbye!")

        break

    if not user_input:

        continue

    try:

        response = agent.invoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": user_input
                    }
                ]
            }
        )

        print(
            "\nAI:",
            response["messages"][-1].content
        )

    except Exception as e:

        print("\nAgent Error:", e)