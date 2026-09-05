# Windows Laptop AI Tools (MCP)

A focused, **read-only** Model Context Protocol (MCP) server that lets an AI
agent inspect, diagnose, and monitor a Windows laptop - system info, disks,
files, processes, services, network, environment, event logs, and health.

Nothing in this project can delete, modify, format, shut down, reboot,
start/stop services, kill processes, or run arbitrary shell commands. It is
designed to be safe to hand to an autonomous AI agent.

## Purpose

This project exists to give a local AI agent (via MCP) safe visibility into
a Windows machine for troubleshooting and monitoring, without giving it any
ability to change system state.

## Architecture

```
Local-Laptop-ai-mcp/
├── mcp-server.py       # Single MCP entry point - registers every tool
├── tools/              # One module per tool category (plain functions)
│   ├── security.py     # Safe-root path confinement + directory pruning
│   ├── system_info.py  # OS, CPU, memory, uptime
│   ├── disk_storage.py # Drives, disk usage, folder size, large files
│   ├── filesystem.py   # List/read files, metadata, text search
│   ├── processes.py    # Process listing/lookup (no termination)
│   ├── services.py     # Windows service status (no start/stop/restart)
│   ├── network.py      # Adapters, DNS, ping, port check, routing
│   ├── environment.py  # Env vars, PATH, dev-tool versions
│   ├── diagnostics.py  # Windows Event Log (System/Application only)
│   └── health.py       # CPU/memory/disk/battery health snapshot
├── test_client.py      # Lightweight LangChain MCP client for manual testing
├── requirements.txt
└── .gitignore
```

`mcp-server.py` is the single source of truth: every tool module exposes
plain Python functions, and `mcp-server.py` is the only place that wires
them up with `@mcp.tool()`. Tool modules have no MCP/LangChain dependency,
so they can be tested by calling them directly.

## Installation

```powershell
cd Local-Laptop-ai-mcp
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

`pywin32` (services/event-log support) and `psutil` (system/process/disk/
network info) install automatically from `requirements.txt`. No other
system setup is required.

## Running the MCP server

```powershell
python mcp-server.py
```

The server communicates over stdio, per the MCP protocol - it's meant to be
launched by an MCP client (Claude Code, Claude Desktop, LangChain, etc.),
not run standalone for interactive use.

## MCP configuration (Claude Code / Claude Desktop)

Add to your MCP config (e.g. `.mcp.json` or Claude Desktop's config):

```json
{
  "mcpServers": {
    "windows-ai-tools": {
      "command": "python",
      "args": ["D:/git-code-repo-shahid/Agentic-Ai/Local-Laptop-ai-mcp/mcp-server.py"]
    }
  }
}
```

Use the absolute path to `mcp-server.py` (and ideally the venv's
`python.exe`) so the server starts correctly regardless of the client's
working directory.

## Safe-root file access

Filesystem tools (`list_folder`, `read_file`, `get_folder_size`,
`count_items`, `find_large_files`, `search_files`, `search_in_files`,
`file_exists`, `get_file_metadata`) only operate inside a configured set of
**safe roots**. Any path outside them is rejected with `Access denied`.

Defaults: the full `C:\` and `D:\` drives (each only included if it exists
on this machine). Read access is intentionally broad at the root level; the
actual controls against sensitive locations are the recursive-scan pruning
and the `read_file` extension allow-list described below - not the safe-root
boundary itself.

Override the defaults entirely with an environment variable (paths
separated by `;` on Windows), e.g. to scope back down to specific folders:

```powershell
$env:MCP_SAFE_ROOTS = "D:\AI-Agents-DevOps;C:\Users\$env:USERNAME\Documents"
```

Recursive scans (`get_folder_size`, `find_large_files`, `search_files`,
`search_in_files`, `count_items` recursive mode) automatically skip noisy
directories (`.venv`, `__pycache__`, `.git`, `node_modules`, `$RECYCLE.BIN`,
`System Volume Information`, matched case-insensitively anywhere) and the
specific system trees `C:\Windows`, `C:\Program Files`, and
`C:\Program Files (x86)` (matched as exact paths, not crawled regardless of
where in a scan they're reached). Scans stop after 50,000 items. Note that
non-recursive tools (`list_folder`, `get_disk_usage`) still work directly on
excluded paths - e.g. `list_folder("C:\\Windows")` still lists that folder's
immediate contents; only recursive descent into it is pruned.

## Complete tool list (30 tools, all read-only)

**System Information**
- `get_os_info` - hostname, OS name/version/build, architecture
- `get_cpu_info` - processor, core counts, current usage
- `get_memory_info` - RAM and swap/pagefile usage
- `get_uptime` - boot time and elapsed uptime

**Disk / Storage**
- `list_drives` - all mounted drives with free/used space
- `get_disk_usage(drive)` - total/used/free space for one drive
- `get_folder_size(folder_path)` - recursive size of a folder
- `count_items(folder_path, recursive)` - file/folder counts
- `find_large_files(folder_path, min_size_mb, limit)` - largest files above a threshold
- `search_files(folder_path, name_pattern)` - find files/folders by name glob

**File System**
- `list_folder(folder_path)` - list contents of a folder
- `read_file(file_path)` - read a text file (extension allow-list, 12KB cap)
- `file_exists(path)` - check existence and type
- `get_file_metadata(path)` - size and timestamps
- `search_in_files(folder_path, text, extensions)` - grep-like text search

**Processes**
- `list_processes(limit, sort_by)` - top processes by CPU or memory
- `find_process(name)` - find processes by name substring
- `get_process_info(pid)` - detail for one process

**Services**
- `list_services(status_filter)` - enumerate Windows services
- `get_service_status(service_name)` - detail for one service

**Network Diagnostics**
- `get_network_info` - hostname, local IP, adapter status
- `get_dns_info` - configured DNS servers per adapter
- `ping_host(host, count)` - ICMP ping (validated host, fixed args)
- `check_port(host, port, timeout)` - TCP port reachability check
- `get_routing_info` - local routing table

**Environment**
- `get_environment_variables` - env vars (secret-like values redacted)
- `get_path_entries` - PATH directories and whether each exists
- `get_tool_versions` - python/node/npm/git versions

**Windows Diagnostics / Logs**
- `get_recent_events(log_name, max_events, level)` - recent Event Log entries
  (`System`/`Application` only; `Security` is intentionally excluded)

**Laptop Health Monitoring**
- `get_health_summary` - CPU/memory/disk/battery snapshot with a status flag

## Example usage (via the LangChain test client)

```powershell
python test_client.py
```

This connects to `mcp-server.py` over stdio, lists all discovered tools,
then asks a local Ollama model a diagnostic question to exercise the full
tool-calling path. Requires Ollama running locally with a model available
(edit `MODEL_NAME` in `test_client.py` if needed).

## Example questions for an AI agent using these tools

- "What's my current CPU and memory usage?"
- "How much free space is left on my C: and D: drives?"
- "List the top 10 processes using the most memory."
- "Is the Windows Update service running?"
- "Find files larger than 500 MB under D:\git-code-repo-shahid."
- "Ping 8.8.8.8 and tell me if I have internet connectivity."
- "What DNS servers is this laptop using?"
- "Show me recent warning or error events from the System log."
- "What version of Node.js and Git do I have installed?"
- "Give me an overall health summary of this laptop."

## Security considerations

- **Read-only by design.** No tool can delete, modify, rename, or move a
  file; format a disk; shut down/reboot; change the registry or firewall;
  modify user accounts; install/uninstall software; change network
  configuration; or start/stop/restart a process or service.
- **No arbitrary shell execution.** The only subprocess calls are to fixed
  system commands with fixed or validated arguments (`ipconfig /all`,
  `route print`, `ping -n <count> <host>`) - never `shell=True`, never
  free-form user input passed to a shell.
- **Host/port validation.** `ping_host` and `check_port` validate the host
  string against an allow-list pattern before use, preventing argument
  injection into the underlying command.
- **Filesystem confinement.** All path-based tools are restricted to
  configured safe roots (see above); paths outside them are rejected.
- **Event Log scope.** Only `System` and `Application` logs are readable;
  `Security` is excluded since it can contain sensitive audit data and
  typically requires elevated access.
- **Secret redaction.** `get_environment_variables` redacts values for any
  variable name containing `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PWD`,
  `CREDENTIAL`, or `AUTH`.
- **No hardcoded usernames or machine-specific secrets.** The current
  Windows user is always resolved dynamically via `Path.home()`.
- If you later want write/control capabilities (e.g. restarting a specific
  service), add them as new, narrowly-scoped tools behind an explicit
  human-approval step - do not broaden the existing read-only tools.
