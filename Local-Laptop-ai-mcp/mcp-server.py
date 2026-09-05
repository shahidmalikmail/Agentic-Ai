"""
Windows Laptop AI Tools - MCP server.

Single entry point that registers every read-only Windows diagnostic tool
with the MCP protocol. Tool implementations live in tools/ (one module per
category); this file only wires them up as MCP tools.

No destructive or state-changing capability is exposed: no delete, no
format, no shutdown/reboot, no registry/firewall/user changes, no arbitrary
shell execution, no service/process control. See README.md for the full
tool catalog and security model.
"""

from mcp.server.fastmcp import FastMCP

from tools import (
    diagnostics,
    disk_storage,
    environment,
    filesystem,
    health,
    network,
    processes,
    services,
    system_info,
)

mcp = FastMCP("Windows Laptop AI Tools")


# ---------------------------------------------------------------------------
# System Information
# ---------------------------------------------------------------------------
mcp.tool()(system_info.get_os_info)
mcp.tool()(system_info.get_cpu_info)
mcp.tool()(system_info.get_memory_info)
mcp.tool()(system_info.get_uptime)

# ---------------------------------------------------------------------------
# Disk / Storage
# ---------------------------------------------------------------------------
mcp.tool()(disk_storage.list_drives)
mcp.tool()(disk_storage.get_disk_usage)
mcp.tool()(disk_storage.get_folder_size)
mcp.tool()(disk_storage.count_items)
mcp.tool()(disk_storage.find_large_files)
mcp.tool()(disk_storage.search_files)

# ---------------------------------------------------------------------------
# File System
# ---------------------------------------------------------------------------
mcp.tool()(filesystem.list_folder)
mcp.tool()(filesystem.read_file)
mcp.tool()(filesystem.file_exists)
mcp.tool()(filesystem.get_file_metadata)
mcp.tool()(filesystem.search_in_files)

# ---------------------------------------------------------------------------
# Processes
# ---------------------------------------------------------------------------
mcp.tool()(processes.list_processes)
mcp.tool()(processes.find_process)
mcp.tool()(processes.get_process_info)

# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------
mcp.tool()(services.list_services)
mcp.tool()(services.get_service_status)

# ---------------------------------------------------------------------------
# Network Diagnostics
# ---------------------------------------------------------------------------
mcp.tool()(network.get_network_info)
mcp.tool()(network.get_dns_info)
mcp.tool()(network.ping_host)
mcp.tool()(network.check_port)
mcp.tool()(network.get_routing_info)

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
mcp.tool()(environment.get_environment_variables)
mcp.tool()(environment.get_path_entries)
mcp.tool()(environment.get_tool_versions)

# ---------------------------------------------------------------------------
# Windows Diagnostics / Logs
# ---------------------------------------------------------------------------
mcp.tool()(diagnostics.get_recent_events)

# ---------------------------------------------------------------------------
# Laptop Health Monitoring
# ---------------------------------------------------------------------------
mcp.tool()(health.get_health_summary)


if __name__ == "__main__":
    mcp.run()
