# eks-readonly-mcp

Local MCP server for Claude Desktop (Windows). Claude Desktop launches this
process over stdio; it SSHes to the dev bastion, runs read-only `kubectl get`
commands as the `solveda` Linux user, and returns the results to Claude.

Claude Desktop -> this MCP server (stdio) -> SSH -> bastion -> `sudo -u solveda kubectl get ...` -> EKS

## Safety model

- Only 9 fixed tools exist (`get_cluster_info`, `get_namespaces`, `get_nodes`,
  `get_pods`, `get_deployments`, `get_services`, `get_ingress`, `get_hpa`,
  `get_events`). There is no generic "run a command" tool, and no tool
  accepts a raw kubectl string from the model.
- Every command is assembled from a hardcoded resource name and a validated
  namespace (`server.py`), then independently re-checked in `ssh_client.py`
  against an allow-list that permits only `kubectl get` / `kubectl
  cluster-info` and rejects any mutating verb or shell metacharacter, even
  if `server.py` had a bug.
- The kubeconfig and AWS credentials never leave the bastion. Nothing is
  copied to Windows, and command output/stderr is never logged with secret
  material.

## About the SSH key (.ppk)

Paramiko cannot reliably load PuTTY's native `.ppk` key format (tested
against the supplied key: it fails to parse, even PPK v2 with no
passphrase). **Do not** try to work around this - convert the key once:

1. Open **PuTTYgen**.
2. **Conversions > Import key**, select the `.ppk` file.
3. **Conversions > Export OpenSSH key** (or "Export OpenSSH key (force new
   file format)"), save it somewhere private, e.g.
   `C:\Users\<you>\.ssh\ob-dev-bastion-9-1-11-0-openssh.key`.
4. Point `BASTION_KEY_PATH` at that exported file (see below).

If the server fails to connect and the configured key still looks like a raw
`.ppk` file, it will tell you this directly instead of guessing.

## Project layout

```
eks-readonly-mcp/
├── server.py        # MCP tools (stdio transport) - the only entry point
├── ssh_client.py     # SSH + read-only command guard - the only network code
├── config.py         # env-var configuration
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

## Setup (Windows PowerShell)

```powershell
cd D:\git-code-repo-shahid\Agentic-Ai\eks-readonly-mcp

# 1. Create venv
python -m venv venv

# 2. Activate venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# Copy env template and edit it with your converted OpenSSH key path
copy .env.example .env
notepad .env
```

Test SSH connectivity on its own first (uses your `.env` values):

```powershell
# 4. Test SSH (requires VPN connected)
python -c "from config import load_config; from ssh_client import BastionSSHClient; c = load_config(); r = BastionSSHClient(c).run_kubectl('kubectl get namespaces -o json'); print('exit:', r.exit_code); print(r.stdout[:500]); print(r.stderr[:500])"
```

You should see `exit: 0` and JSON output. If it fails, fix connectivity/key
issues before wiring up Claude Desktop.

Run the MCP server directly (it will sit waiting for stdio MCP frames -
`Ctrl+C` to stop; this mainly confirms it starts without errors):

```powershell
# 5. Run/test the MCP server
python server.py
```

## Claude Desktop configuration

Edit `%APPDATA%\Claude\claude_desktop_config.json` (create it if it doesn't
exist) and add an entry under `mcpServers`. Use absolute paths to the venv's
`python.exe` and to `server.py`:

```json
{
  "mcpServers": {
    "eks-readonly": {
      "command": "D:\\git-code-repo-shahid\\Agentic-Ai\\eks-readonly-mcp\\venv\\Scripts\\python.exe",
      "args": [
        "D:\\git-code-repo-shahid\\Agentic-Ai\\eks-readonly-mcp\\server.py"
      ],
      "env": {
        "BASTION_HOST": "10.11.80.131",
        "BASTION_PORT": "22",
        "BASTION_USER": "ubuntu",
        "BASTION_KEY_PATH": "D:\Solveda-Data-OnDrive-10-oct-25\OneDrive - SAKSOFT LIMITED\Office Brands Project\OB-AWS-Pem-Key\ob-aws-key-for-9-1-11-0\ob-dev-bastion-9-1-11-0.pem",
        "KUBERNETES_USER": "solveda",
        "SSH_TIMEOUT": "15",
        "COMMAND_TIMEOUT": "30"
      }
    }
  }
}
```

Then fully quit and restart Claude Desktop (not just close the window).
Make sure the VPN is connected before asking Claude anything that needs the
cluster.

## Example prompts to test

- "Show all EKS namespaces."
- "Show all pods in the commerce namespace."
- "Show HPA status across all namespaces."
- "Show all nodes and their status."
- "Give me a read-only summary of the EKS cluster health."

Claude Desktop interprets the returned JSON itself - this server does no
analysis, it only fetches data.
