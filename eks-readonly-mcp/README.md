# eks-readonly-mcp

Local MCP server for Claude Desktop (Windows). Claude Desktop launches this
process over stdio; it SSHes to the dev bastion, runs read-only `kubectl get`
commands as the `solveda` Linux user, and returns the results to Claude.

Claude Desktop -> this MCP server (stdio) -> SSH -> bastion -> `sudo -u solveda kubectl get ...` -> EKS

## Safety model

- A fixed set of read-only tools exist (cluster/version/api-resources info;
  `get_namespaces`, `get_nodes`; workloads: pods, deployments, replicasets,
  statefulsets, daemonsets, jobs, cronjobs; networking: services, endpoints,
  endpointslices, ingress, networkpolicies; scaling: hpa, pdb; config:
  configmaps, secrets metadata (values always redacted); storage: pv, pvc,
  storageclasses; RBAC: serviceaccounts, roles, rolebindings, clusterroles,
  clusterrolebindings; health: events; and `get_pod_logs` for pod/container
  logs). There is no generic "run a command" tool, and no tool accepts a raw
  kubectl string from the model.
- Every command is assembled from a hardcoded resource name and a validated
  namespace/pod/container (`server.py`), then independently re-checked in
  `ssh_client.py` against an allow-list that permits only `kubectl get`,
  `cluster-info`, `version`, `api-resources`, and `logs`, and rejects any
  mutating verb or shell metacharacter, even if `server.py` had a bug. No
  tool ever builds `exec`, `cp`, `attach`, or `port-forward`.
- Secret values are never returned: `get_secrets_metadata` strips
  `data`/`stringData` fields in Python before the response leaves the
  server, regardless of what kubectl outputs.
- `get_pod_logs` caps `tail_lines` at 1000 (default 100) and requires an
  explicit namespace and pod name.
- The kubeconfig and AWS credentials never leave the bastion. Nothing is
  copied to Windows, and command output/stderr is never logged with secret
  material.
- Every tool takes an explicit `env` parameter (`"dev"` by default, or
  `"uat"`) that selects which bastion/cluster it targets. There is no
  hidden "current environment" state and no environment-switching tool -
  each call states its own target and every response is tagged
  `[env=dev]`/`[env=uat]`. Requesting an unconfigured or unknown env (e.g.
  `"prod"`, not yet supported) returns a clear error, never a fallback to
  the wrong cluster.

## Multi-environment (DEV / UAT)

Configure one or both environments via env vars (see `.env.example`):

```
DEV_BASTION_HOST=10.11.80.131
DEV_BASTION_PORT=22
DEV_BASTION_USER=ubuntu
DEV_BASTION_KEY_PATH=C:\path\to\dev-bastion-openssh.key

UAT_BASTION_HOST=10.12.80.197
UAT_BASTION_PORT=22
UAT_BASTION_USER=ubuntu
UAT_BASTION_KEY_PATH=C:\path\to\uat-bastion-openssh.key

KUBERNETES_USER=solveda
```

If `DEV_BASTION_*` are not set, `dev` falls back to the legacy unprefixed
`BASTION_*` variables - an existing single-environment `.env` or Claude
Desktop config keeps working unchanged. `uat` has no such fallback: all
three `UAT_BASTION_*` variables are required together, or `uat` stays
unconfigured (tools called with `env="uat"` then return a clear error
instead of a crash). `prod` is not yet supported by any tool.

Every tool accepts `env`, e.g.:

- `get_pods(namespace="commerce")` → dev (default)
- `get_pods(namespace="commerce", env="uat")` → UAT
- `get_pod_logs(namespace="commerce", pod="checkout-7d9", env="uat")` → UAT pod logs

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
        "DEV_BASTION_HOST": "10.11.80.131",
        "DEV_BASTION_PORT": "22",
        "DEV_BASTION_USER": "ubuntu",
        "DEV_BASTION_KEY_PATH": "D:\\path\\to\\dev-bastion-openssh.key",
        "UAT_BASTION_HOST": "10.12.80.197",
        "UAT_BASTION_PORT": "22",
        "UAT_BASTION_USER": "ubuntu",
        "UAT_BASTION_KEY_PATH": "D:\\path\\to\\uat-bastion-openssh.key",
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

- "Show all EKS namespaces." (dev, by default)
- "Show all pods in the commerce namespace in UAT."
- "Show HPA status across all namespaces."
- "Show all nodes and their status."
- "Give me a read-only summary of the EKS cluster health."
- "Get the last 200 log lines for pod checkout-7d9 in the commerce namespace, UAT."

Claude Desktop interprets the returned JSON itself - this server does no
analysis, it only fetches data.
