# EKS AI Monitor

Read-only AI monitoring agent for a Dev AWS EKS cluster. Runs on your
Windows laptop, drives `kubectl`/`aws` on an Ubuntu bastion over SSH, and
reports cluster health through the local Temporal Web UI.

## Architecture

```
Laptop/VS Code (Temporal server + Web UI + Python worker)
   -> VPN
   -> Ubuntu Dev Bastion Server (SSH, kubectl + AWS CLI already configured)
   -> AWS EKS (Dev cluster)
```

Temporal (server, Web UI, worker) runs **only** on your laptop. The
bastion only ever receives SSH-executed, read-only `kubectl`/`aws`
commands - nothing is installed on it.

## Project structure

```
eks-ai-monitor/
├── app/
│   ├── workflows.py          # EKSMonitoringWorkflow (no I/O here)
│   ├── activities.py         # check_bastion_connection, collect_cluster_data, analyze_cluster_data
│   ├── kubernetes_monitor.py # kubectl orchestration + problem detection
│   ├── ssh_client.py         # Paramiko SSH client + read-only command guard
│   ├── ai_analyzer.py        # LLMProvider abstraction (Anthropic implementation)
│   ├── models.py             # shared dataclasses + report formatter
│   └── config.py             # env-var configuration
├── worker.py                 # Temporal worker (connects to local Temporal)
├── start_monitor.py          # creates/updates the Temporal Schedule
├── requirements.txt
├── .env.example
└── .gitignore
```

## Safety

Every command sent over SSH passes through an allow-list in
`app/ssh_client.py` (`kubectl get/describe/top/version/cluster-info/...`,
`aws eks describe-cluster`, `aws sts get-caller-identity`) and a deny-list
that rejects `delete`, `scale`, `apply`, `patch`, `edit`, `exec`, `rollout
restart`, etc., plus shell-metacharacter chaining. This is enforced
independently of what `kubernetes_monitor.py` generates.

## 1. Windows PowerShell setup

```powershell
cd D:\git-code-repo-shahid\Agentic-Ai\eks-ai-monitor

# 1. Create venv
python -m venv venv

# 2. Activate venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# Configure secrets (edit .env with your bastion + Anthropic key)
Copy-Item .env.example .env
notepad .env
```

## 2. Install & start local Temporal dev server

```powershell
# Install the Temporal CLI (one-time)
irm https://temporal.download/cli.ps1 | iex

# Start the local dev server (includes the Web UI) - keep this running in its own terminal
temporal server start-dev
```

- Temporal Server: `localhost:7233`
- Temporal Web UI: `http://localhost:8233`

## 3. Start the worker

In a second PowerShell terminal (with the venv activated):

```powershell
.\venv\Scripts\Activate.ps1
python worker.py
```

## 4. Start monitoring

In a third PowerShell terminal (with the venv activated):

```powershell
.\venv\Scripts\Activate.ps1
python start_monitor.py
```

This creates a Temporal Schedule (`eks-monitoring-schedule`) that runs
`EKSMonitoringWorkflow` every `MONITOR_INTERVAL_SECONDS` (default 300s)
and triggers one run immediately. Re-running `start_monitor.py` is safe -
it reuses the existing schedule and just triggers another immediate run.

## Test procedure

1. Confirm VPN is connected and you can `ssh` to the bastion manually with
   the same host/user/key as in `.env`.
2. Start the Temporal dev server, worker, then `start_monitor.py` as above.
3. Open `http://localhost:8233` -> Workflows -> `eks-monitoring-workflow`.
4. Open the latest run - its **Input and Results** panel shows the
   formatted health report; the **Activities** section shows the raw
   `check_bastion_connection` / `collect_cluster_data` / `analyze_cluster_data`
   results for every namespace, node, and resource collected.
5. To change the interval, edit `.env`, delete the schedule, and rerun:
   ```powershell
   temporal schedule delete --schedule-id eks-monitoring-schedule
   python start_monitor.py
   ```

## Troubleshooting

```powershell
# Manually verify bastion SSH reachability
ssh -i <path-to-key> <user>@<bastion-host>

# Verify kubectl/AWS access ON the bastion (run over SSH manually)
ssh <user>@<bastion-host> "kubectl cluster-info"
ssh <user>@<bastion-host> "aws sts get-caller-identity"

# Check Temporal dev server is up
temporal operator cluster health

# Tail worker logs
python worker.py   # structured [SSH]/[EKS]/[AI]/[TEMPORAL] logs print to this console

# List/describe the schedule
temporal schedule list
temporal schedule describe --schedule-id eks-monitoring-schedule

# Inspect a specific workflow run from the CLI
temporal workflow show --workflow-id eks-monitoring-workflow
```

Common failure modes and where they surface:

| Symptom | Cause | Where it's reported |
|---|---|---|
| VPN disconnected / bastion unreachable | SSH connect timeout | `check_bastion_connection` activity fails, retried 3x, then the workflow returns an ERROR report |
| Bad SSH key/user | Auth failure | Same as above, non-retryable after auth rejection surfaces in activity error |
| `kubectl`/`aws` misconfigured on bastion | Non-zero exit code | `RemoteCommandError` in the relevant activity, visible in Web UI activity failure details |
| Malformed kubectl JSON | Partial/corrupt output | Logged and recorded in `ClusterSnapshot.collection_errors`; that resource is skipped, rest of the snapshot still returned |
| Invalid `ANTHROPIC_API_KEY` | 401 from Anthropic | `analyze_cluster_data` fails non-retryably with a clear message |
| LLM returns non-JSON text | Prompt/model drift | `ai_analyzer` falls back to a summary built from the raw text plus the already-collected snapshot data |
| Temporal server not running | Worker/`start_monitor.py` can't connect | Clear connection error at startup, before anything else runs |
