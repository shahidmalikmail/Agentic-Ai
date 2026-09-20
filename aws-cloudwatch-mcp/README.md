# aws-cloudwatch-mcp

A **strictly read-only** MCP server that lets Claude Desktop investigate AWS through CloudWatch
(logs, metrics, alarms). It observes, analyses and suggests; it **never changes** any AWS or
Kubernetes resource and it never executes a recommendation.

It runs **only on your local Windows laptop**, launched directly by Claude Desktop from the project's
virtual environment. There is no bastion, SSH, instance profile or remote execution.

**Status: Phase 1 of 9** - foundation, log discovery/search, metrics, alarms. Everything else is on the
[roadmap](#roadmap).

## Authentication architecture

```
Claude Desktop
   -> local aws-cloudwatch-mcp   (python -m aws_cw_mcp, stdio)
      -> boto3 Session(profile_name="ob-aws-cloudwatch")
         -> AWS CLI profile  ob-aws-cloudwatch   (~/.aws/credentials, set up with `aws configure`)
            -> IAM user  cloud-watch-log-review   (account 926266574832, us-east-1)
```

* Credentials come only from the standard boto3 credential chain via the **named profile**. No access keys are
  in source, `.env`, the Claude Desktop config or logs. The server never reads or prints key values.
* `AWS_ACCOUNT_ID` is **required** at startup (the server exits without it). Before any CloudWatch client is handed
  out, `sts:GetCallerIdentity` must return that account; otherwise **every** AWS operation is refused
  (`account_mismatch`) and stays refused.
* `aws_health_check` shows only safe identity metadata: account, principal ARN/type, region, profile name.
* If `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` happen to be set in the environment, boto3
  ignores them when a profile is explicitly selected (covered by a test) and the server logs a warning
  (names only, never values).

## Setup (Windows)

```powershell
cd D:\git-code-repo-shahid\Agentic-Ai\aws-cloudwatch-mcp
python -m venv venv
.\venv\Scripts\pip install -e ".[dev]"
Copy-Item .env.example .env      # optional; Claude Desktop's "env" block can supply the same values
```

The AWS profile is assumed to exist already (`aws configure --profile ob-aws-cloudwatch`). This project never
creates credentials or modifies IAM.

Configuration (see [`.env.example`](.env.example)):

```
AWS_PROFILE=ob-aws-cloudwatch
AWS_REGION=us-east-1
AWS_ACCOUNT_ID=926266574832
```

To load a `.env` from another location set `AWS_CW_MCP_ENV_FILE=<path>`. Real environment variables (for
example from Claude Desktop's `env` block) always take precedence over the file.

## IAM permissions

The user currently has `AmazonCloudWatchEvidentlyReadOnlyAccess`. **That policy contains only `evidently:*`
actions** and does not grant CloudWatch Logs/Metrics/Alarms access. See
[`docs/IAM-REQUIRED-PHASE1.md`](docs/IAM-REQUIRED-PHASE1.md) for the exact API-to-action table, the Phase 2
(Logs Insights) needs, and manual validation commands; a ready policy is in
[`docs/iam-policy-phase1.json`](docs/iam-policy-phase1.json). This project never changes IAM itself.

## Claude Desktop configuration (local)

Edit `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aws-cloudwatch": {
      "command": "D:\\git-code-repo-shahid\\Agentic-Ai\\aws-cloudwatch-mcp\\venv\\Scripts\\python.exe",
      "args": ["-m", "aws_cw_mcp"],
      "env": {
        "AWS_PROFILE": "ob-aws-cloudwatch",
        "AWS_REGION": "us-east-1",
        "AWS_ACCOUNT_ID": "926266574832"
      }
    }
  }
}
```

Fully quit and restart Claude Desktop (system tray), then ask: "Run aws_health_check". Server logs go to stderr
(Claude Desktop's MCP log file); stdout carries only MCP protocol frames.

## Result format

Every tool returns JSON with the same envelope so facts, calculations and advice never blur:

| Key | Meaning |
|---|---|
| `FACT` | Values read directly from AWS |
| `ANALYSIS` | Derived / calculated from the facts (labelled as such) |
| `RECOMMENDATION` | Suggestions for a human - always prefixed "human decision required; nothing was executed" |
| `status` | `ok`, `partial`, `empty`, `error` |
| `warnings`, `meta`, `error` | Truncation notes, range/limits used, classified error (`access_denied`, `account_mismatch`, `throttled`, `timeout`, ...) |

Missing data is reported as unavailable ("No CloudWatch data is currently available...") - never guessed.

## Tools (Phase 1)

| Tool | Purpose | AWS API |
|---|---|---|
| `aws_health_check` | Verify profile, pinned account, effective limits | `sts:GetCallerIdentity` |
| `aws_discover_log_groups` | Find log groups by keyword / category / prefix (name heuristics) | `logs:DescribeLogGroups` |
| `aws_search_logs` | Filter-pattern search across up to N log groups, sanitized and capped | `logs:FilterLogEvents` |
| `aws_list_log_streams` | List streams of one log group | `logs:DescribeLogStreams` |
| `aws_get_log_events` | Read events from one stream | `logs:GetLogEvents` |
| `aws_list_metrics` | Check which metrics are actually published | `cloudwatch:ListMetrics` |
| `aws_get_metrics` | Metric series + calculated min/avg/p50/p90/p95/p99/max | `cloudwatch:GetMetricData` |
| `aws_get_alarms` | Alarm states (actions/ARNs not returned) | `cloudwatch:DescribeAlarms` |
| `aws_get_alarm_history` | State-change history of one alarm, flapping hint | `cloudwatch:DescribeAlarmHistory` |

There is deliberately **no** generic "run AWS API" tool.

## Architecture

```
src/aws_cw_mcp/
  server.py          MCPServer creation, stdio transport, stderr-only sanitized logging
  runtime.py         config + lazy clients/services (add Phase 2+ services here)
  config.py          env config with hard safety ceilings; AWS_ACCOUNT_ID required at startup
  aws/client.py      boto3 profile session, pinned-account gate, read-only before-call guard
  aws/logs.py        LogsService        aws/cloudwatch.py  MetricsService, AlarmsService
  aws/catalog.py     name-based category hints (hcl_commerce, waf, eks, ...)
  tools/             one module per tool family; each exposes build_tools(runtime)
  models/results.py  FACT / ANALYSIS / RECOMMENDATION envelope
  utils/             sanitize, errors, timerange, cache, stats
tests/               botocore Stubber tests, no AWS access needed
docs/                IAM-REQUIRED-PHASE1.md, iam-policy-phase1.json
```

## Security controls

* **Read-only in three independent layers:** (1) only named, hand-written read tools exist; (2) every boto3
  client has a `before-call` guard that raises `ReadOnlyViolation` for any operation not on the allow-list
  (also rejects write-verb prefixes) - tested against real clients; (3) IAM should grant only reads.
* MCP tool annotations declare `readOnlyHint=true`, `destructiveHint=false`.
* **Sanitization** of log messages, alarm reasons, errors and the server's own stderr log: AWS key IDs,
  secret/token/password pairs, bearer tokens, JWTs, cookies, URL credentials, private keys. Best-effort.
* No subprocess, `eval`, shell, SSH or IMDS use anywhere (enforced by tests). Input validation on names,
  stats, periods and patterns; internal errors never echo raw exception text.

## Cost and load controls

| Control | Default | Env var (hard ceiling) |
|---|---|---|
| Max log events returned per call | 200 | `MAX_LOG_RESULTS` (2000) |
| Max datapoints per metric series | 1000 | `MAX_QUERY_RESULTS` (5000) |
| Max log search window | 24h | `MAX_LOG_TIME_RANGE_HOURS` (168) |
| Max metric/alarm window | 720h | `MAX_METRIC_TIME_RANGE_HOURS` (2160) |
| Log groups per search / metrics per call | 5 / 10 | `MAX_LOG_GROUPS_PER_QUERY`, `MAX_METRIC_QUERIES` |
| Pages per API loop | 10 | `MAX_PAGES` (50) |
| Response size budget | 60,000 chars | `MAX_RESPONSE_CHARS` |
| Metadata cache TTL | 60s | `CACHE_TTL_SECONDS` |
| AWS timeouts / retries | 5s / 30s / 5 attempts (adaptive) | `AWS_API_*` |

## Tests

```powershell
.\venv\Scripts\python -m pytest -q      # fully mocked; no AWS calls, no credentials needed
```

## Manual validation against real AWS (you run these)

First, always:

```powershell
aws sts get-caller-identity --profile ob-aws-cloudwatch
```

It must show account `926266574832` and `user/cloud-watch-log-review`. The remaining read-only checks for log
groups, metrics and alarms (and how to read AccessDenied vs. empty results) are in
[`docs/IAM-REQUIRED-PHASE1.md`](docs/IAM-REQUIRED-PHASE1.md#5-manual-read-only-validation-you-run-these-the-mcpclaude-never-does).

## Example prompts

* "Run aws_health_check and tell me which account and region you are connected to."
* "Find all CloudWatch log groups related to HCL Commerce."
* "Search the ts-app log group for ERROR or Exception in the last 6 hours and summarise what you see."
* "Which CloudWatch alarms are in ALARM right now? Show the history of the first one for 24 hours."
* "List the metrics in AWS/ApplicationELB, then show HTTPCode_Target_5XX_Count (Sum) for the last 24 hours."
* "Is the CloudWatch agent publishing memory metrics? (check the CWAgent namespace)"

## Known limitations (Phase 1)

* The IAM user currently lacks the CloudWatch Logs/Metrics/Alarms permissions; data tools return `access_denied`
  until the policy in `docs/` is applied by you.
* No Logs Insights, so `aws_search_logs` returns a capped sample and says so.
* Error grouping and WAF/CDN/EKS/ALB/EC2 analysis, correlation, anomaly detection and incident reports are not built.
* Discovery categories are name heuristics. Sanitization is regex best-effort.
* One region and one account per server instance. Written for Python 3.10+, verified on 3.14 only.
* Not yet exercised against real AWS (only mocked); use the manual validation above.

## Roadmap

1. **Phase 1** (this): foundation, logs, metrics, alarms. 2. Log Insights, error detection/grouping.
3. WAF (bots, rate limits, countries). 4. CloudFront/CDN. 5. EC2/EKS/ALB/NLB. 6. S3/VPC/NAT/Route53/SNS/SES.
7. Correlation, root cause, performance. 8. Historical comparison, anomalies, incident reports. 9. Hardening/docs.
