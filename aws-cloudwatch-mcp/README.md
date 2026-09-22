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

## Phase 2A: CloudWatch Logs Insights (optional, OFF by default)

**Status: implemented and unit-tested with mocks; not yet validated against real AWS.** With `INSIGHTS_ENABLED`
unset/false the server is exactly Phase 1: no Insights code path is built and no Insights tool is registered.

Insights aggregates on the AWS side so Claude can answer "how many / when / where" questions without downloading
raw logs. It uses a **dedicated identity and profile** (`ob-aws-cloudwatch-insights`, IAM user
`cloud-watch-insights-review`) with exactly `logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery`
(`docs/PHASE-2A-IAM-POLICY-PROPOSED.json`, `docs/PHASE-2A-IAM-APPLY-GUIDE.md`). AWS classes StartQuery/StopQuery as
**Write** actions: the model is "read-only access to application/infrastructure data through tightly constrained
Logs Insights query jobs", and queries are billed by data scanned.

| Tool | Purpose |
|---|---|
| `aws_insights_estimate_scan` | Estimate scan size (`\| estimate`), verdict vs caps; never runs the real query |
| `aws_insights_count_over_time` | Matches per time bin: trend, first/peak bins |
| `aws_insights_count_by` | Matches by log group / log stream / status code |
| `aws_insights_sample_events` | A few (max 20) recent matching events; sanitized, **untrusted** |
| `aws_insights_get_results` | Continue a query that outlived the wait budget (opaque `query_handle`) |
| `aws_insights_cancel_query` | Cancel a query this server started |
| `aws_insights_budget_status` | Limits, scan budget used/remaining, running jobs (local state, no AWS call) |

**Safety model (all enforced in code and tests):** no tool accepts a query string, AWS action, regex or raw query id.
Claude names a preset (`errors`, `exceptions`, `timeouts`, `connection_problems`, `http_4xx`, `http_5xx`, `oom`,
`auth_failures`, `tls_errors`, `dns_errors`), up to 3 literal terms and status codes; the server renders the query from
vetted templates and validates every stage against an allow-list (`SOURCE`, `join`, `lookup`, `subqueries`,
`appendcols`, `cidrlookup`, `unmask`, SQL and PPL are blocked). A boto-level gate refuses any `StartQuery` the validator
did not approve (single use), any operation other than the three, and any `queryId` this process did not start.
Every query is preceded by a `| estimate` run and **fails closed** if no unambiguous estimate exists; per-query
(2 GiB) and per-process (20 GiB) scan budgets, 2 concurrent queries, rate limits, a circuit breaker, a 40 s wait then a
handle, and a 180 s application deadline with `StopQuery`. `StartQuery` is made with exactly one attempt and is never
retried after a timeout (no idempotency token: a retry could create a duplicate billed query).

Enable it by adding names only (no secrets) to the Claude Desktop `env`, then restart Claude Desktop. **Intended
configuration** (same AWS account and, currently, the same region for both phases; separate variables keep the regions
independently configurable):

```json
"env": {
  "AWS_PROFILE": "ob-aws-cloudwatch",
  "AWS_REGION": "us-east-1",
  "AWS_INSIGHTS_PROFILE": "ob-aws-cloudwatch-insights",
  "AWS_INSIGHTS_REGION": "us-east-1",
  "AWS_ACCOUNT_ID": "926266574832",
  "INSIGHTS_ENABLED": "true"
}
```

**Regions.** `AWS_REGION` (Phase 1: logs, metrics, alarms) is `us-east-1` and is never changed by Insights.
`AWS_INSIGHTS_REGION` selects the region used for Logs Insights (`StartQuery`/`GetQueryResults`/`StopQuery`) and for the
log-group existence/retention lookup that precedes a query. **It is set to `us-east-1`, because that is where the PROD
CloudWatch log groups actually are:** all eight (`/aws/internet-monitor/Prod-CDN-Traffic/{byCity,byCountry,byMetro,bySubdivision}`,
`aws-CDN-prod-main-log`, `aws-CDN-prod-ts-app-log`, `aws-waf-logs-prod`, `aws-waf-logs-prod-91-ts-app`) were confirmed in
`us-east-1`, and none exist in `ap-southeast-1` (the application/environment being associated with another region does not
matter for Logs Insights: the region must be the one that holds the log groups). The variable is kept as a separate
setting so a different region can be used in future; if it is unset it follows `AWS_REGION`. Both phases use the **same
account**; the pin `AWS_ACCOUNT_ID=926266574832` is enforced for both, and the Insights identity must remain a different
principal from Phase 1. The lookup uses the Phase 1 *profile* with the Insights *region*; with both set to `us-east-1`
it simply reuses Phase 1's log-group service. Phase 1 IAM and behaviour are not modified by this project.

**Estimate query handling (fixed after real-AWS validation step V2).** An estimate runs the same query plus a trailing
`| estimate`, which must be the *final* command. AWS applies the API `limit` parameter as a trailing stage, so sending
`limit` with an estimate produced `MalformedQueryException: unexpected symbol found limit`. Estimate requests are now sent
**without** an API `limit`; real queries still carry their bounded `limit`. The boto gate enforces both shapes.

`aws_health_check` then also reports the Insights identity (STS only; no query). It must resolve to account
`926266574832` **and** to a different principal than the Phase 1 profile, otherwise Insights refuses to run (Phase 1
keeps working). Limits and their hard ceilings are listed in `.env.example`.

**Known limitations:** matching is regex/substring on `@message` (approximate, especially for unstructured text);
literal terms cannot contain `/`, `"` or `\`; the per-process budget resets on restart; an empty result never proves
health; `estimate` result shape, exact query syntax and time units are confirmed only in real-AWS validation (the
parser fails closed until then); log-group IAM scoping is not applied yet (Q2, see `docs/PHASE-2A-IAM-DESIGN.md`).

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
