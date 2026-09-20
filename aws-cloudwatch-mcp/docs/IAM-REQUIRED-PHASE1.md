# IAM required for Phase 1 (and what Phase 2 will need)

Identity: IAM user `cloud-watch-log-review`, account `926266574832`, AWS CLI profile
`ob-aws-cloudwatch`, region `us-east-1`.

**Nothing in this repository changes IAM.** This document is for you to apply (or not) by hand.

## 0. Current state: the attached policy does not cover Phase 1

`AmazonCloudWatchEvidentlyReadOnlyAccess` (checked against the AWS managed-policy reference, v1,
last edited 2021-11-29) contains exactly these actions on `Resource: "*"`:

```
evidently:GetExperiment  evidently:GetFeature   evidently:GetLaunch    evidently:GetProject
evidently:ListExperiments evidently:ListFeatures evidently:ListLaunches evidently:ListProjects
```

It contains **no `logs:*`, no `cloudwatch:*` and no `sts:*` action**. It is for CloudWatch *Evidently*
(feature flags/experiments), a different product from CloudWatch Logs/Metrics/Alarms.
With only this policy attached, every Phase 1 data call is expected to fail with `AccessDenied`
(the MCP will then report "No CloudWatch data is currently available ... access_denied").

Caveat: I cannot see the user's other policies (inline, group-attached, permissions boundary, org SCPs).
Section 5 has commands that show the real state.

## 1. Phase 1: APIs actually called by the code

Derived from `READ_ONLY_OPERATIONS` in `src/aws_cw_mcp/aws/client.py` and the service modules; a unit test
(`test_iam_doc_and_policy_cover_every_allowed_operation`) fails if an allowed API is missing from this
document or from the policy file.

| # | AWS API | IAM action | Why the MCP needs it | Tool(s) | Required for Phase 1? | Needed later? |
|---|---|---|---|---|---|---|
| 1 | STS `GetCallerIdentity` | `sts:GetCallerIdentity` | Verify the active identity and refuse to run unless the account equals `AWS_ACCOUNT_ID` | every tool (gate), `aws_health_check` | **Yes** - but **no IAM grant is needed**: AWS documents this call as usable by any authenticated principal and it cannot be denied by IAM policy | Yes (same gate) |
| 2 | Logs `DescribeLogGroups` | `logs:DescribeLogGroups` | Discover log groups (by keyword/category/prefix, allowlist) | `aws_discover_log_groups` | **Yes** | Yes |
| 3 | Logs `DescribeLogStreams` | `logs:DescribeLogStreams` | List streams so a stream can be read | `aws_list_log_streams` | **Yes** | Yes |
| 4 | Logs `FilterLogEvents` | `logs:FilterLogEvents` | Filter-pattern search over log events | `aws_search_logs` | **Yes** | Yes |
| 5 | Logs `GetLogEvents` | `logs:GetLogEvents` | Read events from one named stream | `aws_get_log_events` | **Yes** | Yes |
| 6 | CloudWatch `ListMetrics` | `cloudwatch:ListMetrics` | Show which metrics are really published before analysing | `aws_list_metrics` | **Yes** | Yes |
| 7 | CloudWatch `GetMetricData` | `cloudwatch:GetMetricData` | Fetch metric time series (the only metric-data API the code calls) | `aws_get_metrics` | **Yes** | Yes |
| 8 | CloudWatch `GetMetricStatistics` | `cloudwatch:GetMetricStatistics` | **Not called by any Phase 1 code.** It was on my earlier allow-list "just in case" and has been removed | none | **No** | Optional; only if a later feature chooses it over `GetMetricData` |
| 9 | CloudWatch `DescribeAlarms` | `cloudwatch:DescribeAlarms` | List alarms and current state | `aws_get_alarms` | **Yes** | Yes |
| 10 | CloudWatch `DescribeAlarmHistory` | `cloudwatch:DescribeAlarmHistory` | Alarm state-change history | `aws_get_alarm_history` | **Yes** | Yes |

So Phase 1 needs **8 IAM grants** (rows 2-7, 9, 10). Row 1 needs none; row 8 is not used.

### Resource scoping (from the AWS Service Authorization Reference for CloudWatch Logs)

| Action | Access level | Resource types | Scoping used in `iam-policy-phase1.json` |
|---|---|---|---|
| `logs:DescribeLogGroups` | List | log-group (not required) | `*` |
| `logs:DescribeLogStreams` | List | log-group, log-stream (not required) | `*` |
| `logs:FilterLogEvents` | Read | log-group, log-stream (not required) | `arn:aws:logs:us-east-1:926266574832:log-group:*:*` |
| `logs:GetLogEvents` | Read | log-group, log-stream (not required) | same |
| `cloudwatch:*` (the four above) | List/Read | resource-level scoping not supported for these (expected; see note) | `*` |

Log-group ARN format: `arn:aws:logs:REGION:ACCOUNT:log-group:NAME` (policies conventionally append `:*`).
Note: the documentation page for CloudWatch (metrics/alarms) was only returned as a partial summary when I
checked, so "no resource-level scoping for the four `cloudwatch:` actions" is the standard, widely-documented
behaviour but I did not get it verbatim from the page. If validation (section 5) shows a scoped resource is
denied, use `*` for those four.

**Tighten log content access:** `FilterLogEvents`/`GetLogEvents` read log *content* that may hold sensitive
data. Replace `log-group:*:*` with specific groups (e.g. `log-group:/aws/eks/*:*`) and mirror them in
`LOG_GROUP_ALLOWLIST`.

The policy file also pins `aws:RequestedRegion` to `us-east-1`. Remove that `Condition` if you later need
another region (or if it interferes during validation).

Possible extra: if a log group is encrypted with a customer-managed KMS key you may see KMS-related access
errors for that group only. I did not verify the exact KMS permissions required for readers; treat it as a
per-group diagnostic, not something to grant pre-emptively.

## 2. Ready-to-use policy

[`iam-policy-phase1.json`](iam-policy-phase1.json) - a customer-managed policy containing exactly the
8 grants above. Attach it to `cloud-watch-log-review` yourself if you agree with it. Broad AWS managed
policies (e.g. `CloudWatchReadOnlyAccess`, `ReadOnlyAccess`) grant far more than needed and were not evaluated.

## 3. Phase 2 (Logs Insights) - documented only, NOT in the code or the Phase 1 policy

Checked against the CloudWatch Logs Service Authorization Reference:

| Purpose | API | IAM action | AWS access level | Resource | Required for Phase 2? |
|---|---|---|---|---|---|
| Start a Logs Insights query | `StartQuery` | `logs:StartQuery` | **Write** | log-group ARNs (`...:log-group:NAME:*`) | **Yes** |
| Fetch results / poll status | `GetQueryResults` | `logs:GetQueryResults` | Read | no resource type (`*`) | **Yes** |
| Cancel a running query (cost/time-out control) | `StopQuery` | `logs:StopQuery` | **Write** | no resource type (`*`) | Recommended (needed to abort runaway queries) |
| List running queries | `DescribeQueries` | `logs:DescribeQueries` | List | `*` | Optional |
| Discover field names of a log group | `GetLogGroupFields` | `logs:GetLogGroupFields` | Read | log-group | Optional |
| Fetch one full record from an Insights `@ptr` | `GetLogRecord` | `logs:GetLogRecord` | Read | `*` | Optional |

Points to weigh before granting them:

1. **AWS classifies `StartQuery` and `StopQuery` as Write-level.** In practice `StartQuery` creates a
   transient query job (no resource in your account is modified) and `StopQuery` cancels one, but an IAM
   review tool or auditor will see "write" actions. Say so explicitly when you approve them.
2. `StartQuery` is billed by **data scanned**. Scope it to specific log groups and rely on the MCP's
   planned limits (max range, query count, timeout, result cap).
3. The current code guard blocks every `Start*`/`Stop*` operation. Phase 2 will need a narrow, reviewed
   exception for exactly these three operations - not a relaxation of the prefix rule.
4. Phase 2 code should only ever `StopQuery` a `queryId` it started itself.

## 4. Later phases (not Phase 1)

WAF, CloudFront, EC2, EKS, ELB, S3, Route53, VPC, SNS and SES need service-specific `Describe*/List*/Get*`
metadata permissions; they are deliberately not listed or granted here. They will be derived from the
actual APIs of each phase when it is built.

## 5. Manual read-only validation (you run these; the MCP/Claude never does)

Use PowerShell with the AWS CLI. All commands are read-only. To avoid printing log content, permission
checks for log events use `--query "length(events)"`.

```powershell
# A. Identity - must show Account 926266574832 and user/cloud-watch-log-review
aws sts get-caller-identity --profile ob-aws-cloudwatch

# B. Logs
aws logs describe-log-groups --profile ob-aws-cloudwatch --region us-east-1 --limit 5 --query "logGroups[].logGroupName"
aws logs describe-log-streams --profile ob-aws-cloudwatch --region us-east-1 --log-group-name "<LOG_GROUP>" --order-by LastEventTime --descending --limit 3 --query "logStreams[].logStreamName"
aws logs filter-log-events --profile ob-aws-cloudwatch --region us-east-1 --log-group-name "<LOG_GROUP>" --start-time ([DateTimeOffset]::UtcNow.AddHours(-1).ToUnixTimeMilliseconds()) --limit 5 --query "length(events)"
aws logs get-log-events --profile ob-aws-cloudwatch --region us-east-1 --log-group-name "<LOG_GROUP>" --log-stream-name "<LOG_STREAM>" --limit 1 --query "length(events)"

# C. Metrics
aws cloudwatch list-metrics --profile ob-aws-cloudwatch --region us-east-1 --namespace AWS/Logs --max-items 5
'[{"Id":"m1","MetricStat":{"Metric":{"Namespace":"AWS/Logs","MetricName":"IncomingLogEvents"},"Period":3600,"Stat":"Sum"}}]' | Set-Content -Encoding ascii "$env:TEMP\q.json"
aws cloudwatch get-metric-data --profile ob-aws-cloudwatch --region us-east-1 --metric-data-queries file://$env:TEMP/q.json --start-time (Get-Date).AddHours(-3).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") --end-time (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# D. Alarms
aws cloudwatch describe-alarms --profile ob-aws-cloudwatch --region us-east-1 --max-items 5 --query "MetricAlarms[].[AlarmName,StateValue]"
aws cloudwatch describe-alarm-history --profile ob-aws-cloudwatch --region us-east-1 --max-items 5 --query "AlarmHistoryItems[].[AlarmName,HistoryItemType]"
```

Reading the results: `AccessDenied` on a command means that action is missing. An **empty** result (no
groups/metrics/alarms) with no error means the permission works and there is simply nothing to show.
`get-metric-data` with `Namespace AWS/Logs` may legitimately return no datapoints without a `LogGroupName`
dimension; success = no `AccessDenied`.

To see what is really attached (use an **admin** profile, not `ob-aws-cloudwatch`, which lacks IAM access):

```powershell
aws iam list-attached-user-policies --user-name cloud-watch-log-review
aws iam list-user-policies          --user-name cloud-watch-log-review
aws iam list-groups-for-user        --user-name cloud-watch-log-review
```
