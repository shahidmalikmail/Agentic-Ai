# Phase 2A - CloudWatch Logs Insights foundation (DESIGN ONLY)

Status: **proposal for review. No code, IAM, or AWS changes accompany this document.**
Account `926266574832`, region `us-east-1`, profile `ob-aws-cloudwatch`, IAM user `cloud-watch-log-review`.

Reading guide: statements marked **[V]** were checked against AWS documentation while writing this
document (see Appendix A). Statements marked **[U]** are unverified or the sources conflicted; they must be
confirmed before implementation depends on them. Nothing here should be read as a verified AWS capability
unless it is marked **[V]**.

---

## 1. Objective

Let the MCP investigate large CloudWatch Logs datasets by asking CloudWatch Logs Insights to aggregate on the
AWS side, returning small, structured, sanitized results instead of thousands of raw log events.

Phase 2A builds only the **foundation**: a safe, cost-bounded, validated query pipeline plus a handful of
narrow tools (count over time, count by dimension, sample events, scan estimate). It deliberately does **not**
implement error grouping (2B), HCL Commerce awareness (2C), CDN/WAF/EKS analysis (2D+), baseline comparison,
spike detection or root-cause reasoning. Those later phases consume the primitives defined here.

Non-negotiables carried over from Phase 1: strictly read-only in effect, no generic AWS or query executor,
no credentials/secrets in output, FACT / ANALYSIS / RECOMMENDATION separation, honest "no data" results.

## 2. Current architecture (Phase 1, validated)

```
Claude Desktop -> local aws-cloudwatch-mcp (stdio) -> boto3 -> profile ob-aws-cloudwatch
   -> IAM user cloud-watch-log-review -> account 926266574832 -> CloudWatch
```

Reusable Phase 1 building blocks:

| Component | Reuse in 2A |
|---|---|
| `AwsClients.verify_account()` + pinned account | unchanged; every Insights call goes through it |
| `before-call` read-only guard + allow-list (`aws/client.py`) | **must be extended** (Section 8.4): it currently blocks every `Start*`/`Stop*` operation |
| `LogsService` discovery, allowlist (`LOG_GROUP_ALLOWLIST`), name regex | log-group selection and validation |
| `resolve_range` / `TimeRange` | time-range parsing, with new Insights-specific ceilings |
| `sanitize_text`, sanitizing stderr formatter | applied to every returned row and every log line |
| `TTLCache`, `ToolResult` envelope, `guarded()` wrapper, config ceilings | reused; new limits follow the same "hard ceiling" pattern |
| Tool pattern `build_tools(runtime)` | new `tools/insights_tools.py` |

## 3. Proposed Phase 2A architecture

Strict layering. Each layer only calls downward; **AWS access never mixes with reasoning**.

```
 Claude (LLM) ── maps the user's words to STRUCTURED tool arguments (the server never parses natural language)
      │
 L5  tools/insights_tools.py     thin MCP tools: argument schema, ToolResult envelope, no logic
      │
 L4  analysis/  (pure functions) deterministic statistics over normalized rows: totals, shares, peak bin, ...
      │                          no AWS, no I/O, unit-testable with plain data
 L3  insights/results.py         normalization: AWS field/value rows -> typed rows, sanitize, cap, drop @ptr
      │
 L2  insights/planner.py         QueryPlan (structured) -> vetted template -> rendered query string
     insights/validator.py       allow-list validation of the plan AND the rendered string
      │
 L1  insights/executor.py        lifecycle: estimate, cost guard, start, poll, stop, cache, dedupe, rate limit
      │
 L0  aws/insights_client.py      the ONLY code that calls StartQuery/GetQueryResults/StopQuery,
                                 behind the Insights gate (Section 8.4)
```

Key design decisions:

1. **Template-only, no query strings from Claude.** Tools accept structured parameters (a closed vocabulary of
   presets, literal terms, status codes, time range, log groups). The server renders the Logs Insights query from
   vetted templates. There is **no tool that accepts a query string**. A "validated raw query" tool is explicitly
   deferred (Open question Q7) because the language is broad and growing (Appendix A lists commands such as `join`,
   `lookup`, `subqueries`, `SOURCE`, `unmask`).
2. **Validator as a tripwire, not the primary defence.** Because queries are generated from templates, the
   validator's job is to catch template bugs and injection through user-supplied literals, and to be the
   mandatory gate for any future raw-query path.
3. **Boto-level enforcement.** A gate on the boto3 client refuses `StartQuery` unless the exact request was
   pre-approved by the validator, and refuses `GetQueryResults`/`StopQuery` unless the `queryId` was started by this
   process. Even a coding mistake elsewhere cannot start an unvalidated query.
4. **The MCP does deterministic calculation only.** The "AI reasoning" layer is Claude. The server returns
   FACT (from AWS), ANALYSIS (deterministic calculations over those facts, each with `evidence` references) and
   RECOMMENDATION (human-action suggestions, never executed). The server does not speculate about causes in 2A.
5. **Opt-in.** Insights tools are registered only when `INSIGHTS_ENABLED=true` (default `false`), so Phase 1 keeps
   working unchanged until you have applied the Insights IAM permissions and reviewed this design.

## 4. Required AWS APIs (Phase 2A)

| API | IAM action | Why | Classification |
|---|---|---|---|
| `StartQuery` | `logs:StartQuery` | Run the Insights query (and the `| estimate` pre-flight) | **REQUIRED**. AWS access level "Write" **[V]** |
| `GetQueryResults` | `logs:GetQueryResults` | Poll status and fetch results | **REQUIRED**. Read **[V]** |
| `StopQuery` | `logs:StopQuery` | Cancel on timeout/deadline/user request. AWS says a running query otherwise keeps running; the query-string docs warn that abandoned console queries "continue to run until completion" **[V]**. Not required for correctness, **required for cost control** | **REQUIRED (control)**. Write **[V]** |
| `GetCallerIdentity` | none | Account pin (existing) | already in Phase 1 |

**Are the three sufficient for 2A? Yes.** Log-group discovery and stream listing already exist from Phase 1
(`DescribeLogGroups`, `DescribeLogStreams`). Estimate, count, group-by and sample queries need nothing else.

## 5. Optional AWS APIs and the ones we do NOT need

| API / action | Verdict | Reasoning |
|---|---|---|
| `logs:DescribeQueries` | **NOT CURRENTLY NEEDED - recommend NOT granting** | It lists queries in the whole account, returning each `queryString` and `userIdentity` **[V]**. That exposes other people's queries (which may embed sensitive terms) and adds nothing we need, because the process tracks its own `queryId`s. Only benefit: cleaning up orphans after a crash; covered instead by the app-side estimate cap plus AWS's 60-minute timeout **[V]**. |
| `logs:GetLogGroupFields` | **OPTIONAL, defer to 2C** | Samples field names of a log group. Useful when HCL/CDN log schemas must be discovered. In 2A the fixed templates only use `@timestamp`, `@message`, `@log`; a discovery need can be met with the sample-events tool. |
| `logs:GetLogRecord` | **NOT CURRENTLY NEEDED** | Fetches the *full* record behind an `@ptr` **[V]**. That would bypass the "only projected fields are returned" property and enlarge data exposure. Not needed for counts/samples. |
| `logs:StartLiveTail`, `logs:PutQueryDefinition`, saved/scheduled queries | **NEVER** | Not read-only in spirit; out of scope. |
| KMS permissions | **[U]** | If query results are encrypted with a customer-managed KMS key in this account, extra permissions may be needed **[U]** (StartQuery doc mentions a results-encryption key **[V]** but not who needs which KMS action). Surface AccessDenied honestly; do not pre-grant. |

## 6. IAM permissions

### 6.1 Draft policy (NOT applied; do not copy until Q2 is resolved)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InsightsStartQueryOnApprovedGroupsOnly",
      "Effect": "Allow",
      "Action": "logs:StartQuery",
      "Resource": [
        "arn:aws:logs:us-east-1:926266574832:log-group:<APPROVED_GROUP_PATTERN_1>:*",
        "arn:aws:logs:us-east-1:926266574832:log-group:<APPROVED_GROUP_PATTERN_2>:*"
      ],
      "Condition": { "StringEquals": { "aws:RequestedRegion": "us-east-1" } }
    },
    {
      "Sid": "InsightsPollAndStopQueries",
      "Effect": "Allow",
      "Action": ["logs:GetQueryResults", "logs:StopQuery"],
      "Resource": "*",
      "Condition": { "StringEquals": { "aws:RequestedRegion": "us-east-1" } }
    }
  ]
}
```

Notes: (a) The API's `logGroupIdentifiers` ARN form must **not** end in `:*` **[V]**, whereas IAM policies use the
`log-group:NAME:*` convention (the same form already validated for `FilterLogEvents`/`GetLogEvents` in Phase 1).
(b) `GetQueryResults`/`StopQuery` use `"*"` in the draft because the two sources I consulted **disagree** on whether
they accept a `log-group` resource type **[U]** (Q2). A policy that names an unsupported resource type silently
matches nothing (denies). Resolve with IAM Policy Simulator or a one-line manual test before finalizing. This also
means the Phase 1 document's statement that these actions have "no resource type" needs re-verification.
(c) Access-level column: AWS lists `StartQuery` and `StopQuery` as **Write**, `GetQueryResults` as **Read** **[V]**.

### 6.2 Security implications of granting them (must be understood and accepted explicitly)

1. **The write classification is real.** `StartQuery` creates a query job (no resource in your account is modified),
   but IAM reviewers, Access Analyzer and SCPs will treat it as write. The project's statement "strictly read-only"
   becomes "read-only with respect to your infrastructure and data; it creates transient, billed query jobs".
2. **IAM cannot cap cost.** `StartQuery` has no parameter bounding data scanned **[V]** (the full parameter list is
   `endTime, limit, logGroupIdentifiers|logGroupName|logGroupNames, queryLanguage, queryString, startTime`).
   Anyone holding the profile's credentials can run expensive queries directly, bypassing every guard in this
   MCP. The MCP's cost controls only protect against the MCP's own behaviour. Real limits come from IAM
   *scoping* (which log groups) plus AWS Budgets/billing alarms (outside this project).
3. **The query language can reach beyond the named log groups.** A `SOURCE` command inside `queryString` can select
   log groups by prefix/account/class/tag **[V]**, and `join`, `lookup`, `subqueries` bring in other data
   **[V]**. Resource-scoped IAM would still deny unpermitted groups, but the app-level allowlist can be bypassed
   by a naive pass-through. Hence template-only queries plus an allow-list validator that rejects these commands.
4. **`unmask` reveals data masked by a data-protection policy [V]** (command list). Blocked unconditionally.
5. **`GetQueryResults` / `StopQuery` accept a bare `queryId`.** A caller who knows another principal's `queryId`
   could read results or cancel their query if IAM allows. IDs are unguessable but `DescribeQueries` would
   reveal them; we do not grant it and the gate only allows IDs this process started.
6. **Shared quotas.** Interactive queries share the concurrent-query quota with dashboards and scheduled queries
   (up to 100 concurrent) **[V]**; `StartQuery` and `GetQueryResults` are each throttled at 10 TPS per
   account/region and are **not adjustable** **[V]**. A runaway MCP can degrade other users' dashboards.
7. **Recommendation (human decision):** keep `StartQuery` scoped to an explicit list of approved log groups, not
   `log-group:*`; consider a **separate IAM user/profile for Insights** so it can be enabled/disabled and audited
   independently of the Phase 1 profile (Q1); set an AWS Budgets alert for CloudWatch Logs.

## 7. Query lifecycle

| # | Step | Owner | Notes / failure handling |
|---|---|---|---|
| 1 | User request | user | free text |
| 2 | Intent extraction | **Claude** | Claude maps the request to a tool + structured arguments. The server performs no NL parsing. |
| 3 | Time-range validation | L2 | presets/ISO; ceilings (Section 11); future/inverted/over-max -> `invalid_input` |
| 4 | Log-group selection | L2 | explicit list validated against allowlist + existence; categories resolve only to a *proposed* list (Section 12) |
| 5 | Query generation | L2 planner | vetted template + closed-vocabulary parameters; literals escaped by a builder (no string concatenation of raw input) |
| 6 | Query validation | L2 validator | Section 8; on success the request fingerprint is registered as approved (single use, 60 s TTL) |
| 6b | **Estimate pre-flight** | L1 | run the same query with `\| estimate` appended **[V: no Insights charges; approximate]**; compare with per-query byte cap and remaining session budget; fail closed if it cannot be obtained |
| 7 | `StartQuery` | L0 | only via the gate; explicit `queryLanguage="CWLI"`, `limit`, epoch seconds |
| 8 | Poll `GetQueryResults` | L1 | adaptive schedule (Section 15); status in `Scheduled/Running/Complete/Failed/Cancelled/Timeout/Unknown` **[V]** |
| 9 | Timeout handling | L1 | wait budget expires -> either return a handle (still running) or stop, per Section 15 |
| 10 | `StopQuery` | L1 | on deadline, cancel request, or process shutdown; only owned IDs; "already ended" error is treated as success **[V]** |
| 11 | Result normalization | L3 | field/value pairs -> dict rows; drop `@ptr`; sanitize + truncate every string; cap rows; record statistics |
| 12 | Analysis | L4 | deterministic calculations only, each linked to evidence |
| 13 | Final response | L5 | `ToolResult` envelope; explicit empty/partial/error semantics |

State machine of one `QueryJob`: `PLANNED -> VALIDATED -> ESTIMATED -> STARTED -> POLLING -> {COMPLETE | FAILED |
TIMED_OUT_APP -> STOPPING -> CANCELLED | CANCELLED_BY_USER | AWS_TIMEOUT}`; every terminal state releases its
concurrency slot and records actual bytes scanned in the budget ledger.

## 8. Query validation architecture

### 8.1 Two validation stages

**Stage A - plan validation (structured input).** Rejects before any string is built:
log-group count/pattern/allowlist/existence; time range and window ceilings; template id in the registry;
each parameter against its type, length and charset (Section 8.3); result limit <= configured cap; total plan
budget (estimated bytes) checked later at 6b.

**Stage B - rendered-string validation.** Runs on the final query text (tripwire + gate input):

| Check | Rule |
|---|---|
| Length | <= `INSIGHTS_MAX_QUERY_CHARS` (default 2,000; the API allows 10,000 **[V]**) |
| Character set | printable ASCII plus a small allowed punctuation set; **no comments** (`#`), no control characters, no newlines except those the renderer emits |
| Tokenization | split on top-level `\|` while respecting quoted strings and `/regex/` literals; unbalanced quote/regex/paren -> reject |
| Stage count | <= `INSIGHTS_MAX_STAGES` (default 6, excluding the appended `estimate`) |
| Command allow-list | first token of every stage must be in **ALLOWED** (below); anything else, including unknown/new commands -> reject (**allow-list, not block-list**, because the language keeps growing) |
| Terminal bound | the query must end in `stats` (bounded output) or `limit N` with N <= row cap, so output size is bounded |
| Language | `queryLanguage` must be exactly `CWLI`; SQL/PPL embed log-group selection inside the query string **[V]** and are rejected |
| Log-group parameters | exactly one of `logGroupNames`/`logGroupIdentifiers`; each name matches `[\.\-_/#A-Za-z0-9]+` **[V]** and the allowlist; count <= cap |
| Time | `startTime < endTime`, both inside the validated range, integer epoch seconds **[V]** |

### 8.2 Command policy for Phase 2A

| Command | 2A | Reason |
|---|---|---|
| `fields`, `filter` (and its alias `where`), `stats`, `sort`, `limit`, `display`, `dedup` | **ALLOWED** | needed for counts, group-bys, samples |
| `parse` | **ALLOWED, glob mode only or server-owned regex** | field extraction (e.g. status code) from server-owned patterns only; no user-supplied regex |
| `estimate` | **ALLOWED, system-appended, last stage only** | cost pre-flight **[V: must be the last command]** |
| `pattern`, `diff`, `logcompare`, `anomaly`, `filterIndex`, `unnest`, `countFrequent`, `outlier`, `fillmissing`, `filldown`, `accum`, `autoregress`, `addtotals`, `sessionize`, `relevantfields`, `expand` | **DEFERRED** | useful for 2B/2C/8 (grouping, baselines, spikes); each needs its own review |
| `SOURCE`, `join`, `lookup`, `subqueries`, `appendcols`, `cidrlookup` | **BLOCKED** | reach outside the selected log groups / external data (bypass of scope) |
| `unmask` | **BLOCKED** | reveals data masked by a data-protection policy |
| SQL / PPL languages | **BLOCKED** | log groups chosen inside the query text |

Infrequent Access log groups support all CWLI commands except `pattern`, `diff`, `unmask` **[V]**; `filterIndex` is
also unsupported there **[V]**. 2A templates avoid all of these, so log class does not matter.

### 8.3 User-influenced values (the injection surface)

Claude may supply only: log-group names, time range, a **preset id** from a fixed catalog, up to 3 literal
`contains` terms, up to 3 literal `exclude` terms, up to 8 HTTP status codes, and enumerated options
(`group_by`, `bin`, `limit`). Literals: charset `[A-Za-z0-9 _.:/=@-]`, length <= 64, escaped by the renderer,
matched as literal substrings (never interpreted as regex). **No regex, no field names, no functions and no
commands come from Claude.** Presets map to server-owned, reviewed regexes.

### 8.4 Boto-level Insights gate (defence in depth)

Extend `aws/client.py` so the general guard stays as is (still rejects `Start*`/`Stop*`) but a second,
Insights-specific gate handles exactly three operations:

* `StartQuery`: allowed only if the outgoing parameters are exactly `{queryString, startTime, endTime, limit,
  logGroupNames|logGroupIdentifiers, queryLanguage="CWLI"}` **and** the request fingerprint
  (hash of queryString + groups + times) is in the **ApprovedQueryRegistry** (created only by the validator,
  single-use, 60 s TTL). Implementation should hook botocore's parameter-level event so it sees the caller's
  parameters (to be confirmed against the installed botocore during implementation).
* `GetQueryResults` / `StopQuery`: allowed only if `queryId` is in the **OwnedQueryRegistry** (filled from the
  `StartQuery` response).
* Everything else, including any other `Start*`/`Stop*`, remains blocked. Unit tests use real boto clients to prove
  that unapproved `StartQuery` and foreign `queryId` calls are refused **before any network I/O**.

## 9. Cost controls

What AWS can and cannot enforce (do not assume otherwise):

| Concern | AWS-side control? | Application-level guard (proposed) |
|---|---|---|
| Max data scanned per query | **None.** No such StartQuery parameter **[V]** | `| estimate` pre-flight **[V]** vs `INSIGHTS_MAX_ESTIMATED_BYTES`; fail closed if unavailable |
| Max runtime | AWS times a query out after 60 min **[V]** | our own deadline, default 180 s, then `StopQuery` |
| Max result rows | `limit` <= 100,000; 10,000 per `GetQueryResults` page **[V]** | default 200 rows, hard ceiling 2,000; templates always bound output |
| Concurrent queries | 100 per account/region, shared with dashboards/scheduled queries **[V]** | max 2 concurrent from this MCP (ceiling 5) |
| Request rate | `StartQuery` 10 TPS and `GetQueryResults` 10 TPS, not adjustable **[V]** | token buckets far below these (Section 17) |
| Time range | none | max window 24 h default, ceiling 168 h |
| Log-group breadth | up to 50 groups per query **[V]** | default 5, ceiling 20; IAM resource scoping |
| Repeated identical queries | none | result cache + in-flight de-duplication |
| Query complexity | none beyond 10,000 chars **[V]** | <= 2,000 chars, <= 6 stages, command allow-list |
| Abandoned queries | keep running to completion **[V]** | `StopQuery` on deadline/cancel/shutdown |
| Spend over time | none (use AWS Budgets) | per-process byte budget (default 20 GiB); optional persisted daily ledger (Q4) |

Illustrative cost model (**price [U]**): cost = bytes scanned / 1 GB x price-per-GB. The pricing page I fetched did
not state the figure or whether failed/cancelled queries are billed **[U]**; a commonly cited us-east-1 rate is
$0.005 per GB scanned but **confirm on the pricing page/Cost Explorer**. Configure `INSIGHTS_PRICE_PER_GB_USD`
only after confirming; until then tools report bytes only. With the defaults (2 GiB per query, 20 GiB per
session) the bound on MCP-initiated spend would be about `2 x price` per query and `20 x price` per session.
Actual bytes come from `statistics.bytesScanned` **[V]** and reconcile the ledger after each query; failed or
stopped queries are counted at the last reported bytes (pessimistic assumption).

## 10. Security controls (summary)

* Template-only queries; allow-listed commands; literals escaped; no regex/field/command input from Claude.
* Insights gate at boto level; approved-request and owned-query registries; `queryId`s never accepted from Claude.
  Claude receives an opaque `query_handle`, mapped to the `queryId` in-process.
* Account pin, read-only allow-list, and Phase 1 controls remain in force.
* `INSIGHTS_ENABLED=false` by default; IAM resource scoping recommended (Section 6).
* Rows sanitized (secrets patterns) and truncated (`MAX_MESSAGE_CHARS`) before leaving the process; only
  projected fields returned; `@ptr` dropped; response-size budget enforced.
* Log content is labelled `untrusted_log_content: true`; server `instructions` tell Claude that log text is data
  and must never be followed as instructions (prompt-injection hygiene).
* Observability to stderr only, via the sanitizing formatter: template id, request fingerprint (hash), group
  count, range, estimated/actual bytes, duration, status, cache hit. **Never** log query terms, log messages,
  credentials or tokens.
* Thread-safety: registries, limiter, cache and budget use locks (tool handlers may run concurrently).

## 11. Time-range controls

| Rule | Value |
|---|---|
| Accepted forms | `lookback` (`15m`, `1h`, `6h`, `24h`, `7d`) or ISO-8601 `start`/`end` (existing parser) |
| Default window | `1h` |
| Standard maximum | `INSIGHTS_MAX_RANGE_HOURS` = **24 h** |
| Extended range | up to **168 h (7 d)** only if the estimate succeeds, is under the byte cap and groups <= 3; otherwise rejected with the reason |
| Hard ceiling | 168 h in code; not overridable by `.env` |
| Rejected | inverted, empty, future `end` (clamped to now), or unparsable |
| Units | API times are epoch **seconds** **[V]** (one AWS example shows milliseconds **[U]**; confirm with the first manual test) |
| Bin size | auto-chosen so a series has <= ~100 buckets: <=1 h -> 1 min; <=6 h -> 5 min; <=24 h -> 15 min; <=7 d -> 1 h (overridable within an allowed set) |
| Retention | facts include each group's retention (from `DescribeLogGroups`); a window older than retention is flagged so "no data" is not misread |
| Ingestion delay | very recent minutes may be incomplete **[U]**; the last bucket is flagged `possibly_incomplete` |
| Comparisons | "today vs yesterday" = two separate bounded queries, designed for 2B/8; not a 2A tool |

## 12. Log-group selection strategy

1. **Never "all groups".** The run tools require an explicit `log_groups` list (<= `INSIGHTS_MAX_LOG_GROUPS`).
2. Each name must match `[\.\-_/#A-Za-z0-9]+`, match `LOG_GROUP_ALLOWLIST` (if set) and exist in the (cached)
   discovery listing; unknown names -> `not_found` with suggestions, never silently dropped.
3. `category` (HCL Commerce, EKS, Nginx, CloudFront/CDN, WAF, EC2, ALB/NLB, Application, Infrastructure, ...)
   is used only to **propose** groups (existing name heuristics). If the resolved set exceeds the cap the tool
   refuses and returns the candidate list; it never truncates silently. Categories are heuristics on names, so
   they are labelled as such.
4. Optional named scopes (a local JSON such as `config/insights_scopes.json`: `{"hcl-commerce": ["<glob>", ...]}`)
   bounded by the allowlist; decision pending (Q6).
5. `estimate` is available before any run so Claude can shrink scope by group/range first.
6. Note for ALB/NLB: **ALB/NLB access logs are delivered to S3, not CloudWatch Logs** by default **[U for this
   account]**; 2A can query only what is actually in CloudWatch Logs. Availability must be checked per group.

## 13. Result model

Same envelope as Phase 1 (`FACT`, `ANALYSIS`, `RECOMMENDATION`, `status`, `warnings`, `meta`, `error`) with
Insights-specific content:

```
FACT
  query:        {template, preset/terms (echo of accepted literals, sanitized), fingerprint, query_language:"CWLI"}
  scope:        {log_groups:[...], time_range:{start,end,seconds}, bin_seconds, retention_days_by_group}
  aws:          {status:"Complete", statistics:{bytes_scanned, records_matched, records_scanned, ...}, aws_calls}
  cost:         {estimated_bytes, actual_bytes, budget_remaining_bytes, est_cost_usd|null}
  rows|series:  normalized data, capped; {"row_count": n, "truncated": bool}
  untrusted_log_content: true              (whenever any row echoes log text)
ANALYSIS      list of {statement, method:"calculated", evidence:["FACT.series[14]", ...]}
RECOMMENDATION list of strings, auto-prefixed "RECOMMENDATION (human decision required; nothing was executed)"
```

2A analysis is limited to deterministic arithmetic: totals, per-group share, first/last non-empty bin, peak bin and
its value, count of empty bins, comparison of the peak with the median bin **of the same series**. Baselines from a
different period, spike verdicts and cause statements are out of scope. Every ANALYSIS line references evidence;
claims without evidence are not emitted.

## 14. Error handling

| Situation | Result |
|---|---|
| `AccessDeniedException` on StartQuery/GetQueryResults/StopQuery | `access_denied` + hint naming the action and `docs/IAM-*` |
| `MalformedQueryException` | `query_rejected_by_aws` (internal template bug); report the sanitized error, not an invented result |
| `LimitExceededException` (concurrency) | back off once, then `concurrency_limit`; the circuit breaker (Section 17) engages after repeats |
| Throttling / `ServiceUnavailableException` | bounded retries with backoff (boto adaptive retries + limited app retries), then `throttled`/`aws_error` |
| `ResourceNotFoundException` (log group or queryId) | `not_found` |
| Validation failure | `query_rejected` (names the rule broken; never echoes unsafe text) |
| Estimate over cap / budget exhausted | `cost_guard` with numbers (estimated vs cap, remaining budget) and how to narrow |
| Estimate unavailable | fail closed: `cost_guard` "could not estimate"; no query is run |
| App wait timeout | `running` with handle, or stopped -> `query_timeout` (Section 15) |
| AWS status `Failed` / `Cancelled` / `Timeout` / `Unknown` **[V]** | reported verbatim as `query_failed` with the status; no data invented |
| Empty result | status `empty`, summary exactly: **"No matching log data was found for the selected time range and log groups."** plus a note that this does not establish system health (logging may be off, groups/range wrong, retention, or ingestion delay) |
| Partial results while `Running` **[V]** | never presented as final; flagged `partial: true` and, for `stats`, "counts are lower bounds" |
| KMS/other AWS errors **[U]** | surfaced with the AWS code; no guessing |

## 15. Timeout / polling strategy

* **Wait budget:** `INSIGHTS_WAIT_SECONDS` default 40 (ceiling 55), chosen to stay under typical client tool-call
  timeouts (Claude Desktop's exact timeout is not confirmed **[U]**).
* **Adaptive schedule:** first poll after ~1 s, then 1.5, 2, 3, 4, 5 s and a 5 s cap, +/-10% jitter; ~10 polls in
  40 s. A global limiter keeps `GetQueryResults` at <= 2 calls/s (AWS allows 10 TPS, not adjustable **[V]**).
* **Cheap polling:** poll with a tiny `maxItems`, then fetch the full page only when `Complete` **[U: confirm
  behaviour of small `maxItems` against a real query; fall back to full polls if it misbehaves]**.
* **When the wait budget expires (recommended, Q3):** return `status: "running"` with an opaque `query_handle`;
  the query remains owned by the process with a hard deadline (`INSIGHTS_MAX_QUERY_SECONDS`, default 180 s) after
  which it is stopped; the user/Claude can call `aws_insights_get_results(query_handle)`. Overdue queries are
  stopped by a lightweight reaper (checked on every tool call, plus a daemon timer and an exit hook). *Simpler
  alternative:* stop immediately and ask for a narrower range. Trade-off: handles avoid wasting a partially
  completed scan but add lifecycle code.
* **Shutdown:** stdio EOF/termination triggers `StopQuery` for owned running queries. A hard kill cannot; the
  estimate cap plus the 60-minute AWS timeout bound the damage.
* Paging: `nextToken` pages (10,000 rows/page **[V]**, token valid 1 hour **[V]**) are followed only up to the row cap.

## 16. Caching strategy

| Cache | Key | TTL / bound | Notes |
|---|---|---|---|
| Result cache | fingerprint of {template, normalized params, groups, range with `end` rounded down to the minute} | 120 s default, max 32 entries, max size per entry | only `Complete`, sanitized, non-error results; cache hits are labelled `cached: true, age_s` and consume no budget |
| In-flight de-duplication | same fingerprint | lifetime of the job | a second identical request attaches to the running job, no second `StartQuery` |
| Estimate cache | fingerprint | 300 s | estimates are cheap but count toward rate limits |
| Discovery cache | existing (log groups) | 60-300 s | reused for existence checks |

Errors, partial and cost-guard refusals are never cached. Cached content contains nothing beyond what would have
been returned uncached (already sanitized).

## 17. Rate limiting

* Token bucket for `StartQuery`: burst 3, refill 1 per 2 s; hard cap 6 query starts/minute (estimate + run count
  as separate starts). AWS limit is 10 TPS **[V]**.
* `GetQueryResults` <= 2/s overall.
* Concurrency semaphore: 2 in-flight jobs (ceiling 5).
* **Circuit breaker:** after 3 consecutive `LimitExceededException`/throttling responses, refuse new starts for
  60 s with a clear message (protects dashboards sharing the quota **[V]**).
* Limits are per MCP process; another process or person using the same profile is not visible to this limiter.

## 18. Example safe queries (rendered from templates; illustrative)

The exact syntax must be verified with `| estimate` and real runs during implementation **[U]**; the log field
names depend on each log format (unstructured HCL text vs JSON).

```
# T1  count_over_time  (preset: errors)
filter @message like /(?i)(error|exception|fatal)/
| stats count(*) as matches by bin(15m)

# T2  count_by  (dimension: log_group)
filter @message like /(?i)(error|exception|fatal)/
| stats count(*) as matches by @log
| sort matches desc
| limit 20

# T3  count_by  (dimension: status_code, codes 403/404/502/503/504; unstructured text, anchored pattern)
filter @message like /\b(403|404|502|503|504)\b/
| parse @message /\b(?<status>403|404|502|503|504)\b/
| stats count(*) as matches by status

# T4  sample_events  (limit 20, projected fields only)
fields @timestamp, @log, @message
| filter @message like /(?i)timeout/
| sort @timestamp desc
| limit 20

# Pre-flight variant of any template
<template> | estimate
```

Precision caveat: `like /503/` on unstructured text matches any "503" (ports, ids). The tools therefore anchor
patterns (`\b`), label results as substring/regex matches on `@message`, and 2C/2D replace this with field-based
queries for known log formats.

## 19. Example user requests and how Phase 2A serves them

| # | User request | 2A path |
|---|---|---|
| 1 | "Show me errors from the last 24 hours." | `aws_insights_count_over_time` (preset `errors`, 24 h) then `aws_insights_sample_events` |
| 2 | "Top errors in HCL Commerce?" | discovery proposes groups; `count_by` `log_group`; distinct message shapes = **2B** |
| 3 | "How many 403/404/502/503/504?" | `aws_insights_count_by` `status_code` |
| 4 | "When did the spike start?" | `count_over_time` returns series with first non-empty and peak bins; spike *decision* = 2B/8 |
| 5 | "Which log groups generate the most errors?" | `count_by` `log_group` |
| 6 | "Which component generates them?" | `count_by` `log_stream`/`log_group`; component parsing = 2C |
| 7 | "Error trend over 24 hours." | `count_over_time` |
| 8 | "Compare today with yesterday." | two bounded `count_over_time` calls by Claude; automatic comparison = 8 |
| 9 | "Find unusual spikes." | **future** (statistical analysis layer) |
| 10 | "Investigate the cause of the 503 spike." | **future** (cross-service correlation); 2A supplies the evidence series |

## 20. Example expected response (ILLUSTRATIVE numbers; not real data)

Request: `aws_insights_count_over_time(log_groups=["<group>"], preset="http_5xx", status_codes=[503], lookback="6h")`

```json
{
  "tool": "aws_insights_count_over_time", "status": "ok", "read_only": true,
  "summary": "412 matching events in 6h across 1 log group (bin 5m).",
  "FACT": {
    "query": {"template": "count_over_time", "match": {"status_codes": [503]}, "query_language": "CWLI"},
    "scope": {"log_groups": ["<group>"], "time_range": {"start": "...", "end": "...", "seconds": 21600},
              "bin_seconds": 300, "retention_days_by_group": {"<group>": 30}},
    "aws": {"status": "Complete", "statistics": {"bytes_scanned": 81349723, "records_matched": 412,
            "records_scanned": 610956}},
    "cost": {"estimated_bytes": 90000000, "actual_bytes": 81349723, "est_cost_usd": null},
    "series": [["2026-09-20T13:55:00Z", 3], ["2026-09-20T14:00:00Z", 2], ["2026-09-20T14:20:00Z", 96]],
    "row_count": 72, "truncated": false, "untrusted_log_content": false
  },
  "ANALYSIS": [
    {"statement": "Total 412; peak 96 in the 14:20 UTC bucket; median bucket 2.",
     "method": "calculated", "evidence": ["FACT.series[*]"]},
    {"statement": "First non-empty bucket 08:05 UTC; 41 of 72 buckets are empty.",
     "method": "calculated", "evidence": ["FACT.series[*]"]}
  ],
  "RECOMMENDATION": ["RECOMMENDATION (human decision required; nothing was executed): compare load-balancer and pod metrics around 14:15-14:25 UTC to see whether the 14:20 bucket coincides with other signals."],
  "warnings": ["Matching is a regex/substring match on @message, so counts may include unrelated occurrences.",
               "The most recent bucket may be incomplete (ingestion delay)."]
}
```

Empty case: `status: "empty"`, summary "No matching log data was found for the selected time range and log groups."
Error case: `status: "error"`, `error: {kind: "cost_guard", message: "Estimated scan 6.3 GiB exceeds the 2 GiB per-query cap ..."}`.

## 21. Threat model

| # | Threat | Vector | Mitigation |
|---|---|---|---|
| T1 | Prompt injection via log content | attacker-controlled text in logs is returned to Claude and contains "instructions" | rows marked `untrusted_log_content`; server `instructions` say log text is data; tools cannot do more than bounded read-only queries; no tool takes free-form queries |
| T2 | Query-language injection | crafted literal terms | closed vocabulary; strict charset/length; renderer escapes; literals never regex; stage-B validator |
| T3 | Scope bypass | `SOURCE`/`join`/`lookup`/SQL/PPL in the query text | allow-list validator rejects them; language pinned to `CWLI`; IAM resource scoping |
| T4 | Reading masked data | `unmask` | blocked |
| T5 | Cost amplification | wide range, many groups, high-cardinality `stats by`, repeated calls | estimate pre-flight, byte caps, session budget, range/group caps, template design (bounded group-bys), cache/dedupe, rate limits |
| T6 | Resource exhaustion of shared quotas | many concurrent queries/polls | concurrency 2, token buckets, circuit breaker |
| T7 | `queryId` misuse | reading/stopping other users' queries | owned-ID registry; opaque handles; `DescribeQueries` not granted |
| T8 | Information disclosure through results | secrets/PII in messages | sanitizer, truncation, field projection, row caps, no `@ptr`/`GetLogRecord`, logs never contain messages |
| T9 | Credential exposure | logs/errors | unchanged Phase 1 controls; sanitizing formatter |
| T10 | Runaway/orphaned queries | crash, kill, disconnect | deadline + `StopQuery`, exit hook, estimate cap, AWS 60 min timeout |
| T11 | Stale or misleading data | cache, partial results, ingestion delay | cache labelling, partial flags, incomplete-last-bucket warning |
| T12 | Validator/parser differential | our tokenizer disagrees with AWS parser | allow-list rejects the unknown; templates keep the grammar tiny; AWS `MalformedQueryException` surfaced |
| T13 | Stolen laptop credentials | attacker uses the profile outside the MCP | out of app scope: IAM scoping, key rotation, budgets, optional separate Insights user |
| T14 | Time-range abuse | inverted/huge/future ranges | reused `resolve_range` + Insights ceilings |
| T15 | False confidence | "no data" read as "healthy" | mandated wording; retention/ingestion notes; no health claims |

## 22. Known limitations

* Insights queries only ingested data within retention; absence of rows is not evidence of health.
* No AWS-enforced scan cap; the estimate is approximate **[V]** and adds an extra API round trip per query.
* Unstructured HCL/text logs make status-code and error detection regex-based and approximate; JSON logs allow
  precise field queries (2C/2D).
* ALB/NLB/CloudFront standard access logs are typically in S3, not CloudWatch **[U]**; not reachable in 2A.
* The account currently has 8 log groups (4 `internet-monitor`, `aws-CDN-prod-main-log`, and 3 others); the field
  structure of each is unknown and must be learned before 2D.
* Prices, billing of failed/stopped queries, results retention period and Claude Desktop tool timeout are
  unconfirmed **[U]**.
* Limits are per process; no cross-process coordination; no persistent ledger unless Q4 is approved.
* One region/account; no cross-account observability.

## 23. Phase 2B dependencies (error classification and grouping)

2B needs from 2A: bounded `sample_events` and `count_by` primitives; the row cap and sanitizer; the preset catalog
(errors/exceptions/timeouts/connection/DB/Redis/Solr/auth/TLS/DNS/OOM); the result model; the executor's
cost guard. 2B adds: message normalization (mask ids, numbers, UUIDs, IPs) and grouping in Python over a bounded
sample or over a top-K list obtained with a bounded `stats count(*) by <server-defined key>`; first/last seen per
group; affected-log-group attribution. It must not require unbounded `stats by @message` on high-cardinality logs.

## 24. Future WAF / CDN / EKS integration points

* A shared normalized **`Series`** (timestamps + values + bin) and **`Evidence`** (source, time window, fact
  reference) model so Insights bins and `GetMetricData` series align on the same bins for correlation.
* **Pluggable template packs** per source, registered with the same planner/validator (no new execution path):
  WAF (JSON fields such as action/terminating rule/client attributes), CloudFront/CDN (`aws-CDN-prod-main-log`
  and Internet Monitor groups exist here), EKS Container Insights and pod logs, HCL Commerce (ts-app, ts-web,
  search-app, Solr, Redis, DB2 patterns), Nginx.
* Correlation chain (later): CloudFront -> WAF -> ALB -> EKS -> HCL Commerce -> Solr/Redis/DB2 using aligned
  series plus the Phase 1 metric/alarm tools; each link is an `Evidence` item, conclusions carry confidence
  tied to available evidence.
* Each pack adds fields/commands only through the reviewed allow-list process (Section 8.2).

## 25. Proposed MCP tools for Phase 2A

Common to all: registered only if `INSIGHTS_ENABLED=true`; read-only annotations
(`readOnlyHint=true`, `destructiveHint=false`) even though AWS classifies StartQuery as Write; no tool accepts a
query string, an AWS API name, an action, a queryId supplied by the caller (only opaque handles), or free regex.

**Common match vocabulary (used by the count/sample tools):**
`preset` in {`errors`, `exceptions`, `timeouts`, `connection_problems`, `http_4xx`, `http_5xx`, `oom`, `auth_failures`,
`tls_errors`, `dns_errors`}; `contains` (<=3 literals); `exclude` (<=3 literals); `status_codes` (<=8 ints, 100-599).

| Tool | Purpose | Inputs | Outputs | AWS APIs | Security | Cost |
|---|---|---|---|---|---|---|
| `aws_insights_estimate_scan` | Preview scope and scan size before running | `log_groups`, range, match vocabulary, template kind | resolved groups, retention, estimated bytes, verdict vs caps and budget | `StartQuery` (with `\| estimate`), `GetQueryResults` | validator + gate; estimate only | estimate incurs no Insights charges **[V]**; counts toward rate limits |
| `aws_insights_count_over_time` | Event counts per time bin (trend, first/peak bins) | `log_groups`, range, match vocabulary, `bin?` | series, totals, peak/first/last bins, stats | `StartQuery`, `GetQueryResults`, (`StopQuery`) | template-only, gate | estimate pre-flight, byte cap, session budget, cache, dedupe |
| `aws_insights_count_by` | Counts grouped by a dimension | same + `dimension` in {`log_group`, `log_stream`, `status_code`}, `top_n` <= 20 | ranked counts with shares | same | same; dimension is an enum, not a field name | same; group-by cardinality bounded by enum + `limit` |
| `aws_insights_sample_events` | A few recent matching events as examples | groups, range, match vocabulary, `limit` <= 20 | sanitized truncated events | same | rows sanitized/truncated, `untrusted_log_content` | limit <= 20 rows; same guards |
| `aws_insights_get_results` | Poll or finish a job that outlived the wait budget | `query_handle` | status, results if complete | `GetQueryResults` | owned handle only | no new scan |
| `aws_insights_cancel_query` | Cancel a job started by this server | `query_handle` | cancelled / already finished | `StopQuery` | owned handle only | stops further scanning |
| `aws_insights_budget_status` | Show limits, budget used, in-flight jobs, limiter/breaker state | none | local state only | none | no AWS call | none |

Explicitly **not** created: `aws_execute`, `aws_query`, `aws_run_any_command`, `generic_cloudwatch_query`,
or any tool taking a raw Insights query.

## 26. Test strategy (to implement with Phase 2A; nothing implemented now)

All tests use botocore Stubber and fake clocks; no AWS access; a network-blocking fixture is applied globally.

| Area | Tests |
|---|---|
| Unit | planner renders each template deterministically; renderer escaping; registries; fingerprinting; normalization; statistics; config ceilings |
| Query validation | allow-list accept/reject matrix; every BLOCKED command in varied casing/whitespace/comment/pipe-inside-string obfuscations; unbalanced quotes/regex; length and stage caps; missing terminal bound; SQL/PPL rejected; literal-charset fuzz (property-based); user literal cannot terminate a string/regex or inject `\|`; validator rejects unknown future commands |
| Time-range | presets, ISO, inverted, future, > standard max, > 7 d hard ceiling, bin selection per range, retention-older-than-window flag, epoch-seconds conversion |
| Cost guard | estimate over cap refused; estimate unavailable fails closed; session budget exhaustion; budget reconciliation with actual bytes; failed/stopped queries counted; extended-range rules; cache hit consumes no budget |
| Timeout | wait budget expiry -> handle path and stop path; deadline reaper; fake-clock polling schedule (counts, jitter bounds, cap); AWS `Timeout` status |
| Cancellation | `StopQuery` on deadline/user/shutdown; "already ended" treated as success; foreign `queryId` refused; stop not attempted for unknown handles |
| IAM failure | AccessDenied on each of the three APIs; hint text; partial permission sets (Start allowed, GetQueryResults denied) |
| Empty result | exact sentence; no health claim; status `empty`; retention note |
| Malformed query | `MalformedQueryException` surfaced as internal error without leaking user text |
| Large result | row cap, pagination across `nextToken`, response-size budget, truncation flags, downsampled series |
| Sensitive data | secrets in rows redacted; `@ptr` dropped; queries/terms/messages absent from stderr logs; `untrusted_log_content` set; credentials never present |
| AWS API errors | throttling/`LimitExceededException` with backoff and circuit breaker; `ServiceUnavailable`; `ResourceNotFound`; unknown status |
| Gate (real clients) | unapproved `StartQuery`, altered parameters after approval, replayed approval, foreign `queryId`, other `Start*`/`Stop*` operations all raise before any network I/O |
| Concurrency | limiter under threads; semaphore; in-flight dedupe; registry thread-safety |
| Static | extend the existing source scan: no raw query pass-through, no `DescribeQueries`/`GetLogRecord` in allow-list |
| Regression | all 137 Phase 1 tests unchanged and passing; Insights tools absent when `INSIGHTS_ENABLED=false` |

## 27. Recommended default limits

| Setting | Default | Hard ceiling |
|---|---|---|
| `INSIGHTS_ENABLED` | `false` | - |
| `INSIGHTS_MAX_RANGE_HOURS` | 24 | 168 |
| `INSIGHTS_MAX_LOG_GROUPS` | 5 | 20 (AWS max 50 **[V]**) |
| `INSIGHTS_MAX_RESULT_ROWS` | 200 | 2,000 (AWS max 100,000 **[V]**) |
| `INSIGHTS_MAX_ESTIMATED_BYTES` (per query) | 2 GiB | 50 GiB |
| `INSIGHTS_SESSION_BYTES_BUDGET` | 20 GiB | 200 GiB |
| `INSIGHTS_REQUIRE_ESTIMATE` | `true` (fail closed) | cannot be disabled in 2A |
| `INSIGHTS_MAX_CONCURRENT` | 2 | 5 |
| `INSIGHTS_MAX_STARTS_PER_MINUTE` | 6 | 20 |
| `INSIGHTS_WAIT_SECONDS` | 40 | 55 |
| `INSIGHTS_MAX_QUERY_SECONDS` (app deadline) | 180 | 900 (AWS timeout 3,600 **[V]**) |
| `INSIGHTS_MAX_QUERY_CHARS` | 2,000 | 4,000 (AWS max 10,000 **[V]**) |
| `INSIGHTS_MAX_STAGES` | 6 | 8 |
| `INSIGHTS_CACHE_TTL_SECONDS` / entries | 120 / 32 | 900 / 128 |
| `INSIGHTS_PRICE_PER_GB_USD` | unset (bytes only) | - |
| sample events `limit` | 20 | 50 |
| top-N in `count_by` | 10 | 20 |

## 28. Open design questions

| # | Question | Recommendation |
|---|---|---|
| Q1 | Reuse the Phase 1 IAM user or create a separate Insights user/profile? | Separate profile, so Insights can be revoked and audited independently |
| Q2 | Do `GetQueryResults`/`StopQuery` support a log-group resource, and what exact ARN form does `StartQuery` need? (sources conflict) | Verify with IAM Policy Simulator or a manual test before writing the final policy; use `"*"` for the two until proven |
| Q3 | Handle-based continuation vs stop-on-timeout? | Handle-based with a hard deadline and reaper |
| Q4 | Persisted daily byte ledger across restarts? | Yes if you want spend limits that survive restarts (small local JSON, no secrets); otherwise per-process only |
| Q5 | Confirm Logs Insights price per GB and billing of failed/stopped queries | Confirm on the pricing page/Cost Explorer before setting `INSIGHTS_PRICE_PER_GB_USD` |
| Q6 | Named log-group scopes file? | Yes, bounded by `LOG_GROUP_ALLOWLIST` |
| Q7 | Ever allow a validated raw-query tool? | Not in 2A; revisit after 2B with real usage evidence |
| Q8 | Allow 7-day windows in 2A? | Yes but only behind the estimate cap and <= 3 groups |
| Q9 | Which of the 8 existing groups are in scope and what are their log formats? | Do a manual, minimal schema look (one `estimate` and one 20-row sample per group) before 2D |
| Q10 | Claude Desktop tool-call timeout? | Measure; adjust `INSIGHTS_WAIT_SECONDS` |
| Q11 | Are query results KMS-encrypted in this account? | Check; adds possible KMS permissions |
| Q12 | Real behaviour of `\| estimate` through `StartQuery` (result shape) and epoch seconds vs ms | Confirm with one manual CLI run before coding |

## 29. Exact implementation order for Phase 2A (after your approval)

0. **You decide** Q1, Q2, Q4, Q6, Q8. **You apply IAM** (after review). **You run manual CLI checks** (these use
   StartQuery, a Write-classified action, so I will not run them): one tiny `| estimate` query on a single small
   group and range to learn the real result shape and time units (Q12); optionally a 15-minute count. I never
   run these.
1. Config and limits (pure): new settings, ceilings, `INSIGHTS_ENABLED`. Tests.
2. Time-range and bin policy (pure). Tests.
3. Query plan model, template registry, renderer/escaper (pure). Tests.
4. Validator stages A and B (pure) with the full malformed/obfuscation matrix. Tests.
5. Registries and the boto-level Insights gate in `aws/client.py`; static-scan updates. Tests with real clients.
6. Result normalizer and deterministic statistics (pure). Tests.
7. Executor: estimate, cost guard, start/poll/stop, limiter, breaker, cache, dedupe, budget, reaper, shutdown hook.
   Stubber + fake clock tests.
8. Tools in this order: `budget_status` -> `estimate_scan` -> `count_over_time` -> `count_by` -> `sample_events`
   -> `get_results` -> `cancel_query`; register behind `INSIGHTS_ENABLED`.
9. Docs: IAM document for Phase 2A, README, correct the Phase 1 IAM note about resource types (Q2).
10. **Real validation, one step at a time with your approval:** (a) `estimate_scan` on one group, (b) one 15-min
    `count_over_time` with a tiny estimate, (c) timeout/cancel path with an artificially small wait budget.
Stop for review after each numbered group.

## 30. What must NOT be implemented in Phase 2A

* Any raw or "validated raw" query tool; any tool taking a query string, AWS action or API name.
* SQL/PPL, `SOURCE`, `join`, `lookup`, `subqueries`, `appendcols`, `cidrlookup`, `unmask`.
* Deferred commands (`pattern`, `diff`, `logcompare`, `anomaly`, `filterIndex`, `unnest`, ...).
* Error classification/grouping (2B), HCL Commerce-specific logic (2C), CDN/WAF/EKS/EC2/ALB analysis, baselines,
  spike/anomaly detection, correlation, root-cause statements.
* `DescribeQueries`, `GetLogGroupFields`, `GetLogRecord`, Live Tail, saved/scheduled queries, export tasks.
* Cross-account observability, background auto-run queries, dashboards, write-type tools of any kind.
* Any change to Phase 1 behaviour when `INSIGHTS_ENABLED=false`.

---

## Appendix A - Verification ledger (AWS documentation fetched while writing; 2026-09-20)

**Verified [V]** (AWS API reference / user guide pages):

* StartQuery: parameters `endTime, limit, logGroupIdentifiers, logGroupName, logGroupNames, queryLanguage, queryString,
  startTime`; times are epoch seconds; `queryString` up to 10,000 chars; `limit` 1-100,000 (10,000 per
  `GetQueryResults` page); up to 50 log groups; exactly one of the three log-group parameters unless `SOURCE`
  (or SQL/PPL source syntax) selects groups; `queryLanguage` in `CWLI|SQL|PPL`; queries time out after 60 minutes;
  up to 100 concurrent Insights queries, shared with dashboards and scheduled queries; ARN form for identifiers has no
  trailing `*`; no parameter limits bytes scanned; errors: `InvalidParameterException`, `LimitExceededException`,
  `MalformedQueryException`, `ResourceNotFoundException`, `ServiceUnavailableException`.
* GetQueryResults: statuses `Scheduled|Running|Complete|Failed|Cancelled|Timeout|Unknown`; `Running` returns partial
  results; `statistics` {`bytesScanned`, `estimatedBytesSkipped`, `estimatedRecordsSkipped`, `logGroupsScanned`,
  `recordsMatched`, `recordsScanned`, `resultCount`}; `maxItems` 0-10,000; `nextToken` expires after 1 hour; only
  requested fields plus `@ptr` returned; `@ptr` usable with `GetLogRecord`.
* StopQuery: errors if the query already ended; cancels only the identified execution.
* DescribeQueries: returns `queryString`, `logGroupName`, `userIdentity`, `bytesScanned`, status, etc.
* Quotas: `StartQuery` 10 TPS and `GetQueryResults` 10 TPS per account/region, both not adjustable.
* Query syntax: full command list (including `join`, `lookup`, `subqueries`, `SOURCE`, `unmask`, `estimate`);
  `estimate` returns estimated bytes without running the query, incurs no Insights charges, must be the last command,
  is approximate; Infrequent Access class restrictions; `SOURCE` usable only via CLI/programmatically; best-practice
  warning that abandoned queries continue to run.
* Service Authorization Reference: `StartQuery` access level Write with log-group resource types; `StopQuery`
  Write; `GetQueryResults`/`DescribeQueries`/`GetLogGroupFields`/`GetLogRecord` Read.

**Unverified or conflicting [U]:** resource types for `GetQueryResults`/`StopQuery`/`DescribeQueries` (two fetches
disagreed; the Service Authorization page could not be reproduced verbatim); price per GB and billing of
failed/cancelled queries (pricing page did not contain it); how long query results stay retrievable; the exact result
shape of `| estimate` through the API; epoch seconds vs milliseconds (an AWS example uses milliseconds); behaviour of
small `maxItems` while polling; Claude Desktop tool-call timeout; KMS requirements for reading results; CloudTrail
visibility of these calls; whether this account's ALB/NLB/CDN logs are in CloudWatch or S3; ingestion delay.

---

## Appendix B - Post-validation corrections (real-AWS step V2, 2026-09-20)

* **Estimate and the API `limit` (amends Sections 7, 8, 9).** The lifecycle step "run the same query with `| estimate`
  appended" must send the estimate **without** the API `limit` parameter. Real AWS rejected the estimate with
  `MalformedQueryException: unexpected symbol found limit`: the API `limit` is applied as a trailing stage, so it would
  come after `estimate`, which must be the final command **[V: observed in real AWS; explanation inferred]**. Real queries
  keep their bounded `limit`. Details: `PHASE-2A-IMPLEMENTATION-PLAN.md` Section 19.
* **Regions (amends Sections 2 and 12).** Phase 1 uses `AWS_REGION` (`us-east-1`); Logs Insights uses the independent
  `AWS_INSIGHTS_REGION`, same account `926266574832`. The log-group existence/retention lookup follows the Insights
  region. **Validated 2026-09-20: the eight PROD CloudWatch log groups are in `us-east-1`** (none exist in
  `ap-southeast-1`), so `AWS_INSIGHTS_REGION=us-east-1`. The variable stays separate so another region can be used later.
