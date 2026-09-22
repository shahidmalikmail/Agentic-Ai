# Phase 2A - IAM / profile design for CloudWatch Logs Insights (Q1)

**Status: Q1 DECIDED (dedicated IAM user + profile for the current implementation). The identity, its access key, its policy and the CLI profile are still PROPOSED: NOTHING IN THIS DOCUMENT HAS BEEN CREATED, CONFIGURED OR APPLIED.**

This resolves Phase 2A design question **Q1** ("separate IAM identity/profile for Logs Insights?") on paper.
It creates no IAM user, no access key, no policy, no AWS CLI profile, no Claude Desktop entry and no code.
Related: [`PHASE-2A-LOGS-INSIGHTS-DESIGN.md`](PHASE-2A-LOGS-INSIGHTS-DESIGN.md), [`IAM-REQUIRED-PHASE1.md`](IAM-REQUIRED-PHASE1.md).

Markers: **[V]** = checked against AWS documentation. **[U]** = UNVERIFIED (unknown, ambiguous or conflicting).
Where sources conflict the conflict is preserved (Section E), not resolved by assumption.

## Decision summary

| Topic | Proposed decision |
|---|---|
| Q1 | **DECIDED by the project owner: use a separate identity and a separate AWS CLI profile for Insights** (dedicated IAM user for the current implementation; see "Decision record" below). |
| Phase 1 identity | unchanged: profile `ob-aws-cloudwatch`, IAM user `cloud-watch-log-review` |
| Phase 2A profile name | `ob-aws-cloudwatch-insights` (proposed, not configured) |
| Phase 2A identity | dedicated IAM user `cloud-watch-insights-review` (proposed, not created); role-based alternatives in Section C |
| Permissions | exactly `logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery` (+ `sts:GetCallerIdentity`, which needs no grant) |
| Resource scoping | **UNVERIFIED** for `GetQueryResults` and `StopQuery` (Q2). `StartQuery` scoping is documented by one source and unexercised. |
| Account/region pin | unchanged and applied to both profiles: `AWS_ACCOUNT_ID=926266574832`, `AWS_REGION=us-east-1` |
| Security wording | "read-only access to application/infrastructure data through tightly constrained Logs Insights query jobs" (Section I) |
| AWS resources | **NOT CREATED.** The IAM user, its access key, the policy and the `ob-aws-cloudwatch-insights` profile must still be created manually by the project owner (or with explicit approval). Code is developed and tested against mocks; nothing in the code requires them to exist until the real-AWS validation sequence. |

### Decision record (added when Phase 2A implementation planning began)

* **Q1 = DECIDED.** For the current implementation (local Windows laptop + Claude Desktop) Phase 2A uses a
  **dedicated IAM user and AWS CLI profile**: user `cloud-watch-insights-review`, profile
  `ob-aws-cloudwatch-insights`, account `926266574832`, region `us-east-1` (Option 1 in Section C.1). Role-based
  identities or IAM Identity Center remain a later hardening option (N1).
* **AWS resources are not created.** Creating the user, access key, policy and profile is a manual step (or needs
  explicit approval) and has not happened. The Section D policy remains **"PROPOSED ONLY - DO NOT APPLY"**.
* **Q2 is still OPEN and UNVERIFIED** (Section E): sources conflict on whether `GetQueryResults`/`StopQuery`
  accept a log-group resource, and the `StartQuery` policy ARN form is unconfirmed. The implementation must not
  depend on resource-level scoping working; it must function with `"Resource": "*"` for those two actions.
* All other open questions (Section M) are unchanged.

---

## A. Objective

Phase 1 uses only APIs that AWS classifies as List/Read (`Describe*`, `Filter*`, `Get*`, `List*`). Their IAM
policy can honestly be called read-only.

Phase 2A adds Logs Insights **query-job APIs**:

| API | AWS access level [V] | What it does |
|---|---|---|
| `StartQuery` | **Write** | creates a transient query job that scans log data and is billed by data scanned |
| `GetQueryResults` | Read | reads the results/status of a job |
| `StopQuery` | **Write** | cancels a running job |

These do not modify your infrastructure or logs, but they are not "Read" actions. Putting them on the Phase 1
identity would change what that identity can do, and would make the statement "the Phase 1 credentials can only
read" false. A separate identity gives:

1. **Blast-radius separation.** A leaked or misused Phase 1 credential still cannot start billed query jobs.
2. **Independent revocation.** Insights can be switched off (deactivate one key / detach one policy) without
   touching Phase 1.
3. **Distinct audit trail.** The calling principal identifies which identity ran a query job (CloudTrail
   visibility of these calls is **[U]**, to be confirmed).
4. **Least privilege per capability.** The Phase 1 policy stays at 8 read grants; the Insights policy is 3 actions.
5. **Cleaner review.** An IAM/security reviewer sees one identity that is read-only and one that is
   "query-job only", instead of a blended identity.
6. **Cost attribution** for scanned data (by principal) and a natural place for an AWS Budgets alert.

Honest costs: two credentials to manage and rotate, a second profile, a second session in the MCP process, more
configuration to get wrong. On a single laptop both keys live in the same `~/.aws` directory, so this is
**logical separation, not protection against malware running as your Windows user**.

## B. Proposed AWS CLI profile (NOT configured)

| Item | Value |
|---|---|
| Profile name | `ob-aws-cloudwatch-insights` |
| Region | `us-east-1` |
| Account | `926266574832` |
| Configured by | you, later, with `aws configure --profile ob-aws-cloudwatch-insights` (interactive; keys are typed only into the AWS CLI prompt) |

The existing `ob-aws-cloudwatch` profile is **not touched**. Nothing in this project creates or edits
`~/.aws/credentials` or `~/.aws/config`.

## C. Proposed IAM identity (NOT created)

### C.1 Options

| Option | Description | For | Against |
|---|---|---|---|
| **1. Dedicated IAM user** (proposed) | New user `cloud-watch-insights-review`, no console access, one access key, one customer-managed policy (Section D) | Same operating pattern as Phase 1; no coupling to the Phase 1 identity; trivially revocable | long-lived access key on the laptop. AWS's IAM overview page describes attaching policies directly to IAM users as **"Not recommended"** and prefers roles/federation **[V]** |
| 2. IAM role assumed from a *dedicated* source identity | Profile with `role_arn` + `source_profile` pointing at a new tiny user that can only assume the role | short-lived credentials for the actual permissions; aligns with AWS guidance | still a long-lived key (on the source user); more moving parts and config |
| 3. IAM role assumed from the Phase 1 profile | `source_profile = ob-aws-cloudwatch` | no new long-lived key | **couples the two identities**: whoever holds Phase 1 credentials can reach Insights (defeats reason 1 above); may require changing the Phase 1 user's permissions or trust configuration, which this design forbids; same-account trust semantics **[U]** |
| 4. IAM Identity Center (SSO) permission set | SSO profile | no long-lived keys; AWS-preferred pattern | depends on your organisation having Identity Center; unknown for this account **[U]** |

Recommendation: **Option 1 now** (matches the way Phase 1 was set up and keeps Phase 1 untouched), and revisit
Options 2 or 4 as hardening once Phase 2A is working. This is a human decision (Section M, N1).

### C.2 Proposed identity details (Option 1)

| Item | Proposed |
|---|---|
| IAM user name | `cloud-watch-insights-review` |
| Console (password) access | none |
| Access keys | exactly one, created and stored by you via the AWS CLI; never pasted into chat, code, docs or `.env` |
| Attached policies | one customer-managed policy containing only Section D |
| Groups / inline policies | none |
| Tags (optional) | e.g. `purpose=aws-cloudwatch-mcp-insights`, for cost attribution |
| Permissions boundary (optional, defence in depth) | the same three actions, so an accidental extra attachment cannot widen it |

## D. Least-privilege policy

### PROPOSED ONLY - DO NOT APPLY

Do not apply either variant until Q2 is settled by a human check (Section E) and the log-group ARNs are decided.
Placeholders in `<ANGLE BRACKETS>` are deliberately not filled in; **no resource ARN below has been verified to
work**.

**Variant S - preferred (scoped `StartQuery`):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InsightsStartQueryApprovedLogGroupsOnly",
      "Effect": "Allow",
      "Action": "logs:StartQuery",
      "Resource": [
        "arn:aws:logs:us-east-1:926266574832:log-group:<APPROVED_LOG_GROUP_NAME_1>:*",
        "arn:aws:logs:us-east-1:926266574832:log-group:<APPROVED_LOG_GROUP_NAME_2>:*"
      ]
    },
    {
      "Sid": "InsightsPollAndStopOwnJobs",
      "Effect": "Allow",
      "Action": ["logs:GetQueryResults", "logs:StopQuery"],
      "Resource": "*"
    }
  ]
}
```

**Variant W - fallback (only if scoping `StartQuery` proves not to work):** the same two statements with
`"Resource": "*"` for all three actions. This lets the identity start a query against **any** log group in the
account/region; the MCP allow-list would then be the only limiter for group choice, which is weaker. Use only with
explicit acceptance.

Notes:

* **Only three actions.** No `logs:*`, `cloudwatch:*`, `iam:*`, `s3:*`, KMS, or any other service; no
  `DescribeQueries`, `GetLogRecord`, `GetLogGroupFields`, `DescribeQueryDefinitions`, `PutQueryDefinition`,
  `StartLiveTail`, or any `Put*`/`Delete*`/`Create*`.
* **`GetQueryResults`/`StopQuery` use `"*"`** in both variants because their resource support is UNVERIFIED (E).
  This means the identity could read/stop *any* query in the account if it knew a `queryId`. The MCP mitigates this
  in software (only `queryId`s it started; opaque handles); IAM does not.
* The trailing `:*` on the `StartQuery` ARN follows the convention used for Phase 1 `FilterLogEvents` (validated),
  but for `StartQuery` it is **[U]**. The API's own `logGroupIdentifiers` parameter documents an ARN **without** a
  trailing `*` **[V]**; policy-resource format and API-parameter format are different things.
* `aws:RequestedRegion` conditions are **not** included, to avoid an unverified interaction. Adding
  `"Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}` is a reasonable hardening that must be
  tested first **[U]**.
* `sts:GetCallerIdentity` needs no permission **[V]** (verified for Phase 1).
* **No permission for `logs:DescribeLogGroups`** is granted to this identity: discovery, existence checks and
  retention facts keep using the Phase 1 identity (Section F).
* Whether these three actions are *sufficient* for the API flow is expected but not proven **[U]**: if any call is
  denied for an additional action, the AccessDenied message must be reported and reviewed; do not guess or widen.
* `logs:DescribeQueryDefinitions` is needed only to run *saved queries with parameters* **[V]**; the MCP never does.

## E. Resource scoping: what is known and unknown

### E.1 Evidence collected (documentation, fetched while preparing the Phase 2A design and this document)

| Source | What it said (as returned; some fetches are summaries, not raw table rows) |
|---|---|
| Service Authorization Reference, CloudWatch Logs - attempt 1 | `StartQuery`: Write, resource type `log-group` (not required). `GetQueryResults`: Read, **no resource type**. `StopQuery`: Write, **no resource type**. |
| Same page - attempt 2 | `StartQuery`: Write, `log-group` and `log-group:*`, condition keys `logs:logGroupName`, `aws:RequestedRegion`, `aws:ResourceTag`. `GetQueryResults`: Read, **`log-group`**. `StopQuery`: Write, **`log-group`**. |
| Same page - attempt 3 | could not reproduce the table verbatim (no data returned) |
| Logs permissions reference page | states generally that "for the Resource field, you can specify the ARN of a log group or log stream, or `*`"; gives **no per-action resource statement**; notes `StartQuery` needs `logs:DescribeQueryDefinitions` only for saved queries with parameters |
| Logs IAM overview page | ARN formats: log group `arn:aws:logs:REGION:ACCOUNT:log-group:NAME`; log stream `...:log-group:NAME:log-stream:STREAM`; access to log streams is controlled at log-group level; tags can control access; no per-action table |
| `StartQuery` API reference | `logGroupIdentifiers` ARNs use `arn:aws:logs:region:account-id:log-group:log_group_name` and "don't include an `*` at the end" |
| Empirical (Phase 1) | `DescribeLogGroups`, `DescribeLogStreams`, `FilterLogEvents`, `GetLogEvents` worked under the policy you applied; that says nothing about the three Insights actions |

### E.2 Conclusions

| Action | Resource-level permission | Status |
|---|---|---|
| `StartQuery` | log-group resource type reported by both Service Authorization attempts; exact ARN form for policy (`:*` or not) not confirmed; never exercised | **UNVERIFIED** (reported, not tested) |
| `GetQueryResults` | attempt 1 says none, attempt 2 says `log-group` | **UNVERIFIED - SOURCES CONFLICT** |
| `StopQuery` | attempt 1 says none, attempt 2 says `log-group` | **UNVERIFIED - SOURCES CONFLICT** |

Consequences preserved, not assumed away:

* A statement that names an unsupported resource type for an action **matches nothing (denies)**, which would break
  the flow; a statement using `*` always matches. That is why `*` is proposed for the two unverified actions.
* The earlier Phase 1 IAM document, Section 3, states `GetQueryResults`/`StopQuery` have "no resource type (`*`)".
  That statement is **UNVERIFIED and superseded by this document**. It should be corrected in a later step; it was
  intentionally not edited here.
* How to settle it (human, later): open the AWS Service Authorization Reference page "Actions, resources, and
  condition keys for Amazon CloudWatch Logs" (`https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncloudwatchlogs.html`)
  and read the *Resource types* column for the three actions; then confirm behaviourally in validation step 5
  (Section K) by attempting a scoped statement in a controlled test. Do not rely on this document's summary.

## F. Separation from Phase 1

| | Phase 1 | Phase 2A |
|---|---|---|
| AWS CLI profile | `ob-aws-cloudwatch` | `ob-aws-cloudwatch-insights` |
| IAM user | `cloud-watch-log-review` | `cloud-watch-insights-review` (proposed) |
| Actions | 8 List/Read grants (`IAM-REQUIRED-PHASE1.md`) | 3 query-job actions |
| Used by | all Phase 1 tools | only the Insights executor |
| Changed by Phase 2A? | **No.** No policy edit, no key change, no profile change | new, isolated |

Proposed runtime wiring (to be implemented later; nothing implemented now):

* **One MCP process, two AWS sessions.** New configuration names (proposed): `AWS_INSIGHTS_PROFILE` and the
  existing `INSIGHTS_ENABLED` from the design. The Insights session is created lazily and only when
  `INSIGHTS_ENABLED=true`. The Phase 1 session and all Phase 1 behaviour are unchanged when it is off.
* **Division of labour:** the Insights identity is used **only** for `StartQuery`/`GetQueryResults`/`StopQuery`
  (including the `| estimate` pre-flight). Log-group discovery, existence checks and retention facts continue to
  use the Phase 1 identity, which is why the Insights identity needs no `DescribeLogGroups`.
* **Identity-distinctness check:** at startup the MCP compares the two `sts:GetCallerIdentity` ARNs and **refuses to
  enable Insights if they are the same principal** (guards against setting `AWS_INSIGHTS_PROFILE` to the Phase 1
  profile, which would silently defeat the separation). An optional expected-ARN setting could additionally pin the
  Insights principal (Section M, N3).
* **Alternative (Section M, N2):** two separate MCP servers in Claude Desktop, one per profile. Cleaner isolation
  (each process holds one credential set; Insights can be toggled in Claude Desktop) at the price of duplicated
  discovery code and a second server entry.

## G. Credential handling

* Credentials live only in the AWS CLI shared files (Windows: `%USERPROFILE%\.aws\credentials` and `config`),
  **outside the repository**. This project never reads them directly; boto3 resolves the profile.
* **Not in `.env`, not in `.env.example`, not in Git.** `.gitignore` already excludes `.env`; the repository must
  never contain an access key, secret key, session token or key file. Optional hardening: run a secret scanner
  (for example gitleaks or git-secrets) as a pre-commit check **[not part of this step]**.
* **Claude Desktop receives only names/IDs**, never secrets: `AWS_PROFILE`, `AWS_INSIGHTS_PROFILE`, `AWS_REGION`,
  `AWS_ACCOUNT_ID`, `INSIGHTS_ENABLED`.
* Access keys must never appear in source code, logs, documentation, tests, prompts, chat or MCP responses. Tests use
  obviously fake keys in temp directories, as in Phase 1. The sanitizing log formatter and response sanitizer
  remain in force.
* **Never paste an access key into a conversation with an assistant.** Keys are entered only at the interactive
  `aws configure` prompt.
* Rotation and lifecycle (human-owned): rotate on a schedule (for example 90 days), deactivate before deleting,
  delete unused keys, and keep at most one active key for this user.
* Because both profiles sit in the same `~/.aws` directory, protect that directory with normal Windows account
  hygiene (disk encryption, screen lock, no shared user account).

## H. Account and region pinning

Phase 2A **continues to require** `AWS_ACCOUNT_ID=926266574832` and `AWS_REGION=us-east-1`.

* The account gate applies **per session**: the Insights session must independently pass `sts:GetCallerIdentity`
  and return `926266574832` before any `StartQuery`, `GetQueryResults` or `StopQuery`, **including the `| estimate`
  call**. A mismatch refuses every Insights operation and stays refused (same semantics as Phase 1).
* An Insights identity in a different account, or one equal to the Phase 1 principal, disables Insights only;
  Phase 1 tools keep working.
* The startup logs (stderr) include only the pinned account and profile *name*, never key material.
* `AWS_ACCOUNT_ID` remains required at startup, as today. A per-profile account setting is not proposed: one
  account, one pin.

## I. Read-only safety clarification

AWS IAM classifies `StartQuery` and `StopQuery` as **Write** actions **[V]** because they create and control query
jobs. The intended use is analysis, but the IAM permissions are not literally AWS "Read" actions. Therefore this
project's Phase 2A security model is:

> **Read-only access to application/infrastructure data through tightly constrained Logs Insights query jobs.**

It is **not** "the IAM permissions are Read-level". Concretely:

* The MCP never modifies AWS/Kubernetes resources, logs, IAM or configuration.
* The only state created in AWS is transient query jobs (billed by data scanned).
* Constraints are layered: dedicated identity, three actions only, log-group scoping where verified, MCP-side
  template-only queries, validation, cost pre-flight, rate limits and cancellation (see the Phase 2A design).
* IAM cannot cap scanned data **[V]**; a holder of these credentials can bypass every MCP guard. Treat the
  credentials as sensitive and use AWS Budgets/billing alerts (outside this project).

## J. Future IAM evolution

Later phases may need more permissions (for example `logs:GetLogGroupFields` for schema discovery, or service
metadata APIs for WAF/CloudFront/EKS/ALB/EC2). **None are added now.** Rule: a permission is added only when a
specific, implemented and reviewed feature needs it, with the exact API named, the reason documented, the
resource scoping verified, and a validation step defined. Permissions that are read-only in nature go to the
Phase 1 identity's policy only through a separate, explicit review; query-job actions stay on the Insights identity.

## K. Validation plan (FUTURE - NOT EXECUTED; each step is run by a human after review and approval)

Commands are illustrative shapes. Insights CLI syntax and the `estimate` behaviour are **[U]** and must be confirmed
against the AWS CLI reference when the time comes. Step 4 onward uses `StartQuery`, a Write-classified action, so
the assistant will not run these.

| # | Step | Method | Expected result | Stop if |
|---|---|---|---|---|
| 0 | Prerequisite: human-created dedicated identity and profile | console/CLI by you; the policy from Section D | profile `ob-aws-cloudwatch-insights` exists | any key is exposed anywhere |
| 1 | Identity | `aws sts get-caller-identity --profile ob-aws-cloudwatch-insights` | `Arn` = the new user (not `cloud-watch-log-review`) | ARN equals the Phase 1 principal |
| 2 | Account | same output | `Account` = `926266574832`; region `us-east-1` | any other account |
| 3 | Effective permissions without running anything (admin profile) | `aws iam simulate-principal-policy --policy-source-arn <NEW_USER_ARN> --action-names logs:StartQuery logs:GetQueryResults logs:StopQuery ...` (read-only IAM API). Simulator fidelity (SCPs, boundaries) must be read in AWS docs first **[U]** | the three allowed; everything else `implicitDeny` | any unexpected allow |
| 4 | Small estimate | one `start-query` with a tiny window on a single approved log group whose query ends in `| estimate`, then `get-query-results` | a bytes estimate row; learn its result shape and whether times are epoch seconds (an AWS example uses milliseconds **[U]**) | AccessDenied for an unlisted action: report it, do not widen blindly |
| 5 | One bounded query | `start-query` (window <= 15 min, one group, `limit`) + `get-query-results` until `Complete`; then check whether a policy scoped per Variant S works for `StartQuery` and resolve Q2 for the other two | `Complete` with `statistics`; documented outcome for Q2 | scan estimate exceeds the agreed cap |
| 6 | StopQuery | `start-query` on a slightly longer window, then `stop-query` on that `queryId` | `success` true, or "not running" if it already ended **[V]** | stop fails on a running query |
| 7 | Phase 1 unchanged | rerun the Phase 1 read-only CLI checks (`IAM-REQUIRED-PHASE1.md` Section 5); compare `list-attached-user-policies`, `list-user-policies`, `list-groups-for-user` for `cloud-watch-log-review` before/after (admin profile); confirm the Phase 1 profile's `get-caller-identity` is unchanged; the 137 Phase 1 tests still pass | identical to the baseline captured before step 0 | any difference |
| 8 | No unexpected permissions | simulator (or direct checks) for a deny list, for example `logs:DeleteLogGroup`, `logs:PutRetentionPolicy`, `logs:GetLogRecord`, `logs:DescribeQueries`, `logs:StartLiveTail`, `cloudwatch:PutMetricData`, `iam:*`, `s3:GetObject` | all `implicitDeny` | any allow |

Baseline capture (before step 0): record the Phase 1 user's attached/inline/group policies and the Phase 1
`get-caller-identity` output so step 7 has something exact to compare against. Do not print or copy
`~/.aws/credentials`.

## L. Explicit non-goals of this step

This step does **not**: create IAM users; create access keys; modify IAM policies; modify AWS CLI profiles or
credentials; modify the Claude Desktop config; modify MCP source code; implement Phase 2A; execute any Logs Insights
query or call `StartQuery`/`StopQuery`/`GetQueryResults`; touch any bastion; or change any production or non-production
infrastructure. It also does not edit `PHASE-2A-LOGS-INSIGHTS-DESIGN.md` or `IAM-REQUIRED-PHASE1.md`.

## M. Open questions

Carried forward from the Phase 2A design (Q-numbers unchanged) plus new ones from this document (N-numbers).

| # | Question | Status / recommendation |
|---|---|---|
| **Q1** | Separate identity/profile for Insights? | **DECIDED: yes** - dedicated IAM user/profile for the current implementation. AWS resources still to be created manually/with explicit approval. |
| **Q2** | Do `GetQueryResults` and `StopQuery` support a log-group resource? Exact policy ARN form for `StartQuery`? | **OPEN - UNVERIFIED, sources conflict** (Section E). Use `*` for the two until proven; settle by reading the Service Authorization table directly and by validation step 5 |
| Q4 | Persisted daily byte ledger? | open (design doc) |
| Q5 | Confirm Logs Insights price per GB and billing of failed/stopped queries | open, unverified |
| Q11 | Are query results KMS-encrypted in this account (extra KMS permissions)? | open, unverified |
| Q12 | Real `\| estimate` result shape and epoch seconds vs milliseconds | open; validation step 4 |
| N1 | User (Option 1) vs role-based identity (Options 2/4) given AWS's "not recommended" note on user-attached policies [V]? | DECIDED for the current implementation: Option 1 (dedicated IAM user); revisit roles/SSO later |
| N2 | One process with two sessions vs two MCP servers? | recommend one process with two sessions and a distinctness check; two servers if you want maximum isolation |
| N3 | Pin the expected Insights principal ARN in config? | recommend yes (optional setting) |
| N4 | Is the three-action policy sufficient for the real API flow, or will AWS name an extra action? | unknown; found only during steps 4-6 |
| N5 | Same-account `AssumeRole` trust semantics if a role option is chosen | UNVERIFIED; check AWS docs before choosing Options 2/3 |
| N6 | Is `aws:RequestedRegion` (or other) condition safe with these actions? | untested |
| N7 | Are `StartQuery`/`StopQuery` events visible in CloudTrail in this account, and is anyone watching? | unverified |
| N8 | Which log groups are "approved" for the `StartQuery` resource list (8 groups exist today)? | needs your decision before Variant S can be written |
| N9 | AWS Budgets / billing alert for CloudWatch Logs? | recommended, outside this project |
| N10 | Permissions boundary for the new user? | optional hardening |

## Appendix - sources consulted for this document

* AWS Service Authorization Reference, CloudWatch Logs (two attempts returned conflicting summaries; a third returned
  nothing usable).
* CloudWatch Logs permissions reference; CloudWatch Logs IAM access-control overview (ARN formats; the "not
  recommended" note on user-attached policies).
* `StartQuery` API reference (parameters, ARN format without trailing `*`, saved-query note), from the Phase 2A design work.
* AWS managed policy reference and `GetCallerIdentity` reference, from Phase 1 work.
Everything not attributed above is design proposal or marked **[U]**.

## Addendum - regions (2026-09-20)

Phase 1 remains in `us-east-1` (`AWS_REGION`). Phase 2A Logs Insights uses the independent `AWS_INSIGHTS_REGION`, which is
**`us-east-1`**: validated 2026-09-20, all eight PROD CloudWatch log groups are in `us-east-1` and none exist in
`ap-southeast-1` (the application/environment's association with another region is irrelevant to Logs Insights). Both
phases use the same account `926266574832` and the account pin applies to both. The Section D policy has **no**
`aws:RequestedRegion` condition, so it permits the three actions in any region; if a region condition is added later it must
name `us-east-1` (and any other region intentionally used). The Insights identity still needs no `DescribeLogGroups`: the
existence/retention lookup uses the Phase 1 *profile* with the Insights *region* (currently identical to Phase 1's region).
**This project does not change Phase 1 IAM.**
