# Phase 2A IAM apply guide (Logs Insights identity)

**STATUS: NOT EXECUTED. This guide is for a human operator. Nothing in it has been run, and the AWS resources it
describes do not exist yet.** The assistant/project code never creates IAM users, access keys, policies or profiles.

Companion files: [`PHASE-2A-IAM-POLICY-PROPOSED.json`](PHASE-2A-IAM-POLICY-PROPOSED.json) (the policy),
[`PHASE-2A-IAM-DESIGN.md`](PHASE-2A-IAM-DESIGN.md) (rationale, Q2), [`PHASE-2A-IMPLEMENTATION-PLAN.md`](PHASE-2A-IMPLEMENTATION-PLAN.md).

## 0. Read first

### 0.1 What is being created

| Item | Name |
|---|---|
| IAM user | `cloud-watch-insights-review` (no console password, one access key, one attached policy) |
| Customer-managed policy | `CloudWatchLogsInsightsQueryOnly-MCP` (content = `PHASE-2A-IAM-POLICY-PROPOSED.json`) |
| AWS CLI profile | `ob-aws-cloudwatch-insights` (region `us-east-1`) |
| Account | `926266574832` |

The Phase 1 identity (`cloud-watch-log-review`, profile `ob-aws-cloudwatch`) is **not modified** by any step here.

### 0.2 What the policy contains (exactly)

`logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery` - nothing else. No `logs:*`, no `DescribeLogGroups`,
`DescribeLogStreams`, `FilterLogEvents`, `GetLogEvents`, no `cloudwatch:*`, no `iam:*`, no `sts:*` (`GetCallerIdentity`
needs no permission), no other service.

### 0.3 Why every `Resource` is `"*"` - a TEMPORARY limitation

* **`GetQueryResults` / `StopQuery` - Q2, UNVERIFIED.** Two fetches of the AWS Service Authorization Reference disagreed on
  whether these actions accept a log-group resource (one said no resource type, one said `log-group`); the permissions
  reference and IAM overview pages give no per-action statement. A statement naming an unsupported resource type matches
  nothing and silently denies, so `"*"` is the only choice that cannot break the flow.
* **`StartQuery` - not scoped either**, although both fetches report a `log-group` resource type. Reasons: (a) the exact
  policy ARN form (with or without a trailing `:*`) is **UNVERIFIED** for this action and the API parameter documents an
  ARN *without* a trailing `*`; (b) the list of approved log groups (design question N8) is not decided; (c) I will not
  invent ARNs. A wrong ARN would silently deny and make validation impossible.
* **Consequence (accept it explicitly):** IAM does **not** limit which log groups this identity can query, and it can
  read/stop any query in the account if it knows a `queryId`. The limiters are, in order: the dedicated identity
  and its single key, the MCP's allow-list / template-only queries / validator / estimate cap / byte budget / rate limits
  (all planned, in `PHASE-2A-IMPLEMENTATION-PLAN.md`), and AWS Budgets (Section 8). IAM cannot cap data scanned
  (`StartQuery` has no such parameter).
* **This corresponds to "Variant W" in `PHASE-2A-IAM-DESIGN.md` Section D.** Tightening path: Section 10.
* `aws:RequestedRegion` is **not** in the policy (untested interaction). Optional hardening in Section 10.
* IAM policy JSON cannot carry comments; the `Sid` names (`Temporary...UnverifiedScoping`) mark the caveat in the policy itself.

### 0.3b Timing

Nothing in this guide is needed until the implementation reaches the real-AWS milestone (M9). Applying it earlier is harmless
but leaves an unused credential on the laptop; prefer to wait.

### 0.4 Ground rules (security)

1. Run IAM commands with an **administrator-capable profile you already have** (written `<ADMIN_PROFILE>` below). **Do not**
   use `ob-aws-cloudwatch` (Phase 1; it has no IAM access) and do not give the new user any IAM permissions.
2. **Never paste an access key, secret key or session token into a chat, prompt, ticket, document, `.env`, Git,
   source code, tests, logs or the Claude Desktop config.** Keys are entered only into the AWS CLI, which stores them in
   `%USERPROFILE%\.aws\credentials` (outside the repository).
3. Run commands from a PowerShell window; do not screen-share while creating the key.
4. Do not `type`/`cat`/open `%USERPROFILE%\.aws\credentials` in a shared or recorded session.
5. Stop and roll back (Section 9) at the first unexpected result.

### 0.5 Preconditions and baseline (before anything is created)

```powershell
# The admin profile must be in the right account:
aws sts get-caller-identity --profile <ADMIN_PROFILE>
#   expect Account = 926266574832

# Capture a Phase 1 baseline OUTSIDE the repository (contains no secrets: policy names/ARNs only):
$b = "$env:USERPROFILE\phase1-iam-baseline.txt"
"--- attached"  | Out-File $b -Encoding utf8
aws iam list-attached-user-policies --user-name cloud-watch-log-review --profile <ADMIN_PROFILE> | Out-File $b -Append -Encoding utf8
"--- inline"    | Out-File $b -Append -Encoding utf8
aws iam list-user-policies --user-name cloud-watch-log-review --profile <ADMIN_PROFILE> | Out-File $b -Append -Encoding utf8
"--- groups"    | Out-File $b -Append -Encoding utf8
aws iam list-groups-for-user --user-name cloud-watch-log-review --profile <ADMIN_PROFILE> | Out-File $b -Append -Encoding utf8
"--- identity (Phase 1 profile)" | Out-File $b -Append -Encoding utf8
aws sts get-caller-identity --profile ob-aws-cloudwatch | Out-File $b -Append -Encoding utf8
```

The AWS console works for Sections 1-3 as an alternative (IAM -> Users -> Create user, **no** console access, then
Permissions -> Attach policies directly -> Create policy -> JSON tab, paste the file's content). The CLI form below is
easier to make repeatable.

## 1. IAM user creation

```powershell
aws iam create-user --user-name cloud-watch-insights-review `
  --tags Key=purpose,Value=aws-cloudwatch-mcp-insights `
  --profile <ADMIN_PROFILE>
```

* **Do not** run `create-login-profile` (no console password). Do not add the user to any group.
* Expected: JSON with `User.Arn` = `arn:aws:iam::926266574832:user/cloud-watch-insights-review`.
* `EntityAlreadyExists` -> stop; a user with that name exists; inspect it before doing anything else.

## 2. Policy creation

Run from the repository root so the relative path resolves:

```powershell
$PolicyArn = aws iam create-policy `
  --policy-name CloudWatchLogsInsightsQueryOnly-MCP `
  --description "Logs Insights query jobs only (StartQuery/GetQueryResults/StopQuery) for aws-cloudwatch-mcp. Temporary wildcard resources." `
  --policy-document file://docs/PHASE-2A-IAM-POLICY-PROPOSED.json `
  --query Policy.Arn --output text --profile <ADMIN_PROFILE>
$PolicyArn      # expect arn:aws:iam::926266574832:policy/CloudWatchLogsInsightsQueryOnly-MCP
```

Verify the stored document equals the repository file (formatting differences are not policy differences):

```powershell
$live = aws iam get-policy-version --policy-arn $PolicyArn --version-id v1 --query PolicyVersion.Document --output json --profile <ADMIN_PROFILE> | ConvertFrom-Json | ConvertTo-Json -Depth 10 -Compress
$repo = Get-Content docs\PHASE-2A-IAM-POLICY-PROPOSED.json -Raw | ConvertFrom-Json | ConvertTo-Json -Depth 10 -Compress
$live -eq $repo     # expect True; if False, compare by eye before continuing
```

## 3. Policy attachment

```powershell
aws iam attach-user-policy --user-name cloud-watch-insights-review --policy-arn $PolicyArn --profile <ADMIN_PROFILE>

aws iam list-attached-user-policies --user-name cloud-watch-insights-review --profile <ADMIN_PROFILE>   # exactly one policy
aws iam list-user-policies          --user-name cloud-watch-insights-review --profile <ADMIN_PROFILE>   # PolicyNames: []
aws iam list-groups-for-user        --user-name cloud-watch-insights-review --profile <ADMIN_PROFILE>   # Groups: []
```

Attach **only** this policy. No AWS managed policies, no inline policies, no groups.

## 4. Access-key creation

Create exactly **one** key. The secret is shown by AWS **once** and cannot be retrieved again (lost -> delete that key and
create a new one).

**Method A - the secret is never printed** (recommended). The value passes through a PowerShell variable to the AWS CLI
(it is briefly visible as a command-line argument of the local `aws` process; PowerShell history stores the command
*text*, not the variable's value):

```powershell
$k = aws iam create-access-key --user-name cloud-watch-insights-review --profile <ADMIN_PROFILE> | ConvertFrom-Json
aws configure set aws_access_key_id     $k.AccessKey.AccessKeyId     --profile ob-aws-cloudwatch-insights
aws configure set aws_secret_access_key $k.AccessKey.SecretAccessKey --profile ob-aws-cloudwatch-insights
Remove-Variable k
```

**Method B - interactive.** Run `aws iam create-access-key --user-name cloud-watch-insights-review --profile <ADMIN_PROFILE>`,
type the two values into the `aws configure --profile ob-aws-cloudwatch-insights` prompts, then `Clear-Host`. The secret
is visible on screen and in scrollback: use only in a private session and never copy it anywhere else.

Either way: do **not** save the key to a file, the clipboard history, a password note in the repo, a chat or a ticket.

## 5. AWS CLI profile configuration

```powershell
aws configure set region us-east-1 --profile ob-aws-cloudwatch-insights
aws configure set output json      --profile ob-aws-cloudwatch-insights
aws configure list-profiles        # expect both ob-aws-cloudwatch and ob-aws-cloudwatch-insights
```

* Do not edit or re-run `aws configure` for `ob-aws-cloudwatch` (Phase 1).
* The profile lives only in `%USERPROFILE%\.aws\`. Nothing goes into `.env`, `.env.example`, the repository or the Claude
  Desktop config; Claude Desktop will later receive only the profile *name* (`AWS_INSIGHTS_PROFILE`), and only when the
  implementation is ready.

## 6. Account validation

```powershell
aws sts get-caller-identity --profile ob-aws-cloudwatch-insights
```

Expected: `Account` = `926266574832`; `Arn` = `arn:aws:iam::926266574832:user/cloud-watch-insights-review`.
**Stop** if the account differs or the ARN equals the Phase 1 principal (`.../user/cloud-watch-log-review`).

## 7. Permission validation (no query is started)

**7.1 Simulator (read-only IAM API, admin profile).** Advisory: read the simulator's documented limits (for example
organisation SCPs) before relying on it **[U]**; the real calls in 7.2 are the actual proof.

```powershell
$U = "arn:aws:iam::926266574832:user/cloud-watch-insights-review"

# expect: allowed
aws iam simulate-principal-policy --policy-source-arn $U `
  --action-names logs:StartQuery logs:GetQueryResults logs:StopQuery `
  --query "EvaluationResults[].[EvalActionName,EvalDecision]" --output table --profile <ADMIN_PROFILE>

# expect: implicitDeny for every row
aws iam simulate-principal-policy --policy-source-arn $U `
  --action-names logs:DescribeLogGroups logs:DescribeLogStreams logs:FilterLogEvents logs:GetLogEvents logs:GetLogRecord `
                 logs:DescribeQueries logs:GetLogGroupFields logs:PutQueryDefinition logs:DeleteLogGroup logs:PutRetentionPolicy `
                 cloudwatch:GetMetricData cloudwatch:PutMetricData cloudwatch:DescribeAlarms `
                 iam:ListUsers iam:CreateAccessKey s3:ListAllMyBuckets ec2:DescribeInstances `
  --query "EvaluationResults[].[EvalActionName,EvalDecision]" --output table --profile <ADMIN_PROFILE>
```

**7.2 Real negative checks with the new profile** (harmless reads; each is **expected to fail with AccessDenied**, which
proves nothing extra was granted):

```powershell
aws logs describe-log-groups --limit 1 --region us-east-1 --profile ob-aws-cloudwatch-insights
aws cloudwatch list-metrics --namespace AWS/Logs --region us-east-1 --profile ob-aws-cloudwatch-insights
aws iam list-users --profile ob-aws-cloudwatch-insights
```

**7.3 Permission probes for the granted actions using a non-existent query id** (no query is started; nothing can be
stopped because the id does not exist). Expected outcome **[U]**: an error such as `ResourceNotFoundException` (or a
parameter error) means the *action was authorised*; `AccessDeniedException` means the action is missing:

```powershell
aws logs get-query-results --query-id 00000000-0000-0000-0000-000000000000 --region us-east-1 --profile ob-aws-cloudwatch-insights
aws logs stop-query        --query-id 00000000-0000-0000-0000-000000000000 --region us-east-1 --profile ob-aws-cloudwatch-insights
```

`StartQuery` itself is deliberately **not** exercised here; it is validated later (IAM design Section K steps 4-6:
tiny `| estimate`, one bounded query, one stop) after the code is ready and with your approval. Report any
AccessDenied that names an action **other than** the three; do not widen the policy without review.

## 8. Security checks

```powershell
# a) the user has no console password (expect NoSuchEntity):
aws iam get-login-profile --user-name cloud-watch-insights-review --profile <ADMIN_PROFILE>
# b) exactly one access key, Status Active:
aws iam list-access-keys --user-name cloud-watch-insights-review --profile <ADMIN_PROFILE>
# c) exactly one attached policy, no inline policy, no groups, no other policy versions in use:
aws iam list-attached-user-policies --user-name cloud-watch-insights-review --profile <ADMIN_PROFILE>
aws iam list-policy-versions --policy-arn $PolicyArn --profile <ADMIN_PROFILE>     # one version, v1, IsDefaultVersion true
# d) Phase 1 unchanged - repeat the baseline commands from 0.5 into a second file and compare:
$c = "$env:USERPROFILE\phase1-iam-after.txt"    # (same five commands as 0.5, output to $c)
Compare-Object (Get-Content $b) (Get-Content $c)     # expect no differences
aws sts get-caller-identity --profile ob-aws-cloudwatch   # unchanged Phase 1 identity
```

Repository and workstation hygiene:

```powershell
git status --short                                  # no credential files, no .env changes staged
git grep -nE "AKIA[A-Z0-9]{16}|aws_secret_access_key" -- .    # expect no output (tests may use obviously fake values)
Select-String -Path (Get-PSReadLineOption).HistorySavePath -Pattern "AKIA[A-Z0-9]{16}"   # expect no match (no key typed into a command)
Test-Path .\.env ; # if it exists it must contain no AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN
```

Also (human, outside this repository): set an **AWS Budgets** alert on CloudWatch Logs cost (query charges are per GB
scanned and IAM cannot cap them), and decide who reviews CloudTrail for this user (visibility of these calls in CloudTrail is
**[U]**). Rotate the key on a schedule (for example 90 days); keep at most one active key.

## 9. Rollback / removal procedure

Order matters (each step is independently safe). Use `<ADMIN_PROFILE>`.

```powershell
# 0) Stop using it: remove INSIGHTS_ENABLED / AWS_INSIGHTS_PROFILE from the Claude Desktop env and restart it (once implemented).
# 1) Disable the key immediately (reversible):
aws iam list-access-keys --user-name cloud-watch-insights-review --profile <ADMIN_PROFILE>       # note the AccessKeyId (not secret)
aws iam update-access-key --user-name cloud-watch-insights-review --access-key-id <ACCESS_KEY_ID> --status Inactive --profile <ADMIN_PROFILE>
# 2) Delete the key:
aws iam delete-access-key --user-name cloud-watch-insights-review --access-key-id <ACCESS_KEY_ID> --profile <ADMIN_PROFILE>
# 3) Detach the policy:
aws iam detach-user-policy --user-name cloud-watch-insights-review --policy-arn $PolicyArn --profile <ADMIN_PROFILE>
# 4) Delete the user (must have no keys/policies/groups):
aws iam delete-user --user-name cloud-watch-insights-review --profile <ADMIN_PROFILE>
# 5) Delete the policy (must be detached everywhere; delete non-default versions first if any were added):
aws iam delete-policy --policy-arn $PolicyArn --profile <ADMIN_PROFILE>
```

6. **Remove the local profile** by hand: open `%USERPROFILE%\.aws\credentials` and `config` in an editor and delete only the
   `[ob-aws-cloudwatch-insights]` / `[profile ob-aws-cloudwatch-insights]` sections. **Do not** touch the
   `ob-aws-cloudwatch` sections. Do not print these files into a shared session.
7. **Verify the removal:**

```powershell
aws iam get-user --user-name cloud-watch-insights-review --profile <ADMIN_PROFILE>   # expect NoSuchEntity
aws configure list-profiles                                                           # ob-aws-cloudwatch-insights gone, ob-aws-cloudwatch present
aws sts get-caller-identity --profile ob-aws-cloudwatch                               # Phase 1 still works
aws logs describe-queries --status Running --region us-east-1 --profile <ADMIN_PROFILE>   # no orphaned Insights queries
```

Fast kill switch if something looks wrong: step 1 alone (deactivate the key) stops every Insights call within moments;
any running query is bounded by AWS's 60-minute timeout **[V]**. If a policy *change* (Section 10) misbehaves, restore the
previous version with `aws iam set-default-policy-version --policy-arn $PolicyArn --version-id v1`.

## 10. Later policy changes (NOT part of the initial apply)

Do these only as separate, reviewed steps, each tested with the checks in Sections 6-8:

1. **Region condition (optional hardening, untested [U]).** Add to both statements
   `"Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}}` via a new policy version
   (`aws iam create-policy-version --policy-arn $PolicyArn --policy-document file://<new.json> --set-as-default`); on any
   unexpected AccessDenied roll back with `set-default-policy-version --version-id v1`.
2. **Scope `StartQuery` to approved log groups** once N8 (the approved list) is decided. Replace the first statement's
   `Resource` with the approved log-group ARNs in this *shape* (placeholders; **the trailing `:*` is UNVERIFIED** for this
   action):
   `arn:aws:logs:us-east-1:926266574832:log-group:<APPROVED_LOG_GROUP_NAME>:*`.
   Test both directions with a tiny `| estimate` query: an approved group succeeds, a non-approved group returns
   AccessDenied. If the approved one is denied, roll back to `v1` and record the result in Q2.
3. **Resolve Q2** for `GetQueryResults`/`StopQuery`: read the *Resource types* column in the AWS Service Authorization
   Reference for CloudWatch Logs directly, then test any scoped statement behaviourally before adopting it. Keep `"*"` until proven.
4. Any additional permission requires a named feature, an explicit API, a documented reason, verified scoping and a
   validation step (`PHASE-2A-IAM-DESIGN.md` Section J). None are added now.

## 11. Checklist

- [ ] `<ADMIN_PROFILE>` confirmed in account `926266574832`; Phase 1 baseline captured (0.5)
- [ ] User created, no login profile, no groups (1)
- [ ] Policy created; stored document equals the repository file (2)
- [ ] Exactly one policy attached, none inline (3)
- [ ] Exactly one access key created without printing/pasting it (4)
- [ ] Profile `ob-aws-cloudwatch-insights` configured; Phase 1 profile untouched (5)
- [ ] `get-caller-identity` shows the new user in the right account, different from Phase 1 (6)
- [ ] Simulator and negative checks as expected; get/stop probes authorised (7)
- [ ] Security and hygiene checks clean; Budgets alert set; Phase 1 baseline unchanged (8)
- [ ] Rollback steps understood (9)
