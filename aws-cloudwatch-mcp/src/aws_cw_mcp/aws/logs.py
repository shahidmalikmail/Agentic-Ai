"""CloudWatch Logs: discovery, filtered search, stream listing, raw event reads.

Read-only APIs only: DescribeLogGroups, DescribeLogStreams, FilterLogEvents,
GetLogEvents. All list/read calls are paginated with hard page and result caps.
"""
from __future__ import annotations

import fnmatch
import re
from datetime import datetime, timezone
from typing import Optional

from aws_cw_mcp.aws.catalog import CATEGORY_KEYWORDS, keywords_for
from aws_cw_mcp.config import Config
from aws_cw_mcp.models.results import EMPTY, OK, PARTIAL, ToolResult
from aws_cw_mcp.utils.cache import TTLCache
from aws_cw_mcp.utils.errors import InputError, describe_exception
from aws_cw_mcp.utils.sanitize import sanitize_text
from aws_cw_mcp.utils.timerange import TimeRange

_LOG_GROUP_RE = re.compile(r"^[A-Za-z0-9_\-./#]{1,512}$")
_STREAM_RE = re.compile(r"^[^:*]{1,512}$")
_MAX_PATTERN_CHARS = 1024
_API_PAGE_LIMIT = 10000  # FilterLogEvents / GetLogEvents per-call maximum


def _iso(ms: Optional[int]) -> Optional[str]:
    if ms is None:
        return None
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()


class LogsService:
    def __init__(self, client, config: Config, cache: Optional[TTLCache] = None):
        self._c = client
        self._cfg = config
        self._cache = cache or TTLCache(config.cache_ttl_seconds)

    # ------------------------------------------------------------ validation
    def _allowed(self, name: str) -> bool:
        allow = self._cfg.log_group_allowlist
        return not allow or any(fnmatch.fnmatchcase(name, pat) for pat in allow)

    def _validate_group(self, name: str) -> str:
        if not isinstance(name, str) or not _LOG_GROUP_RE.match(name):
            raise InputError(f"Invalid log group name: {name!r}")
        if not self._allowed(name):
            raise InputError(
                f"Log group {name!r} is outside LOG_GROUP_ALLOWLIST "
                f"({', '.join(self._cfg.log_group_allowlist)}).")
        return name

    # ------------------------------------------------------------- discovery
    def _all_groups(self, prefix: Optional[str]) -> tuple:
        """Paginate DescribeLogGroups. Returns (groups, truncated)."""
        def fetch():
            groups, token, truncated = [], None, False
            for page_no in range(self._cfg.max_pages):
                kwargs = {"limit": 50}
                if prefix:
                    kwargs["logGroupNamePrefix"] = prefix
                if token:
                    kwargs["nextToken"] = token
                resp = self._c.describe_log_groups(**kwargs)
                for g in resp.get("logGroups", []):
                    groups.append({
                        "name": g.get("logGroupName"),
                        "retention_days": g.get("retentionInDays"),
                        "stored_bytes": g.get("storedBytes"),
                        "log_group_class": g.get("logGroupClass"),
                        "created": _iso(g.get("creationTime")),
                    })
                token = resp.get("nextToken")
                if not token:
                    break
            else:
                truncated = True
            return groups, truncated

        value, _ = self._cache.get_or_set(("log_groups", prefix), fetch)
        return value

    def discover(self, keyword: Optional[str] = None, category: Optional[str] = None,
                 name_prefix: Optional[str] = None, limit: int = 100) -> ToolResult:
        tool = "aws_discover_log_groups"
        limit = max(1, min(limit, 500))
        terms: list = []
        if category:
            try:
                terms += keywords_for(category)
            except KeyError:
                raise InputError(
                    f"Unknown category {category!r}. Known: {', '.join(sorted(CATEGORY_KEYWORDS))}") from None
        if keyword:
            terms.append(keyword.strip())
        if name_prefix and not _LOG_GROUP_RE.match(name_prefix):
            raise InputError("Invalid name_prefix")

        groups, truncated = self._all_groups(name_prefix)
        visible = [g for g in groups if self._allowed(g["name"])]
        lowered = [t.lower() for t in terms if t]
        matched = [g for g in visible if not lowered or any(t in g["name"].lower() for t in lowered)]
        matched.sort(key=lambda g: g["name"])
        returned = matched[:limit]

        meta = {"scanned_groups": len(groups), "allowlist": list(self._cfg.log_group_allowlist),
                "match_terms": lowered}
        warnings = []
        if truncated:
            warnings.append(f"Discovery stopped after {self._cfg.max_pages} pages; more log groups "
                            "may exist. Use name_prefix to narrow.")
        if len(matched) > limit:
            warnings.append(f"{len(matched)} groups matched; showing the first {limit}.")

        if not returned:
            return ToolResult(
                tool, EMPTY,
                "No CloudWatch log groups matched. Logging may be disabled for this service, the "
                "naming may differ from the search terms, or the IAM role/allowlist hides them.",
                facts={"log_groups": []}, warnings=warnings, meta=meta)
        analysis = ["Matching is based on log-group NAMES only (heuristic); confirm a group's "
                    "contents with aws_search_logs before drawing conclusions."] if lowered else []
        never_expire = [g["name"] for g in returned if g["retention_days"] is None]
        if never_expire:
            analysis.append(f"{len(never_expire)} listed group(s) have no retention policy "
                            "(logs never expire) - a possible storage-cost review item.")
        return ToolResult(tool, PARTIAL if truncated else OK,
                          f"Found {len(matched)} matching log group(s); returning {len(returned)}.",
                          facts={"log_groups": returned, "total_matched": len(matched)},
                          analysis=analysis, warnings=warnings, meta=meta)

    # ---------------------------------------------------------------- search
    def search(self, log_groups: list, tr: TimeRange, filter_pattern: str = "",
               limit: Optional[int] = None, stream_prefix: Optional[str] = None) -> ToolResult:
        tool = "aws_search_logs"
        if not log_groups:
            raise InputError("Provide at least one log group (see aws_discover_log_groups).")
        if len(log_groups) > self._cfg.max_log_groups_per_query:
            raise InputError(f"At most {self._cfg.max_log_groups_per_query} log groups per call.")
        groups = [self._validate_group(g) for g in dict.fromkeys(log_groups)]
        if len(filter_pattern) > _MAX_PATTERN_CHARS:
            raise InputError(f"filter_pattern longer than {_MAX_PATTERN_CHARS} characters.")
        if stream_prefix is not None and not _STREAM_RE.match(stream_prefix):
            raise InputError("Invalid stream_prefix")
        limit = max(1, min(limit or self._cfg.max_log_results, self._cfg.max_log_results))
        per_group = max(1, limit // len(groups))

        events, per_group_info, warnings = [], {}, []
        first_exc: Optional[BaseException] = None
        failures = 0
        budget = self._cfg.max_response_chars
        used = 0
        budget_hit = False

        for name in groups:
            got, token, pages, more = 0, None, 0, False
            try:
                while True:
                    if got >= per_group or budget_hit or pages >= self._cfg.max_pages:
                        more = bool(token) or budget_hit
                        break
                    kwargs = {"logGroupName": name, "startTime": tr.start_ms, "endTime": tr.end_ms,
                              "limit": min(per_group - got, _API_PAGE_LIMIT)}
                    if filter_pattern:
                        kwargs["filterPattern"] = filter_pattern
                    if stream_prefix:
                        kwargs["logStreamNamePrefix"] = stream_prefix
                    if token:
                        kwargs["nextToken"] = token
                    resp = self._c.filter_log_events(**kwargs)
                    pages += 1
                    for ev in resp.get("events", []):
                        if got >= per_group:
                            break
                        msg = sanitize_text(ev.get("message", ""), self._cfg.max_message_chars)
                        used += len(msg) + 80
                        if used > budget:
                            budget_hit = True
                            break
                        events.append({"time": _iso(ev.get("timestamp")), "_ts": ev.get("timestamp", 0),
                                       "log_group": name, "log_stream": ev.get("logStreamName"),
                                       "message": msg})
                        got += 1
                    token = resp.get("nextToken")
                    if not token:
                        break
                per_group_info[name] = {"returned": got, "more_available": more}
            except Exception as exc:  # noqa: BLE001 - classified and reported per group, not swallowed
                failures += 1
                first_exc = first_exc or exc
                info = describe_exception(exc)
                per_group_info[name] = {"returned": got, "error": info.as_dict()}
                warnings.append(f"{name}: {info.kind} - {info.message}")

        if failures == len(groups) and first_exc is not None:
            raise first_exc

        events.sort(key=lambda e: e["_ts"])
        for e in events:
            e.pop("_ts", None)

        meta = {"time_range": tr.as_dict(), "filter_pattern": filter_pattern or None,
                "per_group": per_group_info, "limit": limit, "per_group_limit": per_group}
        truncated = budget_hit or any(i.get("more_available") for i in per_group_info.values())
        if budget_hit:
            warnings.append("Response size budget reached; remaining events were omitted.")
        if truncated:
            warnings.append("More matching events exist than were returned. Narrow the time range or "
                            "refine filter_pattern to see the rest; this result is a sample.")
        if not events:
            summary = ("No log events matched in the requested window. This can mean nothing was "
                       "logged, the filter matched nothing, or the service is not publishing to "
                       "these log groups.")
            return ToolResult(tool, PARTIAL if failures else EMPTY, summary, facts={"events": []},
                              warnings=warnings, meta=meta)
        status = PARTIAL if (failures or truncated) else OK
        return ToolResult(tool, status, f"Returned {len(events)} log event(s) from {len(groups)} group(s).",
                          facts={"events": events, "count": len(events)},
                          analysis=[f"Events are sorted by timestamp; messages were sanitized for secrets "
                                    f"and truncated to {self._cfg.max_message_chars} chars."],
                          warnings=warnings, meta=meta)

    # --------------------------------------------------------------- streams
    def list_streams(self, log_group: str, prefix: Optional[str] = None, limit: int = 25) -> ToolResult:
        tool = "aws_list_log_streams"
        name = self._validate_group(log_group)
        if prefix is not None and not _STREAM_RE.match(prefix):
            raise InputError("Invalid prefix")
        limit = max(1, min(limit, 50))
        kwargs = {"logGroupName": name, "limit": limit}
        if prefix:
            kwargs["logStreamNamePrefix"] = prefix
        else:
            kwargs.update(orderBy="LastEventTime", descending=True)
        resp = self._c.describe_log_streams(**kwargs)
        streams = [{"name": s.get("logStreamName"),
                    "first_event": _iso(s.get("firstEventTimestamp")),
                    "last_event": _iso(s.get("lastEventTimestamp")),
                    "stored_bytes": s.get("storedBytes")} for s in resp.get("logStreams", [])]
        meta = {"log_group": name, "more_available": bool(resp.get("nextToken"))}
        if not streams:
            return ToolResult(tool, EMPTY, "No log streams found in this log group.",
                              facts={"streams": []}, meta=meta)
        note = "Streams ordered by most recent event." if not prefix else "Streams ordered by name."
        return ToolResult(tool, OK, f"Found {len(streams)} log stream(s).", facts={"streams": streams},
                          analysis=[note], meta=meta)

    # ------------------------------------------------------------ get events
    def get_events(self, log_group: str, log_stream: str, tr: TimeRange, limit: Optional[int] = None,
                   start_from_head: bool = False) -> ToolResult:
        tool = "aws_get_log_events"
        name = self._validate_group(log_group)
        if not isinstance(log_stream, str) or not _STREAM_RE.match(log_stream):
            raise InputError("Invalid log_stream")
        limit = max(1, min(limit or self._cfg.max_log_results, self._cfg.max_log_results))
        events, token, warnings = [], None, []
        used, budget_hit, exhausted = 0, False, False
        token_key = "nextForwardToken" if start_from_head else "nextBackwardToken"
        for _ in range(self._cfg.max_pages):
            kwargs = {"logGroupName": name, "logStreamName": log_stream, "startTime": tr.start_ms,
                      "endTime": tr.end_ms, "startFromHead": start_from_head,
                      "limit": min(limit - len(events), _API_PAGE_LIMIT)}
            if token:
                kwargs["nextToken"] = token
            resp = self._c.get_log_events(**kwargs)
            batch = resp.get("events", [])
            for ev in batch:
                msg = sanitize_text(ev.get("message", ""), self._cfg.max_message_chars)
                used += len(msg) + 60
                if used > self._cfg.max_response_chars:
                    budget_hit = True
                    break
                events.append({"time": _iso(ev.get("timestamp")), "_ts": ev.get("timestamp", 0),
                               "message": msg})
            new_token = resp.get(token_key)
            if budget_hit or len(events) >= limit:
                break
            if not batch or not new_token or new_token == token:
                exhausted = True
                break
            token = new_token
        events = events[:limit]
        events.sort(key=lambda e: e["_ts"])
        for e in events:
            e.pop("_ts", None)
        meta = {"log_group": name, "log_stream": log_stream, "time_range": tr.as_dict(),
                "direction": "oldest_first" if start_from_head else "newest_first_window"}
        if not exhausted:
            warnings.append("More events may exist in this window than were returned; narrow the "
                            "time range or raise MAX_LOG_RESULTS within its ceiling.")
        if not events:
            return ToolResult(tool, EMPTY, "No events in this stream for the requested window.",
                              facts={"events": []}, meta=meta)
        return ToolResult(tool, OK if exhausted else PARTIAL, f"Returned {len(events)} event(s).",
                          facts={"events": events, "count": len(events)},
                          analysis=["Messages were sanitized for secrets and truncated."],
                          warnings=warnings, meta=meta)
