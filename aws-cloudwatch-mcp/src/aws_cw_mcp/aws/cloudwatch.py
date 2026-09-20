"""CloudWatch metrics and alarms (read-only).

APIs: ListMetrics, GetMetricData, DescribeAlarms, DescribeAlarmHistory.
Metric Math expressions are deliberately NOT accepted: only direct metric
lookups (namespace + metric + dimensions), so callers cannot craft arbitrary
expensive queries.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Optional

from aws_cw_mcp.config import Config
from aws_cw_mcp.models.results import EMPTY, OK, PARTIAL, ToolResult
from aws_cw_mcp.utils.cache import TTLCache
from aws_cw_mcp.utils.errors import InputError
from aws_cw_mcp.utils.sanitize import sanitize_text
from aws_cw_mcp.utils.stats import summarize
from aws_cw_mcp.utils.timerange import TimeRange

_NAME_RE = re.compile(r"^[\w\-./#:@ ]{1,255}$")
_STAT_RE = re.compile(
    r"^(Average|Sum|Minimum|Maximum|SampleCount|IQM|p\d{1,2}(\.\d{1,2})?|p100)$")
_STATES = {"OK", "ALARM", "INSUFFICIENT_DATA"}
_HISTORY_TYPES = {"ConfigurationUpdate", "StateUpdate", "Action"}
_PERIODS = (60, 300, 900, 3600, 21600, 86400)


def _iso(dt) -> Optional[str]:
    if dt is None:
        return None
    if isinstance(dt, datetime):
        return dt.astimezone(timezone.utc).isoformat()
    return str(dt)


def _check_name(value: str, what: str) -> str:
    if not isinstance(value, str) or not _NAME_RE.match(value):
        raise InputError(f"Invalid {what}: {value!r}")
    return value


def _dimensions(dims: Optional[dict]) -> list:
    out = []
    for k, v in (dims or {}).items():
        out.append({"Name": _check_name(str(k), "dimension name"),
                    "Value": _check_name(str(v), "dimension value")})
    if len(out) > 30:
        raise InputError("At most 30 dimensions.")
    return out


class MetricsService:
    def __init__(self, client, config: Config, cache: Optional[TTLCache] = None):
        self._c = client
        self._cfg = config
        self._cache = cache or TTLCache(config.cache_ttl_seconds)

    # ----------------------------------------------------------- list metrics
    def list_metrics(self, namespace: Optional[str] = None, metric_name: Optional[str] = None,
                     dimensions: Optional[dict] = None, limit: int = 100) -> ToolResult:
        tool = "aws_list_metrics"
        limit = max(1, min(limit, 500))
        base: dict = {}
        if namespace:
            base["Namespace"] = _check_name(namespace, "namespace")
        if metric_name:
            base["MetricName"] = _check_name(metric_name, "metric_name")
        dims = _dimensions(dimensions)
        if dims:
            base["Dimensions"] = [{"Name": d["Name"], "Value": d["Value"]} for d in dims]
        if not base:
            raise InputError("Provide at least a namespace, metric_name or dimensions filter; "
                             "listing every metric in the account is not allowed.")

        def fetch():
            metrics, token, truncated = [], None, False
            for _ in range(self._cfg.max_pages):
                kwargs = dict(base)
                if token:
                    kwargs["NextToken"] = token
                resp = self._c.list_metrics(**kwargs)
                for m in resp.get("Metrics", []):
                    metrics.append({"namespace": m.get("Namespace"), "metric_name": m.get("MetricName"),
                                    "dimensions": {d["Name"]: d["Value"] for d in m.get("Dimensions", [])}})
                token = resp.get("NextToken")
                if not token or len(metrics) >= limit:
                    break
            else:
                truncated = True
            return metrics, truncated or (bool(token) and len(metrics) >= limit)

        key = ("list_metrics", json.dumps(base, sort_keys=True), limit)
        (metrics, more), cached = self._cache.get_or_set(key, fetch)
        shown = metrics[:limit]
        meta = {"filters": base, "cached": cached}
        warnings = []
        if more or len(metrics) > limit:
            warnings.append("More metrics exist than were returned; add namespace/dimension filters.")
        if not shown:
            return ToolResult(tool, EMPTY,
                              "No metrics found for this filter. The service may not publish to CloudWatch "
                              "(e.g. CloudWatch agent / Container Insights not enabled) or the filter is "
                              "wrong. Metrics with no data in the last ~2 weeks are not listed.",
                              facts={"metrics": []}, meta=meta)
        return ToolResult(tool, PARTIAL if warnings else OK, f"Found {len(shown)} metric(s).",
                          facts={"metrics": shown}, warnings=warnings, meta=meta)

    # ------------------------------------------------------------ get metrics
    def _choose_period(self, seconds: int, requested: Optional[int]) -> int:
        max_points = self._cfg.max_query_results
        if requested is not None:
            if requested < 60 or requested % 60:
                raise InputError("period must be a multiple of 60 seconds (>= 60).")
            if seconds / requested > max_points:
                raise InputError(f"period {requested}s over this range would return more than "
                                 f"{max_points} datapoints per metric; use a larger period or shorter range.")
            return requested
        for p in _PERIODS:
            if seconds / p <= max_points:
                return p
        raise InputError("Time range too large for the configured datapoint limit.")

    def get_metrics(self, queries: list, tr: TimeRange, period: Optional[int] = None,
                    include_datapoints: bool = True) -> ToolResult:
        tool = "aws_get_metrics"
        if not queries:
            raise InputError("Provide at least one metric query.")
        if len(queries) > self._cfg.max_metric_queries:
            raise InputError(f"At most {self._cfg.max_metric_queries} metrics per call.")
        period = self._choose_period(tr.seconds, period)

        built, labels = [], {}
        for i, q in enumerate(queries):
            if not isinstance(q, dict):
                raise InputError("Each metric query must be an object with namespace and metric_name.")
            ns = _check_name(q.get("namespace", ""), "namespace")
            name = _check_name(q.get("metric_name", ""), "metric_name")
            stat = q.get("stat", "Average")
            if not isinstance(stat, str) or not _STAT_RE.match(stat):
                raise InputError(f"Unsupported stat {stat!r}. Use Average, Sum, Minimum, Maximum, "
                                 "SampleCount, IQM or a percentile like p99.")
            mid = f"m{i}"
            labels[mid] = {"namespace": ns, "metric_name": name, "stat": stat,
                           "dimensions": dict(q.get("dimensions") or {})}
            built.append({"Id": mid, "Label": f"{ns}/{name}",
                          "MetricStat": {"Metric": {"Namespace": ns, "MetricName": name,
                                                    "Dimensions": _dimensions(q.get("dimensions"))},
                                         "Period": period, "Stat": stat},
                          "ReturnData": True})

        series = {mid: {"timestamps": [], "values": []} for mid in labels}
        messages, token, complete = [], None, False
        max_dp = self._cfg.max_query_results * len(built)
        for _ in range(self._cfg.max_pages):
            kwargs = {"MetricDataQueries": built, "StartTime": tr.start, "EndTime": tr.end,
                      "ScanBy": "TimestampAscending", "MaxDatapoints": max_dp}
            if token:
                kwargs["NextToken"] = token
            resp = self._c.get_metric_data(**kwargs)
            for r in resp.get("MetricDataResults", []):
                s = series.get(r.get("Id"))
                if s is None:
                    continue
                s["timestamps"].extend(r.get("Timestamps", []))
                s["values"].extend(r.get("Values", []))
                for m in r.get("Messages", []) or []:
                    messages.append(sanitize_text(f"{r.get('Label')}: {m.get('Value')}", 300))
            for m in resp.get("Messages", []) or []:
                messages.append(sanitize_text(m.get("Value", ""), 300))
            token = resp.get("NextToken")
            if not token:
                complete = True
                break

        results, analysis, empty_labels = [], [], []
        for mid, meta_q in labels.items():
            ts, vals = series[mid]["timestamps"], series[mid]["values"]
            entry = {**meta_q, "period_seconds": period, "datapoint_count": len(vals)}
            if not vals:
                empty_labels.append(f"{meta_q['namespace']}/{meta_q['metric_name']}")
                entry["stats"] = {"count": 0}
                results.append(entry)
                continue
            st = summarize(vals)
            peak_i = max(range(len(vals)), key=vals.__getitem__)
            entry["stats"] = {**st, "latest": vals[-1], "max_at": _iso(ts[peak_i]),
                              "first_timestamp": _iso(ts[0]), "last_timestamp": _iso(ts[-1])}
            if include_datapoints:
                step = max(1, -(-len(vals) // self._cfg.max_datapoints_returned))
                pts = [[_iso(t), v] for t, v in list(zip(ts, vals))[::step]]
                entry["datapoints"] = pts
                if step > 1:
                    entry["datapoints_downsampled_every"] = step
            results.append(entry)
            analysis.append(
                f"{meta_q['namespace']}/{meta_q['metric_name']} ({meta_q['stat']}): calculated over "
                f"{len(vals)} datapoints of {period}s - min {st['min']:.4g}, avg {st['avg']:.4g}, "
                f"p95 {st['p95']:.4g}, max {st['max']:.4g}. Percentiles here describe the distribution "
                "of the returned datapoints, not per-request latency percentiles.")

        meta = {"time_range": tr.as_dict(), "period_seconds": period}
        warnings = list(dict.fromkeys(messages))
        if not complete:
            warnings.append("Pagination limit reached; datapoints may be incomplete.")
        if empty_labels:
            warnings.append("No datapoints for: " + ", ".join(empty_labels) +
                            ". The metric may not be published (agent/feature disabled), the dimensions "
                            "may not match exactly, or there was no activity in the window.")
        if len(empty_labels) == len(labels):
            return ToolResult(tool, EMPTY, "No metric data is currently available for this request.",
                              facts={"metrics": results}, warnings=warnings, meta=meta)
        return ToolResult(tool, PARTIAL if (empty_labels or not complete) else OK,
                          f"Retrieved {len(labels) - len(empty_labels)} of {len(labels)} metric series.",
                          facts={"metrics": results}, analysis=analysis, warnings=warnings, meta=meta)


class AlarmsService:
    def __init__(self, client, config: Config):
        self._c = client
        self._cfg = config

    def get_alarms(self, state: Optional[str] = None, name_prefix: Optional[str] = None,
                   include_composite: bool = True, limit: int = 100) -> ToolResult:
        tool = "aws_get_alarms"
        limit = max(1, min(limit, 500))
        kwargs: dict = {"MaxRecords": min(limit, 100),
                        "AlarmTypes": ["MetricAlarm", "CompositeAlarm"] if include_composite else ["MetricAlarm"]}
        if state:
            state = state.upper()
            if state not in _STATES:
                raise InputError(f"state must be one of {sorted(_STATES)}")
            kwargs["StateValue"] = state
        if name_prefix:
            kwargs["AlarmNamePrefix"] = _check_name(name_prefix, "name_prefix")

        alarms, token, truncated = [], None, False
        for _ in range(self._cfg.max_pages):
            call = dict(kwargs)
            if token:
                call["NextToken"] = token
            resp = self._c.describe_alarms(**call)
            for a in resp.get("MetricAlarms", []):
                alarms.append({
                    "name": a.get("AlarmName"), "type": "MetricAlarm", "state": a.get("StateValue"),
                    "state_updated": _iso(a.get("StateUpdatedTimestamp")),
                    "reason": sanitize_text(a.get("StateReason", ""), 500),
                    "namespace": a.get("Namespace"), "metric": a.get("MetricName"),
                    "dimensions": {d["Name"]: d["Value"] for d in a.get("Dimensions", [])},
                    "statistic": a.get("Statistic") or a.get("ExtendedStatistic"),
                    "comparison": a.get("ComparisonOperator"), "threshold": a.get("Threshold"),
                    "period": a.get("Period"), "evaluation_periods": a.get("EvaluationPeriods"),
                    "treat_missing_data": a.get("TreatMissingData"),
                    "actions_enabled": a.get("ActionsEnabled"),
                })
            for a in resp.get("CompositeAlarms", []):
                alarms.append({
                    "name": a.get("AlarmName"), "type": "CompositeAlarm", "state": a.get("StateValue"),
                    "state_updated": _iso(a.get("StateUpdatedTimestamp")),
                    "reason": sanitize_text(a.get("StateReason", ""), 500),
                    "rule": sanitize_text(a.get("AlarmRule", ""), 500),
                    "actions_enabled": a.get("ActionsEnabled"),
                })
            token = resp.get("NextToken")
            if not token or len(alarms) >= limit:
                break
        else:
            truncated = True
        more = truncated or (bool(token) and len(alarms) >= limit)
        alarms = alarms[:limit]

        meta = {"filters": {"state": state, "name_prefix": name_prefix}}
        warnings = ["More alarms exist than were returned; filter by state or name_prefix."] if more else []
        if not alarms:
            return ToolResult(tool, EMPTY, "No CloudWatch alarms matched this filter.",
                              facts={"alarms": []}, warnings=warnings, meta=meta)
        counts: dict = {}
        for a in alarms:
            counts[a["state"]] = counts.get(a["state"], 0) + 1
        analysis = [f"State counts (calculated from returned alarms): {counts}"]
        firing = [a["name"] for a in alarms if a["state"] == "ALARM"]
        if firing:
            analysis.append(f"{len(firing)} alarm(s) currently in ALARM: {', '.join(firing[:20])}")
        insufficient = [a["name"] for a in alarms if a["state"] == "INSUFFICIENT_DATA"]
        if insufficient:
            analysis.append(f"{len(insufficient)} alarm(s) report INSUFFICIENT_DATA - the metric may have "
                            "stopped publishing; this is not proof of health.")
        return ToolResult(tool, PARTIAL if more else OK, f"Returned {len(alarms)} alarm(s).",
                          facts={"alarms": alarms, "state_counts": counts}, analysis=analysis,
                          warnings=warnings, meta=meta)

    def get_history(self, alarm_name: str, tr: TimeRange, history_type: Optional[str] = None,
                    limit: int = 100) -> ToolResult:
        tool = "aws_get_alarm_history"
        _check_name(alarm_name, "alarm_name")
        limit = max(1, min(limit, 500))
        kwargs: dict = {"AlarmName": alarm_name, "StartDate": tr.start, "EndDate": tr.end,
                        "ScanBy": "TimestampDescending", "MaxRecords": min(limit, 100)}
        if history_type:
            if history_type not in _HISTORY_TYPES:
                raise InputError(f"history_type must be one of {sorted(_HISTORY_TYPES)}")
            kwargs["HistoryItemType"] = history_type

        items, token, truncated = [], None, False
        for _ in range(self._cfg.max_pages):
            call = dict(kwargs)
            if token:
                call["NextToken"] = token
            resp = self._c.describe_alarm_history(**call)
            for h in resp.get("AlarmHistoryItems", []):
                new_state = None
                if h.get("HistoryItemType") == "StateUpdate":
                    try:
                        new_state = json.loads(h.get("HistoryData") or "{}").get("newState", {}).get("stateValue")
                    except (ValueError, AttributeError):
                        new_state = None
                items.append({"time": _iso(h.get("Timestamp")), "type": h.get("HistoryItemType"),
                              "summary": sanitize_text(h.get("HistorySummary", ""), 400),
                              "new_state": new_state})
            token = resp.get("NextToken")
            if not token or len(items) >= limit:
                break
        else:
            truncated = True
        more = truncated or (bool(token) and len(items) >= limit)
        items = items[:limit]
        meta = {"alarm_name": alarm_name, "time_range": tr.as_dict()}
        warnings = ["More history exists than was returned; narrow the time range."] if more else []
        if not items:
            return ToolResult(tool, EMPTY,
                              "No alarm history in this window (alarm may not exist, or had no changes).",
                              facts={"history": []}, warnings=warnings, meta=meta)
        to_alarm = sum(1 for i in items if i["new_state"] == "ALARM")
        analysis = [f"Calculated from returned items: {to_alarm} transition(s) into ALARM among "
                    f"{len(items)} history item(s)."]
        if to_alarm >= 5:
            analysis.append("Repeated transitions into ALARM suggest flapping or a recurring issue; "
                            "compare the alarm's threshold/period with the underlying metric.")
        return ToolResult(tool, PARTIAL if more else OK, f"Returned {len(items)} history item(s).",
                          facts={"history": items, "transitions_to_alarm": to_alarm}, analysis=analysis,
                          warnings=warnings, meta=meta)
