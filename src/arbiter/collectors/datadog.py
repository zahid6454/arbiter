"""Datadog collector — fetches logs, monitors, and events via Datadog API."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import time
from datetime import UTC

import httpx

from arbiter.collectors.base import Collector
from arbiter.core.models import (
    EventSource,
    LogEntry,
    LogLevel,
    TimelineEvent,
)
from arbiter.credentials import load_credentials

logger = logging.getLogger(__name__)

# Datadog site -> API base URL
SITE_TO_API = {
    "datadoghq.com": "https://api.datadoghq.com",
    "us3.datadoghq.com": "https://api.us3.datadoghq.com",
    "us5.datadoghq.com": "https://api.us5.datadoghq.com",
    "datadoghq.eu": "https://api.datadoghq.eu",
    "ddog-gov.com": "https://api.ddog-gov.com",
    "ap1.datadoghq.com": "https://api.ap1.datadoghq.com",
}

TIME_RANGES = {
    "15m": "now-15m",
    "30m": "now-30m",
    "1h": "now-1h",
    "2h": "now-2h",
    "4h": "now-4h",
    "6h": "now-6h",
    "12h": "now-12h",
    "24h": "now-24h",
    "1d": "now-1d",
    "2d": "now-2d",
    "7d": "now-7d",
}

_METADATA_TOTAL_MAX_BYTES = 2048

_USEFUL_ATTRIBUTES = {
    "http.status_code",
    "http.method",
    "http.url",
    "http.url_details.path",
    "network.client.ip",
    "http.useragent",
    "error.kind",
    "error.message",
    "error.stack",
    "usr.id",
    "usr.name",
}

load_credentials()


def _parse_log_level(raw: str) -> LogLevel:
    """Map raw log level strings to LogLevel enum."""
    upper = raw.upper()
    if upper in ("CRITICAL", "FATAL", "EMERG"):
        return LogLevel.CRITICAL
    if upper in ("ERROR", "ERR"):
        return LogLevel.ERROR
    if upper in ("WARN", "WARNING"):
        return LogLevel.WARNING
    if upper == "INFO":
        return LogLevel.INFO
    return LogLevel.DEBUG


def _extract_metadata(inner: dict) -> dict:
    """Extract useful attributes from Datadog's nested attributes dict.

    Prioritizes known-useful fields (HTTP details, client info, errors),
    then fills remaining space with other attributes up to the size cap.
    """
    if not inner:
        return {}

    result: dict = {}
    total_size = 0

    # First pass: extract known-useful attributes (with and without @ prefix)
    for key, value in inner.items():
        bare = key.lstrip("@")
        if bare in _USEFUL_ATTRIBUTES:
            try:
                entry_size = len(json.dumps(value, default=str))
            except (TypeError, ValueError):
                continue
            if total_size + entry_size > _METADATA_TOTAL_MAX_BYTES:
                break
            result[key] = value
            total_size += entry_size

    # Second pass: include remaining keys until cap
    for key, value in inner.items():
        if key in result or key == "dd":
            continue
        if isinstance(value, dict) and len(value) > 10:
            continue
        try:
            entry_size = len(json.dumps(value, default=str))
        except (TypeError, ValueError):
            continue
        if total_size + entry_size > _METADATA_TOTAL_MAX_BYTES:
            break
        result[key] = value
        total_size += entry_size

    return result


class DatadogCollector(Collector):
    """Collector for Datadog Logs, Monitors, and Events APIs."""

    def __init__(
        self,
        api_key: str | None = None,
        app_key: str | None = None,
        site: str | None = None,
    ):
        self.api_key = api_key or os.environ.get("DD_API_KEY", "")
        self.app_key = app_key or os.environ.get("DD_APP_KEY", "")
        self.site = site or os.environ.get("DD_SITE", "us3.datadoghq.com")
        self.base_url = SITE_TO_API.get(self.site, f"https://api.{self.site}")
        self._headers = {
            "DD-API-KEY": self.api_key,
            "DD-APPLICATION-KEY": self.app_key,
            "Content-Type": "application/json",
        }
        self._rate_remaining: int | None = None
        self._rate_period: float = 0.0

    @property
    def source(self) -> EventSource:
        return EventSource.DATADOG

    def is_configured(self) -> bool:
        return bool(self.api_key and self.app_key)

    def recommended_delay(self) -> float:
        """Return recommended delay before the next API call based on rate limit state."""
        if self._rate_remaining is None:
            return 3.0
        if self._rate_remaining > 5:
            return 0.0
        if self._rate_remaining > 2:
            return 1.0
        return max(self._rate_period, 3.0)

    def _resolve_time_range(self, time_range: str) -> tuple[str, str]:
        from_time = TIME_RANGES.get(time_range, f"now-{time_range}")
        return from_time, "now"

    def _update_rate_state(self, response: httpx.Response) -> None:
        """Read rate limit headers from the response."""
        remaining = response.headers.get("x-ratelimit-remaining")
        if remaining is not None:
            with contextlib.suppress(ValueError):
                self._rate_remaining = int(remaining)
        period = response.headers.get("x-ratelimit-period")
        if period is not None:
            with contextlib.suppress(ValueError):
                self._rate_period = float(period)

    def _request(
        self,
        method: str,
        path: str,
        json: dict | None = None,
        params: dict | None = None,
    ) -> dict:
        """Make an API request with retry on rate limit."""
        url = f"{self.base_url}{path}"
        last_resp = None
        with httpx.Client(timeout=30) as client:
            for attempt in range(3):
                if method == "POST":
                    last_resp = client.post(url, headers=self._headers, json=json)
                else:
                    last_resp = client.get(url, headers=self._headers, params=params)
                self._update_rate_state(last_resp)
                if last_resp.status_code == 429:
                    reset = last_resp.headers.get("x-ratelimit-reset")
                    if reset:
                        try:
                            reset_epoch = float(reset)
                            delay = max(0.0, reset_epoch - time.time())
                            time.sleep(min(delay, 30))
                            continue
                        except ValueError:
                            pass
                    time.sleep(min(2**attempt + 1, 10))
                    continue
                last_resp.raise_for_status()
                return last_resp.json()
        if last_resp is not None:
            last_resp.raise_for_status()
        raise httpx.HTTPStatusError(
            "Rate limited after 3 retries",
            request=httpx.Request(method, url),
            response=last_resp or httpx.Response(429),
        )

    # ---- Collector interface ----

    def collect_logs(
        self,
        service: str,
        time_range: str = "2h",
        env: str = "production",
        from_time: str | None = None,
        to_time: str | None = None,
        limit: int = 50,
        query: str = "",
    ) -> list[LogEntry]:
        query_parts = [query or "status:(error OR warn OR critical)"]
        if service and f"service:{service}" not in query_parts[0]:
            query_parts.append(f"service:{service}")
        if env and f"env:{env}" not in query_parts[0]:
            query_parts.append(f"env:{env}")
        full_query = " ".join(query_parts)

        if from_time:
            resolved_from, resolved_to = from_time, to_time or "now"
        else:
            resolved_from, resolved_to = self._resolve_time_range(time_range)

        payload = {
            "filter": {
                "query": full_query,
                "from": resolved_from,
                "to": resolved_to,
            },
            "sort": "-timestamp",
            "page": {"limit": min(limit, 1000)},
        }

        data = self._request("POST", "/api/v2/logs/events/search", json=payload)
        return self._parse_log_results(data)

    def collect_events(
        self,
        service: str,
        time_range: str = "2h",
        from_time: str | None = None,
        to_time: str | None = None,
    ) -> list[TimelineEvent]:
        """Collect monitor alerts and events as timeline events."""
        events: list[TimelineEvent] = []

        # Get triggered monitors
        monitors = self.search_monitors(service=service)
        for m in monitors:
            if m["overall_state"] in ("Alert", "Warn"):
                events.append(
                    TimelineEvent(
                        timestamp=m.get("modified", ""),
                        message=f"Alert: {m['name']} ({m['overall_state']})",
                        source=EventSource.DATADOG,
                        service=service,
                        level=LogLevel.ERROR if m["overall_state"] == "Alert" else LogLevel.WARNING,
                        metadata={"monitor_id": m["id"], "priority": m.get("priority")},
                    )
                )

        # Get alert events
        alert_events = self.get_service_alerts(
            service=service, from_time=from_time, to_time=to_time
        )
        for e in alert_events:
            events.append(
                TimelineEvent(
                    timestamp=str(e.get("date_happened", "")),
                    message=e.get("title", ""),
                    source=EventSource.DATADOG,
                    service=service,
                    level=LogLevel.ERROR if e.get("alert_type") == "error" else LogLevel.WARNING,
                    metadata=e,
                )
            )

        return events

    # ---- Datadog-specific methods ----

    def _parse_log_results(self, data: dict) -> list[LogEntry]:
        entries = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            inner = attrs.get("attributes", {})
            tags = attrs.get("tags", [])

            svc = attrs.get("service", "")
            env = ""
            container = ""
            pod = ""
            for tag in tags:
                if tag.startswith("env:"):
                    env = tag.split(":", 1)[1]
                elif tag.startswith("kube_container_name:"):
                    container = tag.split(":", 1)[1]
                elif tag.startswith("pod_name:"):
                    pod = tag.split(":", 1)[1]

            message = attrs.get("message", "")
            raw_level = inner.get("level", attrs.get("status", ""))
            timestamp = inner.get("timestamp") or inner.get("time") or attrs.get("timestamp", "")

            trace_id = inner.get("dd", {}).get("trace_id") or ""
            trace_id = str(trace_id) if trace_id else ""
            if not trace_id:
                for tag in tags:
                    if tag.startswith("dd.trace_id:"):
                        trace_id = tag.split(":", 1)[1]
                        break

            metadata = _extract_metadata(inner)

            entries.append(
                LogEntry(
                    timestamp=str(timestamp),
                    level=_parse_log_level(raw_level),
                    message=message[:500],
                    service=svc,
                    source=EventSource.DATADOG,
                    environment=env,
                    host=attrs.get("host", ""),
                    container=container,
                    pod=pod,
                    trace_id=trace_id,
                    metadata=metadata,
                )
            )
        return entries

    def get_error_summary(
        self,
        service: str,
        time_range: str = "2h",
        env: str = "production",
        limit: int = 100,
    ) -> dict:
        """Get grouped error summary for a service."""
        logs = self.collect_logs(
            service=service,
            time_range=time_range,
            env=env,
            limit=limit,
            query="status:error",
        )

        error_groups: dict[str, int] = {}
        for entry in logs:
            key = entry.message[:100] if entry.message else "unknown"
            error_groups[key] = error_groups.get(key, 0) + 1

        sorted_errors = sorted(error_groups.items(), key=lambda x: -x[1])
        return {
            "service": service,
            "environment": env,
            "time_range": time_range,
            "total_errors": len(logs),
            "unique_error_patterns": len(error_groups),
            "top_errors": [
                {"pattern": pattern, "count": count} for pattern, count in sorted_errors[:10]
            ],
        }

    def search_monitors(self, service: str | None = None, query: str = "") -> list[dict]:
        """Search Datadog monitors."""
        params: dict = {"page": "0", "page_size": "50"}
        if service:
            params["query"] = query or f"tag:service:{service}"
        elif query:
            params["query"] = query

        data = self._request("GET", "/api/v1/monitor", params=params)
        if not isinstance(data, list):
            return []

        return [
            {
                "id": m.get("id"),
                "name": m.get("name", ""),
                "type": m.get("type", ""),
                "priority": m.get("priority"),
                "overall_state": m.get("overall_state", ""),
                "message": m.get("message", "")[:500],
                "tags": m.get("tags", []),
                "created": m.get("created"),
                "modified": m.get("modified"),
            }
            for m in data
        ]

    def search_traces(
        self,
        service: str,
        time_range: str = "2h",
        env: str = "production",
        from_time: str | None = None,
        to_time: str | None = None,
        limit: int = 50,
        status_code: str = "500",
        resource_name: str = "",
        tag_filter: str = "",
    ) -> list[dict]:
        """Search Datadog APM traces for a service.

        Finds traces with errors or specific status codes to identify
        the server-side root cause of failures.
        """
        query_parts = [f"service:{service}", f"env:{env}"]
        if status_code:
            query_parts.append(f"@http.status_code:{status_code}")
        if resource_name:
            query_parts.append(f"resource_name:{resource_name}")
        if tag_filter:
            query_parts.append(tag_filter)

        if from_time:
            resolved_from, resolved_to = from_time, to_time or "now"
        else:
            resolved_from, resolved_to = self._resolve_time_range(time_range)

        # Spans API requires data wrapper
        payload = {
            "data": {
                "type": "search_request",
                "attributes": {
                    "filter": {
                        "query": " ".join(query_parts),
                        "from": resolved_from,
                        "to": resolved_to,
                    },
                    "page": {"limit": min(limit, 50)},
                },
            }
        }

        data = self._request("POST", "/api/v2/spans/events/search", json=payload)
        traces = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            custom = attrs.get("custom", {})
            http_info = custom.get("http", {})
            error_info = custom.get("error", {})
            flask_info = custom.get("flask", {})
            git_info = custom.get("git", {})

            span_tags = custom.get("span_tags", [])
            pod_name = ""
            for tag in span_tags:
                if tag.startswith("pod_name:"):
                    pod_name = tag.split(":", 1)[1]
                    break

            traces.append(
                {
                    "trace_id": attrs.get("trace_id") or "",
                    "span_id": attrs.get("span_id") or "",
                    "service": attrs.get("service", service),
                    "endpoint": flask_info.get("endpoint", ""),
                    "url_rule": flask_info.get("url_rule", ""),
                    "timestamp": attrs.get("start_timestamp", attrs.get("timestamp", "")),
                    "duration_ms": round((custom.get("duration") or 0) / 1_000_000, 1),
                    "status_code": http_info.get("status_code") or "",
                    "http_method": http_info.get("method") or "",
                    "http_path": http_info.get("path_group") or "",
                    "error_type": error_info.get("type") or "",
                    "error_message": (error_info.get("message") or "")[:500],
                    "error_stack": (error_info.get("stack") or "")[:1000],
                    "span_tags": span_tags,
                    "pod_name": pod_name,
                    "env": custom.get("env", ""),
                    "version": custom.get("version", ""),
                    "git_sha": git_info.get("commit", {}).get("sha", ""),
                }
            )

        # Inline warnings for opaque error traces
        for t in traces:
            is_err = str(t.get("status_code", "")).startswith(("4", "5")) or t.get("error_type")
            if (
                is_err
                and not t.get("error_type")
                and not t.get("error_message")
                and t.get("trace_id")
            ):
                t["_warning"] = (
                    "No error details on this span — use fetch_trace_spans "
                    "to inspect child spans"
                )

        return traces

    def search_trace_spans(
        self,
        trace_id: str,
        time_range: str = "2h",
        from_time: str | None = None,
        to_time: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Fetch all spans for a trace ID, including child spans on different services.

        Returns spans sorted chronologically with error details extracted.
        """
        if from_time:
            resolved_from, resolved_to = from_time, to_time or "now"
        else:
            resolved_from, resolved_to = self._resolve_time_range(time_range)

        payload = {
            "data": {
                "type": "search_request",
                "attributes": {
                    "filter": {
                        "query": f"trace_id:{trace_id}",
                        "from": resolved_from,
                        "to": resolved_to,
                    },
                    "sort": "timestamp",
                    "page": {"limit": min(limit, 100)},
                },
            }
        }

        data = self._request("POST", "/api/v2/spans/events/search", json=payload)
        spans = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            custom = attrs.get("custom", {})
            error_info = custom.get("error", {})
            http_info = custom.get("http", {})

            is_error = bool(
                error_info.get("type")
                or str(http_info.get("status_code") or "").startswith(("4", "5"))
            )

            spans.append(
                {
                    "span_id": attrs.get("span_id", ""),
                    "parent_id": attrs.get("parent_id", ""),
                    "service": attrs.get("service", ""),
                    "resource_name": attrs.get("resource_name") or "",
                    "timestamp": attrs.get("start_timestamp", attrs.get("timestamp", "")),
                    "duration_ms": round((custom.get("duration") or 0) / 1_000_000, 1),
                    "error_type": error_info.get("type") or "",
                    "error_message": (error_info.get("message") or "")[:500],
                    "error_stack": (error_info.get("stack") or "")[:1000],
                    "is_error": is_error,
                }
            )

        return spans

    def search_by_uuid(
        self,
        uuid: str,
        from_time: str | None = None,
        to_time: str | None = None,
        time_range: str = "2h",
    ) -> list[LogEntry]:
        """Search for a specific request UUID across all services.

        Used to correlate a client-side error with the server-side root cause.
        """
        return self.collect_logs(
            service="",
            query=f'"{uuid}"',
            from_time=from_time,
            to_time=to_time,
            time_range=time_range,
            limit=20,
        )

    def search_database_errors(
        self,
        service: str,
        time_range: str = "2h",
        env: str = "production",
        from_time: str | None = None,
        to_time: str | None = None,
        limit: int = 50,
    ) -> list[LogEntry]:
        """Search for database-specific errors — Spanner, PostgreSQL, MySQL, etc.

        Catches transaction aborts, deadlocks, connection pool exhaustion,
        and other DB-level failures that cause upstream 500s.
        """
        db_query = (
            '("ABORTED" OR "TransactionAborted" OR "Aborted" OR '
            '"deadlock" OR "lock timeout" OR "connection pool" OR '
            '"Spanner" OR "spanner" OR "google.api_core.exceptions" OR '
            '"psycopg2" OR "OperationalError" OR "IntegrityError" OR '
            '"ConnectionResetError" OR "connection refused" OR '
            '"too many connections" OR "serialization failure" OR '
            '"concurrent update" OR "write conflict")'
        )
        return self.collect_logs(
            service=service,
            query=db_query,
            time_range=time_range,
            env=env,
            from_time=from_time,
            to_time=to_time,
            limit=limit,
        )

    def query_metrics(
        self,
        query: str,
        time_range: str = "2h",
        from_time: str | None = None,
        to_time: str | None = None,
    ) -> list[dict]:
        """Query Datadog Metrics API for timeseries data.

        Returns a list of series, each with scope, unit, and data points.
        """
        from datetime import datetime as dt

        if from_time:
            try:
                start_epoch = int(dt.fromisoformat(from_time.replace("Z", "+00:00")).timestamp())
            except ValueError:
                start_epoch = int(time.time()) - 7200
        else:
            hours = {
                "15m": 0.25,
                "30m": 0.5,
                "1h": 1,
                "2h": 2,
                "4h": 4,
                "6h": 6,
                "12h": 12,
                "24h": 24,
                "1d": 24,
                "2d": 48,
                "7d": 168,
            }
            start_epoch = int(time.time() - hours.get(time_range, 2) * 3600)

        if to_time and to_time != "now":
            try:
                end_epoch = int(dt.fromisoformat(to_time.replace("Z", "+00:00")).timestamp())
            except ValueError:
                end_epoch = int(time.time())
        else:
            end_epoch = int(time.time())

        data = self._request(
            "GET",
            "/api/v1/query",
            params={"from": str(start_epoch), "to": str(end_epoch), "query": query},
        )

        series_list = []
        for series in data.get("series", []):
            points = []
            for point in series.get("pointlist", []):
                if len(point) >= 2:
                    ts_ms, value = point[0], point[1]
                    points.append(
                        {
                            "timestamp": dt.fromtimestamp(ts_ms / 1000, tz=UTC).isoformat(),
                            "value": round(value, 4) if value is not None else None,
                        }
                    )

            unit_list = series.get("unit", [{}])
            unit_name = unit_list[0].get("name", "") if unit_list else ""

            series_list.append(
                {
                    "scope": series.get("scope", ""),
                    "unit": unit_name,
                    "points": points,
                }
            )

        return series_list

    def get_service_alerts(
        self,
        service: str,
        from_time: str | None = None,
        to_time: str | None = None,
    ) -> list[dict]:
        """Get alert events for a service in a time window."""
        from datetime import datetime as dt

        params: dict = {
            "tags": f"service:{service}",
            "sources": "alert,monitor",
        }

        if from_time:
            try:
                start_dt = dt.fromisoformat(from_time.replace("Z", "+00:00"))
                params["start"] = str(int(start_dt.timestamp()))
            except ValueError:
                params["start"] = from_time
        else:
            params["start"] = str(int(time.time()) - 7200)

        if to_time and to_time != "now":
            try:
                end_dt = dt.fromisoformat(to_time.replace("Z", "+00:00"))
                params["end"] = str(int(end_dt.timestamp()))
            except ValueError:
                params["end"] = to_time
        else:
            params["end"] = str(int(time.time()))

        data = self._request("GET", "/api/v1/events", params=params)
        return [
            {
                "id": e.get("id"),
                "title": e.get("title", ""),
                "text": e.get("text", "")[:500],
                "priority": e.get("priority", ""),
                "alert_type": e.get("alert_type", ""),
                "date_happened": e.get("date_happened"),
                "tags": e.get("tags", []),
                "source": e.get("source", ""),
            }
            for e in data.get("events", [])
        ]

    def search_slos(
        self,
        service: str = "",
        query: str = "",
    ) -> list[dict]:
        """Search Datadog SLOs for a service."""
        params: dict = {"limit": "100"}
        if service:
            params["tags"] = f"service:{service}"
        if query:
            params["query"] = query

        data = self._request("GET", "/api/v1/slo", params=params)
        slos = data.get("data", [])
        if not isinstance(slos, list):
            return []

        results = []
        for slo in slos:
            thresholds = slo.get("thresholds", [])
            current_status = slo.get("overall_status", [])

            threshold_info = []
            for th in thresholds:
                info: dict = {
                    "timeframe": th.get("timeframe", ""),
                    "target": th.get("target"),
                    "target_display": th.get("target_display", ""),
                }
                for status in current_status:
                    if status.get("timeframe") == th.get("timeframe"):
                        info["sli_value"] = status.get("sli_value")
                        info["error_budget_remaining"] = status.get("error_budget_remaining")
                        info["status"] = (
                            "breaching"
                            if status.get("error_budget_remaining") is not None
                            and status["error_budget_remaining"] < 0
                            else "ok"
                        )
                        break
                threshold_info.append(info)

            results.append(
                {
                    "id": slo.get("id", ""),
                    "name": slo.get("name", ""),
                    "type": slo.get("type", ""),
                    "tags": slo.get("tags", []),
                    "thresholds": threshold_info,
                }
            )
        return results

    def aggregate_logs(
        self,
        service: str,
        time_range: str = "2h",
        env: str = "production",
        from_time: str | None = None,
        to_time: str | None = None,
        group_by: list[str] | None = None,
        compute: list[dict] | None = None,
        query: str = "status:error",
    ) -> dict:
        """Aggregate logs using the Datadog Log Analytics API.

        Returns grouped counts or metrics (avg, p95, max) by facets.
        On 403/404, returns a fallback message instead of raising.
        """
        query_parts = [query]
        if service and f"service:{service}" not in query:
            query_parts.append(f"service:{service}")
        if env and f"env:{env}" not in query:
            query_parts.append(f"env:{env}")
        full_query = " ".join(query_parts)

        if from_time:
            resolved_from, resolved_to = from_time, to_time or "now"
        else:
            resolved_from, resolved_to = self._resolve_time_range(time_range)

        if compute is None:
            compute = [{"type": "total", "aggregation": "count"}]
        if group_by is None:
            group_by = ["@http.url_details.path"]

        group_by_payload = [
            {"facet": facet, "limit": 25, "sort": {"aggregation": "count", "order": "desc"}}
            for facet in group_by
        ]

        payload = {
            "filter": {
                "query": full_query,
                "from": resolved_from,
                "to": resolved_to,
            },
            "compute": compute,
            "group_by": group_by_payload,
        }

        try:
            data = self._request("POST", "/api/v2/logs/analytics/aggregate", json=payload)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (403, 404):
                return {
                    "error": "unavailable",
                    "message": (
                        "Log Analytics API is not available for this Datadog plan. "
                        "Use fetch_datadog_logs for raw log search."
                    ),
                }
            raise

        buckets = data.get("data", {}).get("buckets", [])
        results = []
        for bucket in buckets:
            entry: dict = {}
            by = bucket.get("by", {})
            for facet, value in by.items():
                entry[facet] = value
            computes = bucket.get("computes", {})
            for key, val in computes.items():
                entry[key] = val
            results.append(entry)

        return {
            "query": full_query,
            "time_range": {"from": resolved_from, "to": resolved_to},
            "group_by": group_by,
            "total_buckets": len(results),
            "buckets": results,
        }

    def search_watchdog_events(
        self,
        service: str = "",
        time_range: str = "2h",
        env: str = "production",
        from_time: str | None = None,
        to_time: str | None = None,
        change_only: bool = False,
    ) -> list[dict]:
        """Search Datadog Watchdog events (anomalies and change detection)."""
        from datetime import datetime as dt

        query_parts = ["source:watchdog"]
        if service:
            query_parts.append(f"service:{service}")
        if env:
            query_parts.append(f"env:{env}")
        if change_only:
            query_parts.append("story_type:change")

        if from_time:
            try:
                start_epoch = int(dt.fromisoformat(from_time.replace("Z", "+00:00")).timestamp())
            except ValueError:
                start_epoch = int(time.time()) - 7200
        else:
            hours = {"1h": 1, "2h": 2, "4h": 4, "6h": 6, "12h": 12, "24h": 24}
            start_epoch = int(time.time() - hours.get(time_range, 2) * 3600)

        if to_time and to_time != "now":
            try:
                end_epoch = int(dt.fromisoformat(to_time.replace("Z", "+00:00")).timestamp())
            except ValueError:
                end_epoch = int(time.time())
        else:
            end_epoch = int(time.time())

        params: dict = {
            "filter[query]": " ".join(query_parts),
            "filter[from]": str(start_epoch),
            "filter[to]": str(end_epoch),
            "page[limit]": "50",
        }

        data = self._request("GET", "/api/v2/events", params=params)
        events = data.get("data", [])
        if not isinstance(events, list):
            return []

        return [
            {
                "title": e.get("attributes", {}).get("title", ""),
                "text": e.get("attributes", {}).get("message", "")[:500],
                "timestamp": e.get("attributes", {}).get("timestamp", ""),
                "tags": e.get("attributes", {}).get("tags", []),
                "source": e.get("attributes", {}).get("evt", {}).get("name", ""),
                "priority": e.get("attributes", {}).get("priority", ""),
                "alert_type": e.get("attributes", {}).get("status", ""),
            }
            for e in events
        ]

    def search_error_tracking_issues(
        self,
        service: str,
        time_range: str = "2h",
        env: str = "production",
        from_time: str | None = None,
        to_time: str | None = None,
        limit: int = 25,
    ) -> list[dict]:
        """Search Datadog Error Tracking issues for a service.

        Falls back to log search with source:error-tracking if the
        Error Tracking API returns 404.
        """
        if from_time:
            resolved_from, resolved_to = from_time, to_time or "now"
        else:
            resolved_from, resolved_to = self._resolve_time_range(time_range)

        # Try the Error Tracking API first
        params: dict = {
            "filter[env]": env,
            "filter[service]": service,
            "filter[time_range]": f"{resolved_from},{resolved_to}",
            "page[limit]": str(min(limit, 100)),
        }

        try:
            data = self._request("GET", "/api/v2/error-tracking/issues", params=params)
            issues = data.get("data", [])
            if not isinstance(issues, list):
                issues = []
            return [
                {
                    "id": issue.get("id", ""),
                    "title": issue.get("attributes", {}).get("title", ""),
                    "error_type": issue.get("attributes", {}).get("error_type", ""),
                    "error_message": issue.get("attributes", {}).get("message", "")[:500],
                    "first_seen": issue.get("attributes", {}).get("first_seen", ""),
                    "last_seen": issue.get("attributes", {}).get("last_seen", ""),
                    "count": issue.get("attributes", {}).get("count", 0),
                    "status": issue.get("attributes", {}).get("status", ""),
                    "platform": issue.get("attributes", {}).get("platform", ""),
                    "service": issue.get("attributes", {}).get("service", service),
                }
                for issue in issues
            ]
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (404, 403):
                logger.info(
                    "Error Tracking API unavailable (HTTP %s), falling back to log search",
                    exc.response.status_code,
                )
            else:
                raise

        # Fallback: search logs with error-tracking source
        logs = self.collect_logs(
            service=service,
            env=env,
            from_time=from_time,
            to_time=to_time,
            time_range=time_range,
            limit=limit,
            query="source:error-tracking",
        )
        return [
            {
                "id": "",
                "title": log.message[:200] if log.message else "",
                "error_type": "",
                "error_message": log.message[:500] if log.message else "",
                "first_seen": log.timestamp,
                "last_seen": log.timestamp,
                "count": 1,
                "status": "OPEN",
                "platform": "",
                "service": service,
                "source": "log_fallback",
            }
            for log in logs
        ]

    def search_database_queries(
        self,
        service: str,
        time_range: str = "2h",
        env: str = "production",
        from_time: str | None = None,
        to_time: str | None = None,
        limit: int = 20,
    ) -> dict:
        """Search Datadog Database Monitoring for query performance data.

        On 403/404, returns a fallback message (DBM requires specific plan tier).
        """
        if from_time:
            resolved_from, resolved_to = from_time, to_time or "now"
        else:
            resolved_from, resolved_to = self._resolve_time_range(time_range)

        query_parts = [f"service:{service}"]
        if env:
            query_parts.append(f"env:{env}")

        payload = {
            "filter": {
                "query": " ".join(query_parts),
                "from": resolved_from,
                "to": resolved_to,
            },
            "sort": "-error_count",
            "page": {"limit": min(limit, 50)},
        }

        try:
            data = self._request("POST", "/api/v2/dbm/queries", json=payload)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (403, 404):
                return {
                    "error": "unavailable",
                    "message": (
                        "Database Monitoring is not available for this service. "
                        "Use fetch_database_errors for log-based DB error detection."
                    ),
                }
            raise

        queries = data.get("data", [])
        if not isinstance(queries, list):
            queries = []

        return {
            "service": service,
            "total": len(queries),
            "queries": [
                {
                    "query_signature": q.get("attributes", {}).get("query_signature", ""),
                    "avg_latency_ms": q.get("attributes", {}).get("avg_latency", 0),
                    "total_executions": q.get("attributes", {}).get("total_executions", 0),
                    "error_count": q.get("attributes", {}).get("error_count", 0),
                    "database_instance": q.get("attributes", {}).get("db_instance", ""),
                    "query_text": q.get("attributes", {}).get("query_text", "")[:500],
                }
                for q in queries[:limit]
            ],
        }

    def collect_logs_multi(
        self,
        services: list[str],
        time_range: str = "2h",
        env: str = "production",
        from_time: str | None = None,
        to_time: str | None = None,
        limit_per_service: int = 20,
    ) -> dict[str, list[LogEntry]]:
        """Collect logs across multiple services with bounded concurrency."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results: dict[str, list[LogEntry]] = {}

        def _fetch(svc: str) -> tuple[str, list[LogEntry]]:
            dd = DatadogCollector(api_key=self.api_key, app_key=self.app_key, site=self.site)
            return svc, dd.collect_logs(
                service=svc,
                time_range=time_range,
                env=env,
                from_time=from_time,
                to_time=to_time,
                limit=limit_per_service,
            )

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {executor.submit(_fetch, svc): svc for svc in services}
            for future in as_completed(futures):
                svc = futures[future]
                try:
                    _, logs = future.result()
                    if logs:
                        results[svc] = logs
                except Exception as e:
                    logger.warning("Failed to collect logs for %s: %s", svc, e)

        return results

    # ---- RUM (Real User Monitoring) methods ----

    def search_rum_events(
        self,
        service: str = "",
        query: str = "@type:error",
        time_range: str = "2h",
        env: str = "production",
        from_time: str | None = None,
        to_time: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Search Datadog RUM events — browser errors, actions, and views.

        Uses the same DD_API_KEY/DD_APP_KEY as other Datadog APIs.
        Returns empty list if RUM is not configured for the org.
        """
        query_parts = [query]
        if service:
            query_parts.append(f"service:{service}")
        if env:
            query_parts.append(f"@context.env:{env}")

        if from_time:
            resolved_from, resolved_to = from_time, to_time or "now"
        else:
            resolved_from, resolved_to = self._resolve_time_range(time_range)

        payload = {
            "filter": {
                "query": " ".join(query_parts),
                "from": resolved_from,
                "to": resolved_to,
            },
            "page": {"limit": min(limit, 50)},
            "sort": "-timestamp",
        }

        try:
            data = self._request("POST", "/api/v2/rum/events/search", json=payload)
        except Exception as e:
            logger.warning("RUM search failed: %s", e)
            return []

        events = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            events.append(
                {
                    "type": attrs.get("type", ""),
                    "timestamp": attrs.get("date", ""),
                    "service": attrs.get("service", ""),
                    "view_url": attrs.get("view", {}).get("url", ""),
                    "view_name": attrs.get("view", {}).get("name", ""),
                    "error_message": attrs.get("error", {}).get("message", ""),
                    "error_source": attrs.get("error", {}).get("source", ""),
                    "error_type": attrs.get("error", {}).get("type", ""),
                    "error_stack": (attrs.get("error", {}).get("stack", "") or "")[:500],
                    "browser": attrs.get("browser", {}).get("name", ""),
                    "os": attrs.get("os", {}).get("name", ""),
                    "session_id": attrs.get("session", {}).get("id", ""),
                    "action_type": attrs.get("action", {}).get("type", ""),
                    "resource_url": attrs.get("resource", {}).get("url", ""),
                }
            )
        return events

    def search_rum_performance(
        self,
        service: str = "",
        time_range: str = "2h",
        env: str = "production",
        from_time: str | None = None,
        to_time: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Search RUM performance views — page load times and resource loading.

        Returns view events with loading performance metrics.
        """
        return self.search_rum_events(
            service=service,
            query="@type:view",
            time_range=time_range,
            env=env,
            from_time=from_time,
            to_time=to_time,
            limit=limit,
        )
