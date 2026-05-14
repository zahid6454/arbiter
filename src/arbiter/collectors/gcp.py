"""GCP Cloud Logging collector — fetches logs via Google Cloud Logging API."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

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

load_credentials()


# GCP severity → LogLevel mapping
_SEVERITY_MAP = {
    "EMERGENCY": LogLevel.CRITICAL,
    "ALERT": LogLevel.CRITICAL,
    "CRITICAL": LogLevel.CRITICAL,
    "ERROR": LogLevel.ERROR,
    "WARNING": LogLevel.WARNING,
    "NOTICE": LogLevel.INFO,
    "INFO": LogLevel.INFO,
    "DEBUG": LogLevel.DEBUG,
    "DEFAULT": LogLevel.INFO,
}

# Time range → hours mapping
_TIME_RANGE_HOURS = {
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


class GCPCollector(Collector):
    """Collector for Google Cloud Logging API.

    Auth options (in priority order):
    1. GCP_SERVICE_ACCOUNT_KEY_FILE — path to service account JSON key
    2. GCP_ACCESS_TOKEN — pre-fetched OAuth2 access token
    3. Application Default Credentials via gcloud CLI

    GCP project is determined per-service from services.yaml (gcp_project field),
    passed via project_override or project parameter on each call.

    Set GCLOUD_CONFIGURATION to control which gcloud config is used for CLI
    auth (defaults to "default"). Needed when the active gcloud config disables
    credentials (e.g. a Spanner emulator config).
    """

    def __init__(
        self,
        project_id: str | None = None,
        access_token: str | None = None,
        key_file: str | None = None,
    ):
        self.project_id = project_id or ""
        self._access_token = access_token or os.environ.get("GCP_ACCESS_TOKEN", "")
        self._key_file = key_file or os.environ.get("GCP_SERVICE_ACCOUNT_KEY_FILE", "")
        self._gcloud_config = os.environ.get("GCLOUD_CONFIGURATION", "default")
        self.base_url = "https://logging.googleapis.com/v2"

    @property
    def source(self) -> EventSource:
        return EventSource.GCP

    def is_configured(self) -> bool:
        if self._access_token or self._key_file:
            return True
        import shutil

        return shutil.which("gcloud") is not None

    def _get_access_token(self) -> str:
        """Get an access token, refreshing from service account if needed."""
        if self._access_token:
            return self._access_token

        if self._key_file:
            return self._token_from_service_account()

        # Try gcloud CLI as fallback
        import subprocess

        try:
            result = subprocess.run(
                ["gcloud", f"--configuration={self._gcloud_config}", "auth", "print-access-token"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return ""

    def _token_from_service_account(self) -> str:
        """Get access token from service account key file via gcloud impersonation."""
        import subprocess

        key_path = Path(self._key_file)
        if not key_path.exists():
            return ""

        sa_info = json.loads(key_path.read_text())

        try:
            result = subprocess.run(
                [
                    "gcloud",
                    f"--configuration={self._gcloud_config}",
                    "auth",
                    "print-access-token",
                    f"--impersonate-service-account={sa_info['client_email']}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return ""

    def _request(self, method: str, path: str, json_body: dict | None = None) -> dict:
        """Make an API request with auth and retry."""
        token = self._get_access_token()
        if not token:
            raise ValueError(
                "No GCP access token available. Set GCP_ACCESS_TOKEN or configure gcloud."
            )

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        url = f"{self.base_url}{path}"

        last_resp = None
        with httpx.Client(timeout=60) as client:
            for attempt in range(3):
                if method == "POST":
                    last_resp = client.post(url, headers=headers, json=json_body)
                else:
                    last_resp = client.get(url, headers=headers)
                if last_resp.status_code == 429:
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

    def _container_request(self, path: str) -> dict:
        """Make a GET request to the GKE Container API."""
        token = self._get_access_token()
        if not token:
            raise ValueError(
                "No GCP access token available. Set GCP_ACCESS_TOKEN or configure gcloud."
            )

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        url = f"https://container.googleapis.com/v1{path}"

        last_resp = None
        with httpx.Client(timeout=60) as client:
            for attempt in range(3):
                last_resp = client.get(url, headers=headers)
                if last_resp.status_code == 429:
                    time.sleep(min(2**attempt + 1, 10))
                    continue
                last_resp.raise_for_status()
                return last_resp.json()
        if last_resp is not None:
            last_resp.raise_for_status()
        raise httpx.HTTPStatusError(
            "Rate limited after 3 retries",
            request=httpx.Request("GET", url),
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
        project_override: str | None = None,
    ) -> list[LogEntry]:
        """Collect logs from GCP Cloud Logging.

        Args:
            project_override: GCP project ID to query instead of the default.
        """
        # Build time filter
        if from_time:
            time_filter = f'timestamp >= "{from_time}"'
            if to_time and to_time != "now":
                time_filter += f' AND timestamp <= "{to_time}"'
        else:
            hours = _TIME_RANGE_HOURS.get(time_range, 2)
            start = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
            time_filter = f'timestamp >= "{start}"'

        # Build log filter
        parts = [time_filter]
        if query:
            parts.append(query)
        else:
            parts.append("severity >= ERROR")

        # Only add service filter if service name is provided
        if service:
            service_filter = (
                f'(labels.service="{service}" OR '
                f'resource.labels.service_name="{service}" OR '
                f'resource.labels.container_name="{service}" OR '
                f'logName=~"{service}")'
            )
            parts.append(service_filter)

        log_filter = "\n".join(parts)

        project = project_override or self.project_id
        if not project:
            logger.warning("No GCP project configured — skipping log collection")
            return []
        body = {
            "resourceNames": [f"projects/{project}"],
            "filter": log_filter,
            "orderBy": "timestamp desc",
            "pageSize": min(limit, 1000),
        }

        data = self._request("POST", "/entries:list", json_body=body)
        return self._parse_entries(data.get("entries", []), service)

    def collect_events(
        self,
        service: str,
        time_range: str = "2h",
        from_time: str | None = None,
        to_time: str | None = None,
    ) -> list[TimelineEvent]:
        """Collect GCP log entries as timeline events."""
        logs = self.collect_logs(
            service=service,
            time_range=time_range,
            from_time=from_time,
            to_time=to_time,
            limit=20,
        )
        return [
            TimelineEvent(
                timestamp=log.timestamp,
                message=f"[GCP] {log.message[:200]}",
                source=EventSource.GCP,
                service=service,
                level=log.level,
            )
            for log in logs
        ]

    def collect_audit_logs(
        self,
        project: str,
        time_range: str = "6h",
        from_time: str | None = None,
        to_time: str | None = None,
        limit: int = 50,
    ) -> list[LogEntry]:
        """Fetch GCP audit logs for infrastructure changes.

        Runs two separate queries to prevent routine events (e.g.
        cloudsql.instances.connect at 1/min) from drowning out meaningful
        system events:
          1. Admin Activity — excludes routine connect events
          2. System Events — separate query so they always appear
        """
        if from_time:
            time_filter = f'timestamp >= "{from_time}"'
            if to_time and to_time != "now":
                time_filter += f' AND timestamp <= "{to_time}"'
        else:
            hours = _TIME_RANGE_HOURS.get(time_range, 6)
            start = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
            time_filter = f'timestamp >= "{start}"'

        per_query_limit = min(limit, 1000)

        # Query 1: Admin Activity — exclude routine CloudSQL connect noise
        activity_filter = "\n".join(
            [
                f'logName="projects/{project}/logs/cloudaudit.googleapis.com%2Factivity"',
                time_filter,
                'NOT protoPayload.methodName="cloudsql.instances.connect"',
            ]
        )
        activity_body = {
            "resourceNames": [f"projects/{project}"],
            "filter": activity_filter,
            "orderBy": "timestamp desc",
            "pageSize": per_query_limit,
        }

        activity_entries: list[LogEntry] = []
        try:
            data = self._request("POST", "/entries:list", json_body=activity_body)
            activity_entries = self._parse_audit_entries(data.get("entries", []), project)
        except Exception as e:
            logger.warning("GCP admin activity audit log query failed: %s", e)

        # Query 2: System Events — separate so they are never drowned out
        system_filter = "\n".join(
            [
                f'logName="projects/{project}/logs/cloudaudit.googleapis.com%2Fsystem_event"',
                time_filter,
            ]
        )
        system_body = {
            "resourceNames": [f"projects/{project}"],
            "filter": system_filter,
            "orderBy": "timestamp desc",
            "pageSize": per_query_limit,
        }

        system_entries: list[LogEntry] = []
        try:
            data = self._request("POST", "/entries:list", json_body=system_body)
            system_entries = self._parse_audit_entries(data.get("entries", []), project)
        except Exception as e:
            logger.warning("GCP system event audit log query failed: %s", e)

        # Merge, sort by timestamp descending, trim to limit
        combined = activity_entries + system_entries
        combined.sort(key=lambda e: e.timestamp, reverse=True)
        return combined[:limit]

    # ---- GCP-specific methods ----

    def _parse_audit_entries(self, entries: list[dict], project: str) -> list[LogEntry]:
        """Parse GCP audit log entries into LogEntry objects."""
        results = []
        for entry in entries:
            timestamp = entry.get("timestamp", "")
            proto = entry.get("protoPayload", {})

            method = proto.get("methodName", "")
            resource = proto.get("resourceName", "")
            if not method and not resource:
                continue
            principal = proto.get("authenticationInfo", {}).get("principalEmail", "")
            status = proto.get("status", {})
            status_msg = status.get("message", "")

            message = f"{method} on {resource}"
            if principal:
                message += f" by {principal}"
            if status_msg:
                message += f" ({status_msg})"

            log_name = entry.get("logName", "")
            audit_type = "system_event" if "system_event" in log_name else "admin_activity"

            results.append(
                LogEntry(
                    timestamp=timestamp,
                    level=LogLevel.INFO,
                    message=message[:500],
                    service=project,
                    source=EventSource.GCP,
                    metadata={
                        "method_name": method,
                        "resource_name": resource,
                        "principal_email": principal,
                        "log_name": log_name,
                        "audit_type": audit_type,
                    },
                )
            )
        return results

    def _parse_entries(self, entries: list[dict], default_service: str) -> list[LogEntry]:
        """Parse GCP Cloud Logging entries into LogEntry objects."""
        results = []
        for entry in entries:
            timestamp = entry.get("timestamp", entry.get("receiveTimestamp", ""))
            severity = entry.get("severity", "DEFAULT")
            level = _SEVERITY_MAP.get(severity, LogLevel.INFO)

            # Extract message from various payload types
            message = ""
            if "textPayload" in entry:
                message = entry["textPayload"]
            elif "jsonPayload" in entry:
                payload = entry["jsonPayload"]
                message = (
                    payload.get("message")
                    or payload.get("msg")
                    or payload.get("error")
                    or json.dumps(payload)[:500]
                )
            elif "protoPayload" in entry:
                proto = entry["protoPayload"]
                message = proto.get("status", {}).get("message", json.dumps(proto)[:500])

            # Extract service from labels/resource
            labels = entry.get("labels", {})
            resource_labels = entry.get("resource", {}).get("labels", {})
            service = (
                labels.get("service")
                or resource_labels.get("service_name")
                or resource_labels.get("container_name")
                or default_service
            )

            results.append(
                LogEntry(
                    timestamp=timestamp,
                    level=level,
                    message=message[:500],
                    service=service,
                    source=EventSource.GCP,
                    environment=resource_labels.get("namespace_name", ""),
                    host=resource_labels.get("instance_id", ""),
                    container=resource_labels.get("container_name", ""),
                    pod=resource_labels.get("pod_name", ""),
                    trace_id=entry.get("trace", ""),
                    metadata={
                        "log_name": entry.get("logName", ""),
                        "insert_id": entry.get("insertId", ""),
                        "resource_type": entry.get("resource", {}).get("type", ""),
                    },
                )
            )
        return results

    def get_error_summary(
        self,
        service: str,
        time_range: str = "2h",
        limit: int = 100,
    ) -> dict:
        """Get grouped error summary from GCP logs."""
        logs = self.collect_logs(
            service=service,
            time_range=time_range,
            limit=limit,
        )

        error_groups: dict[str, int] = {}
        for entry in logs:
            key = entry.message[:100] if entry.message else "unknown"
            error_groups[key] = error_groups.get(key, 0) + 1

        sorted_errors = sorted(error_groups.items(), key=lambda x: -x[1])
        return {
            "service": service,
            "source": "gcp",
            "time_range": time_range,
            "total_errors": len(logs),
            "unique_patterns": len(error_groups),
            "top_errors": [{"pattern": p, "count": c} for p, c in sorted_errors[:10]],
        }

    # ---- Load Balancer logs ----

    def collect_lb_logs(
        self,
        project: str,
        time_range: str = "2h",
        from_time: str | None = None,
        to_time: str | None = None,
        limit: int = 50,
    ) -> list[LogEntry]:
        """Fetch GCP HTTP Load Balancer access logs with 5xx status codes."""
        if from_time:
            time_filter = f'timestamp >= "{from_time}"'
            if to_time and to_time != "now":
                time_filter += f' AND timestamp <= "{to_time}"'
        else:
            hours = _TIME_RANGE_HOURS.get(time_range, 2)
            start = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
            time_filter = f'timestamp >= "{start}"'

        log_filter = "\n".join(
            [
                'resource.type="http_load_balancer"',
                "httpRequest.status>=500",
                time_filter,
            ]
        )

        body = {
            "resourceNames": [f"projects/{project}"],
            "filter": log_filter,
            "orderBy": "timestamp desc",
            "pageSize": min(limit, 1000),
        }

        data = self._request("POST", "/entries:list", json_body=body)
        return self._parse_lb_entries(data.get("entries", []))

    def _parse_lb_entries(self, entries: list[dict]) -> list[LogEntry]:
        """Parse LB access log entries."""
        results = []
        for entry in entries:
            timestamp = entry.get("timestamp", "")
            req = entry.get("httpRequest", {})
            status = req.get("status", 0)
            url = req.get("requestUrl", "")
            latency = req.get("latency", "")
            backend = entry.get("resource", {}).get("labels", {}).get("backend_service_name", "")

            message = f"{status} {req.get('requestMethod', '')} {url}"
            if backend:
                message += f" (backend: {backend})"
            if latency:
                message += f" latency={latency}"

            results.append(
                LogEntry(
                    timestamp=timestamp,
                    level=LogLevel.ERROR,
                    message=message[:500],
                    service=backend or "load-balancer",
                    source=EventSource.GCP,
                    metadata={
                        "status_code": status,
                        "request_url": url,
                        "backend": backend,
                        "latency": latency,
                        "resource_type": "http_load_balancer",
                    },
                )
            )
        return results

    # ---- CloudSQL instance logs ----

    def collect_cloudsql_logs(
        self,
        instance: str,
        project: str,
        time_range: str = "2h",
        from_time: str | None = None,
        to_time: str | None = None,
        limit: int = 50,
    ) -> list[LogEntry]:
        """Fetch CloudSQL postgres.log entries — DB-side view of restarts, connection drops."""
        if from_time:
            time_filter = f'timestamp >= "{from_time}"'
            if to_time and to_time != "now":
                time_filter += f' AND timestamp <= "{to_time}"'
        else:
            hours = _TIME_RANGE_HOURS.get(time_range, 2)
            start = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()
            time_filter = f'timestamp >= "{start}"'

        log_filter = "\n".join(
            [
                'resource.type="cloudsql_database"',
                f'resource.labels.database_id="{project}:{instance}"',
                time_filter,
            ]
        )

        body = {
            "resourceNames": [f"projects/{project}"],
            "filter": log_filter,
            "orderBy": "timestamp desc",
            "pageSize": min(limit, 1000),
        }

        data = self._request("POST", "/entries:list", json_body=body)
        return self._parse_entries(data.get("entries", []), instance)

    # ---- GKE Container API ----

    _TRIVIAL_OPS: ClassVar[set[str]] = {"SET_LABELS", "SET_MAINTENANCE_POLICY", "SET_ADDONS_CONFIG"}

    def collect_gke_operations(
        self,
        project: str,
        location: str,
        cluster: str | None = None,
        time_range: str = "6h",
        from_time: str | None = None,
        to_time: str | None = None,
    ) -> list[dict]:
        """Fetch GKE cluster operations (upgrades, repairs, node pool changes).

        Uses the Container API, not Cloud Logging. Returns operations filtered
        by cluster name and time window.
        """
        path = f"/projects/{project}/locations/{location}/operations"
        data = self._container_request(path)

        if from_time:
            window_start = datetime.fromisoformat(from_time.replace("Z", "+00:00"))
        else:
            hours = _TIME_RANGE_HOURS.get(time_range, 6)
            window_start = datetime.now(UTC) - timedelta(hours=hours)

        if to_time and to_time != "now":
            window_end = datetime.fromisoformat(to_time.replace("Z", "+00:00"))
        else:
            window_end = datetime.now(UTC)

        results = []
        for op in data.get("operations", []):
            op_type = op.get("operationType", "")
            if op_type in self._TRIVIAL_OPS:
                continue

            if cluster:
                target = op.get("targetLink", "")
                target_parts = target.split("/")
                try:
                    cluster_idx = target_parts.index("clusters")
                    if target_parts[cluster_idx + 1] != cluster:
                        continue
                except (ValueError, IndexError):
                    continue

            start_str = op.get("startTime", "")
            end_str = op.get("endTime", "")
            if not start_str:
                continue

            try:
                op_start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
            except ValueError:
                continue

            op_end = None
            if end_str:
                with contextlib.suppress(ValueError):
                    op_end = datetime.fromisoformat(end_str.replace("Z", "+00:00"))

            if op_end and op_end < window_start:
                continue
            if op_start > window_end:
                continue

            target_link = op.get("targetLink", "")
            target_name = target_link.rsplit("/", 1)[-1] if target_link else ""

            node_conditions = {}
            for cond in op.get("nodepoolConditions", []):
                code = cond.get("code", "")
                if not code:
                    continue
                msg = cond.get("message", "")
                try:
                    node_conditions[code] = int(msg)
                except (ValueError, TypeError):
                    node_conditions[code] = msg

            detail_parts = []
            if op.get("statusMessage"):
                detail_parts.append(op["statusMessage"])
            progress = op.get("progress", {})
            if progress:
                pct = progress.get("current", 0)
                total = progress.get("total", 0)
                if total:
                    detail_parts.append(f"progress: {pct}/{total}")

            results.append(
                {
                    "operation_type": op_type,
                    "status": op.get("status", ""),
                    "start_time": start_str,
                    "end_time": end_str,
                    "cluster": cluster or "",
                    "target": target_name,
                    "detail": " | ".join(detail_parts) if detail_parts else "",
                    "node_conditions": node_conditions,
                }
            )

        results.sort(key=lambda x: x.get("start_time", ""))
        return results

    # ---- CloudSQL Operations API ----

    def collect_cloudsql_operations(
        self,
        instance: str,
        project: str,
        time_range: str = "6h",
        from_time: str | None = None,
        to_time: str | None = None,
    ) -> list[dict]:
        """Fetch CloudSQL operations (maintenance, failover, restart) via gcloud CLI.

        CloudSQL scheduled maintenance is ONLY visible through this API — it
        does not appear in admin activity or system event audit logs.
        """
        import subprocess

        if from_time:
            start_filter = from_time
        else:
            hours = _TIME_RANGE_HOURS.get(time_range, 6)
            start_filter = (datetime.now(UTC) - timedelta(hours=hours)).isoformat()

        filter_expr = f"startTime>={start_filter}"
        if to_time and to_time != "now":
            filter_expr += f" AND startTime<={to_time}"

        cmd = [
            "gcloud",
            f"--configuration={self._gcloud_config}",
            "sql",
            "operations",
            "list",
            f"--instance={instance}",
            f"--project={project}",
            f"--filter={filter_expr}",
            "--format=json",
            "--limit=50",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"gcloud sql operations list timed out for {instance}") from exc
        except FileNotFoundError as exc:
            raise RuntimeError(
                "gcloud CLI not found — install Google Cloud SDK or run 'gcloud auth login'"
            ) from exc

        if result.returncode != 0:
            raise RuntimeError(
                f"gcloud sql operations list failed (rc={result.returncode}): {result.stderr[:200]}"
            )

        try:
            ops = json.loads(result.stdout) if result.stdout.strip() else []
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse CloudSQL operations output: {e}") from e

        results = []
        for op in ops:
            results.append(
                {
                    "operation_type": op.get("operationType", ""),
                    "status": op.get("status", ""),
                    "start_time": op.get("startTime", ""),
                    "end_time": op.get("endTime", ""),
                    "instance": instance,
                    "project": project,
                    "error": op.get("error", {}).get("errors", []),
                }
            )
        results.sort(key=lambda x: x.get("start_time", ""))
        return results
