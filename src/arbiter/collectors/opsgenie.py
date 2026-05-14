"""OpsGenie collector — fetches alerts, timeline, and responder data via OpsGenie API."""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime, timedelta

import httpx

from arbiter.collectors.base import Collector
from arbiter.core.models import (
    AlertInfo,
    EventSource,
    LogEntry,
    LogLevel,
    Severity,
    TimelineEvent,
)
from arbiter.credentials import load_credentials

load_credentials()


# OpsGenie priority → Severity mapping
_PRIORITY_MAP = {
    "P1": Severity.P1,
    "P2": Severity.P2,
    "P3": Severity.P3,
    "P4": Severity.P4,
    "P5": Severity.P4,
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


class OpsGenieCollector(Collector):
    """Collector for OpsGenie Alerts API.

    Requires:
        OPSGENIE_API_KEY — API key with read access
        OPSGENIE_BASE_URL — (optional) defaults to https://api.opsgenie.com
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        self.api_key = api_key or os.environ.get("OPSGENIE_API_KEY", "")
        self.base_url = (
            base_url or os.environ.get("OPSGENIE_BASE_URL", "https://api.opsgenie.com")
        ).rstrip("/")
        self._headers = {
            "Authorization": f"GenieKey {self.api_key}",
            "Content-Type": "application/json",
        }

    @property
    def source(self) -> EventSource:
        return EventSource.OPSGENIE

    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _request(self, method: str, path: str, params: dict | None = None) -> dict:
        """Make an API request with retry on rate limit."""
        url = f"{self.base_url}{path}"
        last_resp = None
        with httpx.Client(timeout=30) as client:
            for attempt in range(3):
                last_resp = client.request(method, url, headers=self._headers, params=params)
                if last_resp.status_code == 429:
                    retry_after = int(
                        last_resp.headers.get("X-RateLimit-Period-In-Sec", 2**attempt + 1)
                    )
                    time.sleep(min(retry_after, 10))
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
        """Collect OpsGenie alerts as log entries."""
        alerts = self.get_alerts(
            service=service,
            time_range=time_range,
            from_time=from_time,
            to_time=to_time,
            limit=limit,
            query=query,
        )

        return [
            LogEntry(
                timestamp=alert.get("createdAt", ""),
                level=(
                    LogLevel.CRITICAL if alert.get("priority") in ("P1", "P2") else LogLevel.ERROR
                ),
                message=f"[{alert.get('priority', '?')}] {alert.get('message', '')}",
                service=service,
                source=EventSource.OPSGENIE,
                metadata={
                    "alert_id": alert.get("id"),
                    "status": alert.get("status"),
                    "acknowledged": alert.get("acknowledged", False),
                    "owner": alert.get("owner", ""),
                    "responders": [
                        r.get("name", r.get("id", "")) for r in alert.get("responders", [])
                    ],
                },
            )
            for alert in alerts
        ]

    def collect_events(
        self,
        service: str,
        time_range: str = "2h",
        from_time: str | None = None,
        to_time: str | None = None,
    ) -> list[TimelineEvent]:
        """Collect OpsGenie alerts as timeline events."""
        alerts = self.get_alerts(
            service=service,
            time_range=time_range,
            from_time=from_time,
            to_time=to_time,
        )

        events: list[TimelineEvent] = []
        for alert in alerts:
            # Alert creation
            events.append(
                TimelineEvent(
                    timestamp=alert.get("createdAt", ""),
                    message=f"OpsGenie Alert: [{alert.get('priority', '?')}] {alert.get('message', '')}",
                    source=EventSource.OPSGENIE,
                    service=service,
                    level=(
                        LogLevel.CRITICAL
                        if alert.get("priority") in ("P1", "P2")
                        else LogLevel.ERROR
                    ),
                    metadata={"alert_id": alert.get("id"), "type": "alert_created"},
                )
            )

            # Alert acknowledged
            if alert.get("acknowledged"):
                events.append(
                    TimelineEvent(
                        timestamp=alert.get("updatedAt", alert.get("createdAt", "")),
                        message=f"Alert acknowledged by {alert.get('owner', 'unknown')}",
                        source=EventSource.OPSGENIE,
                        service=service,
                        level=LogLevel.INFO,
                        metadata={"alert_id": alert.get("id"), "type": "acknowledged"},
                    )
                )

        return events

    # ---- OpsGenie-specific methods ----

    def get_alerts(
        self,
        service: str | None = None,
        time_range: str = "2h",
        from_time: str | None = None,
        to_time: str | None = None,
        limit: int = 20,
        query: str = "",
    ) -> list[dict]:
        """Get alerts from OpsGenie, optionally filtered by service tag.

        Args:
            service: Filter by service tag
            time_range: Relative time range (e.g. "2h", "24h")
            from_time: Absolute start time (ISO 8601)
            to_time: Absolute end time (ISO 8601)
            limit: Max results
            query: Custom OpsGenie query
        """
        # Build query
        query_parts = []
        if query:
            query_parts.append(query)

        if service:
            query_parts.append(f'tag:"service:{service}"')

        # Time filter
        if from_time:
            query_parts.append(f"createdAt >= {self._to_epoch_ms(from_time)}")
            if to_time and to_time != "now":
                query_parts.append(f"createdAt <= {self._to_epoch_ms(to_time)}")
        else:
            hours = _TIME_RANGE_HOURS.get(time_range, 2)
            since = datetime.now(UTC) - timedelta(hours=hours)
            query_parts.append(f"createdAt >= {int(since.timestamp() * 1000)}")

        params: dict = {
            "limit": str(min(limit, 100)),
            "sort": "createdAt",
            "order": "desc",
        }
        if query_parts:
            params["query"] = " AND ".join(query_parts)

        data = self._request("GET", "/v2/alerts", params=params)
        return data.get("data", [])

    def get_alert_logs(self, alert_id: str) -> list[dict]:
        """Get the activity log for an alert (acknowledge, assign, close, etc.)."""
        data = self._request("GET", f"/v2/alerts/{alert_id}/logs")
        return data.get("data", [])

    def get_alert_notes(self, alert_id: str) -> list[dict]:
        """Get notes/comments on an alert."""
        data = self._request("GET", f"/v2/alerts/{alert_id}/notes")
        return data.get("data", [])

    def get_alert_timeline(self, alert_id: str) -> list[TimelineEvent]:
        """Build a detailed timeline from alert logs and notes."""
        events: list[TimelineEvent] = []

        # Alert logs (state changes)
        logs = self.get_alert_logs(alert_id)
        for log in logs:
            events.append(
                TimelineEvent(
                    timestamp=log.get("createdAt", ""),
                    message=log.get("log", ""),
                    source=EventSource.OPSGENIE,
                    service="",
                    level=LogLevel.INFO,
                    metadata={"type": "alert_log", "owner": log.get("owner", "")},
                )
            )

        # Notes
        notes = self.get_alert_notes(alert_id)
        for note in notes:
            events.append(
                TimelineEvent(
                    timestamp=note.get("createdAt", ""),
                    message=f"Note by {note.get('owner', '?')}: {note.get('note', '')}",
                    source=EventSource.OPSGENIE,
                    service="",
                    level=LogLevel.INFO,
                    metadata={"type": "note"},
                )
            )

        events.sort(key=lambda e: e.sort_key())
        return events

    def get_structured_alerts(
        self,
        service: str | None = None,
        time_range: str = "2h",
    ) -> list[AlertInfo]:
        """Get alerts as structured AlertInfo objects."""
        raw_alerts = self.get_alerts(service=service, time_range=time_range)
        alerts = []
        for a in raw_alerts:
            priority = a.get("priority", "P3")
            alerts.append(
                AlertInfo(
                    id=a.get("id", ""),
                    title=a.get("message", ""),
                    severity=_PRIORITY_MAP.get(priority, Severity.P3),
                    status=a.get("status", ""),
                    source=EventSource.OPSGENIE,
                    created_at=a.get("createdAt", ""),
                    acknowledged_at=a.get("updatedAt", "") if a.get("acknowledged") else "",
                    responders=[r.get("name", r.get("id", "")) for r in a.get("responders", [])],
                    tags=a.get("tags", []),
                    message=a.get("description", "")[:500],
                    metadata={
                        "priority": priority,
                        "count": a.get("count", 0),
                        "source": a.get("source", ""),
                        "integration": a.get("integration", {}).get("name", ""),
                    },
                )
            )
        return alerts

    def _to_epoch_ms(self, iso_time: str) -> int:
        """Convert ISO 8601 timestamp to epoch milliseconds."""
        try:
            dt = datetime.fromisoformat(iso_time.replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except ValueError:
            return 0
