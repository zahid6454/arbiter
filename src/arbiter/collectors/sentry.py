"""Sentry collector — fetches errors, breadcrumbs, and stack traces via Sentry API."""

from __future__ import annotations

import os
import time

import httpx

from arbiter.collectors.base import Collector
from arbiter.core.models import (
    EventSource,
    LogEntry,
    LogLevel,
    TimelineEvent,
)
from arbiter.credentials import load_credentials

load_credentials()


def _parse_level(level: str) -> LogLevel:
    upper = level.upper()
    if upper in ("FATAL", "CRITICAL"):
        return LogLevel.CRITICAL
    if upper == "ERROR":
        return LogLevel.ERROR
    if upper in ("WARNING", "WARN"):
        return LogLevel.WARNING
    if upper == "INFO":
        return LogLevel.INFO
    return LogLevel.DEBUG


class SentryCollector(Collector):
    """Collector for Sentry Issues and Events API.

    Requires:
        SENTRY_AUTH_TOKEN — org-level auth token with event:read, project:read
        SENTRY_ORG — organization slug
        SENTRY_BASE_URL — (optional) defaults to https://sentry.io
    """

    def __init__(
        self,
        auth_token: str | None = None,
        org: str | None = None,
        base_url: str | None = None,
    ):
        self.auth_token = auth_token or os.environ.get("SENTRY_AUTH_TOKEN", "")
        self.org = org or os.environ.get("SENTRY_ORG", "")
        self.base_url = (base_url or os.environ.get("SENTRY_BASE_URL", "https://sentry.io")).rstrip(
            "/"
        )
        self._headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
        }

    @property
    def source(self) -> EventSource:
        return EventSource.SENTRY

    def is_configured(self) -> bool:
        return bool(self.auth_token and self.org)

    def _request(self, method: str, path: str, params: dict | None = None) -> list | dict:
        """Make an API request with retry on rate limit."""
        url = f"{self.base_url}/api/0{path}"
        last_resp = None
        with httpx.Client(timeout=30) as client:
            for attempt in range(3):
                last_resp = client.request(method, url, headers=self._headers, params=params)
                if last_resp.status_code == 429:
                    retry_after = int(last_resp.headers.get("Retry-After", 2**attempt + 1))
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
        """Collect Sentry issues as log entries.

        Maps Sentry project to service name. The `service` parameter is
        used as the Sentry project slug.
        """
        issues = self.get_project_issues(
            project_slug=service,
            query=query or "is:unresolved",
            time_range=time_range,
            env=env,
            limit=limit,
        )

        entries = []
        for issue in issues:
            entries.append(
                LogEntry(
                    timestamp=issue.get("lastSeen", ""),
                    level=_parse_level(issue.get("level", "error")),
                    message=f"{issue.get('title', '')} (count: {issue.get('count', 0)})",
                    service=service,
                    source=EventSource.SENTRY,
                    environment=env,
                    metadata={
                        "issue_id": issue.get("id"),
                        "short_id": issue.get("shortId"),
                        "culprit": issue.get("culprit", ""),
                        "first_seen": issue.get("firstSeen", ""),
                        "count": issue.get("count", 0),
                        "user_count": issue.get("userCount", 0),
                    },
                )
            )
        return entries

    def collect_events(
        self,
        service: str,
        time_range: str = "2h",
        from_time: str | None = None,
        to_time: str | None = None,
    ) -> list[TimelineEvent]:
        """Collect Sentry issues as timeline events."""
        issues = self.get_project_issues(
            project_slug=service,
            query="is:unresolved",
            time_range=time_range,
            limit=20,
        )

        return [
            TimelineEvent(
                timestamp=issue.get("lastSeen", ""),
                message=f"Sentry: {issue.get('title', '')} ({issue.get('count', 0)}x)",
                source=EventSource.SENTRY,
                service=service,
                level=_parse_level(issue.get("level", "error")),
                metadata={
                    "issue_id": issue.get("id"),
                    "culprit": issue.get("culprit", ""),
                },
            )
            for issue in issues
        ]

    # ---- Sentry-specific methods ----

    def get_project_issues(
        self,
        project_slug: str,
        query: str = "is:unresolved",
        time_range: str = "2h",
        env: str | None = None,
        limit: int = 25,
    ) -> list[dict]:
        """Get issues for a Sentry project.

        Args:
            project_slug: Sentry project slug (often matches service name)
            query: Sentry search query
            time_range: Relative time filter (e.g. "2h", "24h")
            env: Environment filter
            limit: Max results
        """
        params: dict = {
            "query": query,
            "sort": "freq",
            "limit": str(min(limit, 100)),
            "statsPeriod": self._to_stats_period(time_range),
        }
        if env:
            params["environment"] = env

        path = f"/projects/{self.org}/{project_slug}/issues/"
        return self._request("GET", path, params=params)

    def get_issue_events(self, issue_id: str, limit: int = 10) -> list[dict]:
        """Get recent events (occurrences) for a specific issue."""
        path = f"/issues/{issue_id}/events/"
        params = {"limit": str(limit)}
        return self._request("GET", path, params=params)

    def _to_stats_period(self, time_range: str) -> str:
        """Convert our time range format to Sentry's statsPeriod format."""
        mapping = {
            "15m": "15m",
            "30m": "30m",
            "1h": "1h",
            "2h": "2h",
            "4h": "4h",
            "6h": "6h",
            "12h": "12h",
            "24h": "24h",
            "1d": "24h",
            "2d": "48h",
            "7d": "7d",
        }
        return mapping.get(time_range, time_range)
