"""Base collector interface — all data source collectors implement this."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from arbiter.core.models import EventSource, LogEntry, TimelineEvent

logger = logging.getLogger(__name__)


class Collector(ABC):
    """Abstract base class for incident data collectors.

    Each collector knows how to pull data from one observability
    platform and produce standardized TimelineEvent/LogEntry objects.
    """

    @property
    @abstractmethod
    def source(self) -> EventSource:
        """The event source this collector provides."""

    @abstractmethod
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
        """Collect log entries for a service in a time window."""

    @abstractmethod
    def collect_events(
        self,
        service: str,
        time_range: str = "2h",
        from_time: str | None = None,
        to_time: str | None = None,
    ) -> list[TimelineEvent]:
        """Collect timeline events (alerts, deploys, state changes)."""

    def is_configured(self) -> bool:
        """Check if this collector has the credentials/config it needs."""
        return True

    def collect_logs_multi(
        self,
        services: list[str],
        time_range: str = "2h",
        env: str = "production",
        from_time: str | None = None,
        to_time: str | None = None,
        limit_per_service: int = 20,
    ) -> dict[str, list[LogEntry]]:
        """Collect logs across multiple services. Default: sequential."""
        results = {}
        for svc in services:
            try:
                logs = self.collect_logs(
                    service=svc,
                    time_range=time_range,
                    env=env,
                    from_time=from_time,
                    to_time=to_time,
                    limit=limit_per_service,
                )
                if logs:
                    results[svc] = logs
            except Exception as e:
                logger.warning("Failed to collect logs for %s: %s", svc, e)
        return results
