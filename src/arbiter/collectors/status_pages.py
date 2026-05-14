"""Public status page collectors — GCP and Cloudflare incident feeds."""

from __future__ import annotations

import contextlib
import logging
from datetime import UTC, datetime, timedelta

import httpx

logger = logging.getLogger(__name__)

_TIME_RANGE_HOURS = {
    "15m": 0.25,
    "30m": 0.5,
    "1h": 1,
    "2h": 2,
    "4h": 4,
    "6h": 6,
    "12h": 12,
    "24h": 24,
    "7d": 168,
}


def _parse_time_window(
    time_range: str,
    from_time: str | None,
    to_time: str | None,
) -> tuple[datetime, datetime]:
    """Return (start, end) UTC-aware datetimes from time_range or absolute times."""
    if from_time:
        start = datetime.fromisoformat(from_time.replace("Z", "+00:00"))
        if start.tzinfo is None:
            start = start.replace(tzinfo=UTC)
    else:
        hours = _TIME_RANGE_HOURS.get(time_range, 2)
        start = datetime.now(UTC) - timedelta(hours=hours)

    if to_time and to_time != "now":
        end = datetime.fromisoformat(to_time.replace("Z", "+00:00"))
        if end.tzinfo is None:
            end = end.replace(tzinfo=UTC)
    else:
        end = datetime.now(UTC)
    return start, end


def check_gcp_status(
    time_range: str = "6h",
    from_time: str | None = None,
    to_time: str | None = None,
) -> list[dict]:
    """Check GCP status page for active incidents in the time window."""
    window_start, window_end = _parse_time_window(time_range, from_time, to_time)

    try:
        with httpx.Client(timeout=15) as client:
            resp = client.get("https://status.cloud.google.com/incidents.json")
            resp.raise_for_status()
            incidents = resp.json()
    except Exception as e:
        logger.warning("GCP status page fetch failed: %s", e)
        return []

    results = []
    for inc in incidents[:100]:
        begin = inc.get("begin")
        end = inc.get("end")
        if not begin:
            continue
        try:
            inc_start = datetime.fromisoformat(begin.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue

        inc_end = None
        if end:
            with contextlib.suppress(ValueError, TypeError):
                inc_end = datetime.fromisoformat(end.replace("Z", "+00:00"))

        if inc_end and inc_end < window_start:
            continue
        if inc_start > window_end:
            continue

        affected = inc.get("most_recent_update", {}).get("affected_products", [])
        product_names = [p.get("title", "") for p in affected]

        results.append(
            {
                "source": "gcp",
                "id": inc.get("id", ""),
                "title": inc.get("external_desc", ""),
                "severity": inc.get("severity", ""),
                "start": begin,
                "end": end or "ongoing",
                "affected_products": product_names,
                "status": inc.get("most_recent_update", {}).get("status", ""),
            }
        )

    return results


def check_cloudflare_status(
    time_range: str = "6h",
    from_time: str | None = None,
    to_time: str | None = None,
) -> list[dict]:
    """Check Cloudflare status page for active incidents in the time window."""
    window_start, window_end = _parse_time_window(time_range, from_time, to_time)

    try:
        with httpx.Client(timeout=15) as client:
            resp = client.get("https://www.cloudflarestatus.com/api/v2/incidents.json")
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.warning("Cloudflare status page fetch failed: %s", e)
        return []

    results = []
    for inc in data.get("incidents", [])[:50]:
        created = inc.get("created_at", "")
        if not created:
            continue
        try:
            inc_start = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue

        resolved = inc.get("resolved_at")
        inc_end = None
        if resolved:
            with contextlib.suppress(ValueError, TypeError):
                inc_end = datetime.fromisoformat(resolved.replace("Z", "+00:00"))

        if inc_end and inc_end < window_start:
            continue
        if inc_start > window_end:
            continue

        components = [c.get("name", "") for c in inc.get("components", [])]

        results.append(
            {
                "source": "cloudflare",
                "id": inc.get("id", ""),
                "title": inc.get("name", ""),
                "impact": inc.get("impact", ""),
                "start": created,
                "end": resolved or "ongoing",
                "affected_components": components,
                "status": inc.get("status", ""),
            }
        )

    return results
