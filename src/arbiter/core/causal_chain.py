"""Causal chain detection — traces error propagation across services and time."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from dateutil import parser as dateutil_parser

from arbiter.core.models import (
    CausalChain,
    CausalChainConfig,
    ChainLink,
    EventType,
)

logger = logging.getLogger(__name__)

_TRIGGER_TYPES = {EventType.DEPLOY, EventType.INFRASTRUCTURE_CHANGE, EventType.WORKLOAD_BURST}

DEFAULT_CONFIG = CausalChainConfig()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def detect_causal_chain(
    collected_data: dict,
    graph: dict | None = None,
    config: CausalChainConfig | None = None,
) -> CausalChain:
    """Detect causal chain from collected incident data.

    Extracts timestamped events from all sources, identifies the root cause
    (earliest error on the most upstream service), and builds a linear chain
    showing how the incident propagated.
    """
    cfg = config or DEFAULT_CONFIG

    # Step 1: Extract all events
    events = _extract_all_events(collected_data)
    if not events:
        return CausalChain()

    # Step 2: Parse timestamps and sort
    for e in events:
        e.metadata["_parsed_ts"] = _parse_timestamp(e.timestamp)
    events = [e for e in events if e.metadata.get("_parsed_ts") is not None]
    events.sort(key=lambda e: e.metadata["_parsed_ts"])

    if not events:
        return CausalChain()

    # Step 3: Deduplicate
    events = _deduplicate_events(events)

    # Separate triggers (deploys, infra changes) from errors
    error_events = [e for e in events if e.event_type not in _TRIGGER_TYPES]
    if not error_events:
        return CausalChain()

    # Step 4: Find potential triggers
    first_error_ts = error_events[0].metadata["_parsed_ts"]
    triggers = _find_triggers(events, first_error_ts, cfg)

    # Step 5: Find root cause
    root_idx = _find_root_cause(error_events, graph)
    if root_idx is None:
        root_idx = 0

    # Step 6: Build linear chain
    chain_links = _build_chain(error_events, root_idx, graph, cfg)

    # Step 7: Compute metadata
    # Clean internal metadata
    for link in chain_links:
        link.metadata.pop("_parsed_ts", None)
    for t in triggers:
        t.metadata.pop("_parsed_ts", None)

    # Detection delay
    detection_delay = None
    alert_links = [l for l in chain_links if l.event_type == EventType.ALERT]
    error_links = [
        l
        for l in chain_links
        if l.event_type in (EventType.DB_ERROR, EventType.HTTP_ERROR, EventType.SERVICE_ERROR)
    ]
    if alert_links and error_links:
        first_error = _parse_timestamp(error_links[0].timestamp)
        first_alert = _parse_timestamp(alert_links[0].timestamp)
        if first_error and first_alert:
            detection_delay = (first_alert - first_error).total_seconds()

    # Summary
    summary = _build_summary(chain_links, triggers, detection_delay)

    return CausalChain(
        links=chain_links,
        root_cause_index=0 if chain_links else None,
        detection_delay_seconds=detection_delay,
        potential_triggers=triggers,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# Event extraction
# ---------------------------------------------------------------------------


def _extract_all_events(data: dict) -> list[ChainLink]:
    """Normalize all data sources into ChainLink candidates."""
    events: list[ChainLink] = []
    events.extend(_extract_deploy_events(data))
    events.extend(_extract_gke_operation_events(data))
    events.extend(_extract_cloudsql_operation_events(data))
    events.extend(_extract_db_error_events(data))
    events.extend(_extract_http_error_events(data))
    events.extend(_extract_log_error_events(data))
    events.extend(_extract_alert_events(data))
    events.extend(_extract_workload_burst_events(data))
    return events


def _extract_deploy_events(data: dict) -> list[ChainLink]:
    """Extract deploy events from github_deploys."""
    events = []
    deploys = data.get("github_deploys", {})
    for pr in deploys.get("pre_incident_deploys", []):
        merged_at = pr.get("merged_at", "")
        if not merged_at:
            continue
        events.append(
            ChainLink(
                timestamp=merged_at,
                event_type=EventType.DEPLOY,
                service=(
                    pr.get("repository", {}).get("fullName", "")
                    if isinstance(pr.get("repository"), dict)
                    else ""
                ),
                description=f"PR #{pr.get('number', '?')} merged: {pr.get('title', '')}",
                evidence=[pr.get("url", "")],
                metadata={
                    "pr_number": pr.get("number"),
                    "hours_before": pr.get("hours_before_incident"),
                },
            )
        )

    # Workflow deploys (tag-based)
    for run in data.get("github_workflow_deploys", []):
        created_at = run.get("created_at", "")
        if not created_at:
            continue
        tag = run.get("tag", "")
        workflow = run.get("workflow", "")
        desc_parts = [f"Workflow '{workflow}'" if workflow else "Workflow run"]
        if tag:
            desc_parts.append(f"tag {tag}")
        desc_parts.append(f"({run.get('conclusion', 'unknown')})")
        events.append(
            ChainLink(
                timestamp=created_at,
                event_type=EventType.DEPLOY,
                service="",
                description=" ".join(desc_parts),
                evidence=[run.get("url", "")],
                metadata={"tag": tag, "sha": run.get("sha", ""), "workflow": workflow},
            )
        )

    return events


def _extract_gke_operation_events(data: dict) -> list[ChainLink]:
    """Extract GKE operations as infrastructure change events."""
    events = []
    for op in data.get("gke_operations", []):
        start = op.get("start_time", "")
        if not start:
            continue
        op_type = op.get("operation_type", "")
        cluster = op.get("cluster", "")
        detail = op.get("detail", "")
        desc = f"GKE {op_type} on {cluster}" if cluster else f"GKE {op_type}"
        events.append(
            ChainLink(
                timestamp=start,
                event_type=EventType.INFRASTRUCTURE_CHANGE,
                service="gke",
                description=desc,
                evidence=[detail] if detail else [],
                metadata={"gke_operation": op},
            )
        )
    return events


def _extract_cloudsql_operation_events(data: dict) -> list[ChainLink]:
    """Extract CloudSQL operations (maintenance, failover, restart) as infrastructure changes."""
    events = []
    for op in data.get("cloudsql_operations", []):
        start = op.get("start_time", "")
        if not start:
            continue
        op_type = op.get("operation_type", "")
        instance = op.get("instance", "")
        desc = f"CloudSQL {op_type} on {instance}" if instance else f"CloudSQL {op_type}"
        events.append(
            ChainLink(
                timestamp=start,
                event_type=EventType.INFRASTRUCTURE_CHANGE,
                service="cloudsql",
                description=desc,
                evidence=[f"status: {op.get('status', '')}"],
                metadata={"cloudsql_operation": op},
            )
        )
    return events


def _extract_db_error_events(data: dict) -> list[ChainLink]:
    """Extract DB error events from datadog_db_errors + upstream_db_errors."""
    events = []
    # Primary
    for entry in data.get("datadog_db_errors", []):
        ts = entry.get("timestamp", "")
        msg = entry.get("message", "")
        if ts and msg:
            events.append(
                ChainLink(
                    timestamp=ts,
                    event_type=EventType.DB_ERROR,
                    service=entry.get("service", ""),
                    description=msg.split("\n")[0][:200],
                    evidence=[msg[:500]],
                )
            )
    # Upstream
    for svc, errors in data.get("upstream_db_errors", {}).items():
        for entry in errors if isinstance(errors, list) else []:
            ts = entry.get("timestamp", "")
            msg = entry.get("message", "")
            if ts and msg:
                events.append(
                    ChainLink(
                        timestamp=ts,
                        event_type=EventType.DB_ERROR,
                        service=entry.get("service", svc),
                        description=msg.split("\n")[0][:200],
                        evidence=[msg[:500]],
                    )
                )
    return events


def _extract_http_error_events(data: dict) -> list[ChainLink]:
    """Extract HTTP error events from datadog_traces + upstream_traces (500+)."""
    events = []
    # Primary
    for trace in data.get("datadog_traces", []):
        status = str(trace.get("status_code", ""))
        if not status.startswith("5"):
            continue
        events.append(
            ChainLink(
                timestamp=trace.get("timestamp", ""),
                event_type=EventType.HTTP_ERROR,
                service=trace.get("service", ""),
                description=f"{status} on {trace.get('http_path', trace.get('endpoint', ''))}",
                evidence=[
                    f"error_type: {trace.get('error_type', '')}",
                    f"duration: {trace.get('duration_ms', '')}ms",
                ],
                metadata={
                    "endpoint": trace.get("endpoint", ""),
                    "http_path": trace.get("http_path", ""),
                    "duration_ms": trace.get("duration_ms"),
                },
            )
        )
    # Upstream
    for svc, traces in data.get("upstream_traces", {}).items():
        for trace in traces if isinstance(traces, list) else []:
            status = str(trace.get("status_code", ""))
            if not status.startswith("5"):
                continue
            events.append(
                ChainLink(
                    timestamp=trace.get("timestamp", ""),
                    event_type=EventType.HTTP_ERROR,
                    service=trace.get("service", svc),
                    description=f"{status} on {trace.get('http_path', trace.get('endpoint', ''))}",
                    evidence=[
                        f"error_type: {trace.get('error_type', '')}",
                        f"duration: {trace.get('duration_ms', '')}ms",
                    ],
                    metadata={
                        "endpoint": trace.get("endpoint", ""),
                        "http_path": trace.get("http_path", ""),
                        "duration_ms": trace.get("duration_ms"),
                    },
                )
            )
    return events


def _extract_log_error_events(data: dict) -> list[ChainLink]:
    """Extract service error events from datadog_logs (ERROR/CRITICAL only)."""
    events = []
    for log in data.get("datadog_logs", []):
        if log.get("level") not in ("ERROR", "CRITICAL"):
            continue
        ts = log.get("timestamp", "")
        msg = log.get("message", "")
        if ts and msg:
            events.append(
                ChainLink(
                    timestamp=ts,
                    event_type=EventType.SERVICE_ERROR,
                    service=log.get("service", ""),
                    description=msg.split("\n")[0][:200],
                    evidence=[msg[:500]],
                )
            )
    return events


def _extract_alert_events(data: dict) -> list[ChainLink]:
    """Extract alert events from opsgenie_alerts."""
    events = []
    for alert in data.get("opsgenie_alerts", []):
        ts = alert.get("created_at", "")
        if not ts:
            continue
        events.append(
            ChainLink(
                timestamp=ts,
                event_type=EventType.ALERT,
                service=alert.get("service", ""),
                description=f"{alert.get('severity', 'P?')} alert: {alert.get('title', alert.get('message', ''))}",
                evidence=[alert.get("message", "")[:500]],
                metadata={"alert_id": alert.get("id", ""), "severity": alert.get("severity", "")},
            )
        )
    return events


def _extract_workload_burst_events(data: dict) -> list[ChainLink]:
    """Extract message queue burst events from volume metrics."""
    vol = data.get("volume_metrics", {})
    queue = vol.get("queue", {})
    if not queue or not queue.get("volume_anomaly"):
        return []
    current = queue.get("current_backlog", 0)
    baseline = queue.get("baseline_backlog")
    topic = queue.get("topic", "unknown")
    ratio = queue.get("volume_change_ratio")

    desc_parts = [f"Pub/Sub backlog burst on {topic}: {current:.0f} messages"]
    if baseline is not None:
        desc_parts.append(f"(baseline: {baseline:.0f})")
    if ratio is not None:
        desc_parts.append(f"({ratio}x)")

    time_range = data.get("time_range", {})
    ts = time_range.get("from", "")

    return [
        ChainLink(
            timestamp=ts,
            event_type=EventType.WORKLOAD_BURST,
            service=data.get("service_name", ""),
            description=" ".join(desc_parts),
            evidence=[f"backlog: {current}, baseline: {baseline}, ratio: {ratio}"],
            metadata={"topic": topic, "backlog": current, "baseline": baseline},
        )
    ]


# ---------------------------------------------------------------------------
# Timestamp handling
# ---------------------------------------------------------------------------


def _parse_timestamp(ts: str) -> datetime | None:
    """Safely parse an ISO 8601 timestamp, always returning UTC-aware."""
    if not ts:
        return None
    try:
        dt = dateutil_parser.isoparse(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def _deduplicate_events(events: list[ChainLink]) -> list[ChainLink]:
    """Remove near-duplicate events (same service + type within 1 second).

    Trigger events (deploys, infrastructure changes) get a wider window
    (60s) because multiple sources can report the same event.
    """
    if not events:
        return []

    unique: list[ChainLink] = [events[0]]
    for e in events[1:]:
        is_dup = False
        for prev in unique:
            if e.event_type != prev.event_type:
                continue
            ts_e = e.metadata.get("_parsed_ts")
            ts_p = prev.metadata.get("_parsed_ts")
            if not ts_e or not ts_p:
                continue

            delta = abs((ts_e - ts_p).total_seconds())

            if e.event_type in _TRIGGER_TYPES and delta < 60:
                is_dup = True
                break

            if (
                e.service == prev.service
                and e.description[:60] == prev.description[:60]
                and delta < 1.0
            ):
                is_dup = True
                break

        if not is_dup:
            unique.append(e)
    return unique


# ---------------------------------------------------------------------------
# Trigger detection
# ---------------------------------------------------------------------------


def _find_triggers(
    events: list[ChainLink],
    first_error_ts: datetime,
    config: CausalChainConfig,
) -> list[ChainLink]:
    """Find trigger events (deploys, infra changes) within threshold before first error."""
    triggers = []
    threshold = timedelta(hours=config.deploy_to_error_hours)

    for e in events:
        if e.event_type not in _TRIGGER_TYPES:
            continue
        deploy_ts = e.metadata.get("_parsed_ts")
        if not deploy_ts:
            continue
        delta = first_error_ts - deploy_ts
        if timedelta(0) <= delta <= threshold:
            hours_before = delta.total_seconds() / 3600
            e.confidence = round(max(0.1, 1.0 - (hours_before / config.deploy_to_error_hours)), 2)
            e.delta_seconds = -delta.total_seconds()
            e.delta_human = f"{format_delta(delta.total_seconds())} before first error"
            triggers.append(e)

    triggers.sort(key=lambda t: -t.confidence)
    return triggers


# ---------------------------------------------------------------------------
# Root cause identification
# ---------------------------------------------------------------------------


def _find_root_cause(events: list[ChainLink], graph: dict | None) -> int | None:
    """Identify root cause: earliest error on most upstream service.

    Uses the dependency graph to find which erroring service is upstream.
    If service A depends_on service B, and both have errors, B is upstream.
    Among equally-upstream services, the earliest error wins.
    DB_ERROR is prioritized over HTTP_ERROR.
    """
    error_types = (EventType.DB_ERROR, EventType.HTTP_ERROR, EventType.SERVICE_ERROR)
    error_events = [(i, e) for i, e in enumerate(events) if e.event_type in error_types]

    if not error_events:
        return None

    if not graph:
        return error_events[0][0]

    from arbiter.context.service_map import get_transitive_dependencies

    error_services = {e.service for _, e in error_events}

    # Find services that are NOT depended on by any other erroring service
    upstream_candidates = set(error_services)
    for svc in error_services:
        transitive = get_transitive_dependencies(svc, graph, max_depth=3, direction="upstream")
        upstream_deps = {d["service"] for d in transitive} & error_services
        if upstream_deps:
            upstream_candidates.discard(svc)

    # If all were discarded (circular), use all error services
    if not upstream_candidates:
        upstream_candidates = error_services

    # Among upstream candidates, prioritize DB_ERROR, then earliest timestamp
    best_idx = None
    best_priority = 99
    for idx, event in error_events:
        if event.service not in upstream_candidates:
            continue
        priority = 0 if event.event_type == EventType.DB_ERROR else 1
        if best_idx is None or priority < best_priority:
            best_idx = idx
            best_priority = priority
        elif priority == best_priority and best_idx is not None:
            pass

    return best_idx if best_idx is not None else error_events[0][0]


# ---------------------------------------------------------------------------
# Chain building
# ---------------------------------------------------------------------------


def _build_chain(
    events: list[ChainLink],
    root_cause_idx: int,
    graph: dict | None,
    config: CausalChainConfig,
) -> list[ChainLink]:
    """Build linear chain from root cause through downstream effects."""
    if not events or root_cause_idx >= len(events):
        return []

    chain = [events[root_cause_idx]]
    used = {root_cause_idx}

    # Walk forward from root cause
    for i, event in enumerate(events):
        if i in used:
            continue

        # Try to link to the last event in the chain
        last = chain[-1]
        if _is_causal_link(last, event, graph, config):
            # Compute delta
            ts_last = _parse_timestamp(last.timestamp)
            ts_event = _parse_timestamp(event.timestamp)
            if ts_last and ts_event:
                delta = (ts_event - ts_last).total_seconds()
                event.delta_seconds = delta
                event.delta_human = f"{format_delta(abs(delta))} later"

            chain.append(event)
            used.add(i)

    return chain


def _is_causal_link(
    cause: ChainLink,
    effect: ChainLink,
    graph: dict | None,
    config: CausalChainConfig,
) -> bool:
    """Check if two events have a plausible causal relationship."""
    ts_cause = cause.metadata.get("_parsed_ts") or _parse_timestamp(cause.timestamp)
    ts_effect = effect.metadata.get("_parsed_ts") or _parse_timestamp(effect.timestamp)

    if not ts_cause or not ts_effect:
        return False

    delta = (ts_effect - ts_cause).total_seconds()
    if delta < 0:
        return False

    # Alert always links to any prior error
    if effect.event_type == EventType.ALERT:
        return True

    # Infrastructure change → DB error (CloudSQL maintenance, GKE operations)
    if cause.event_type == EventType.INFRASTRUCTURE_CHANGE and effect.event_type in (
        EventType.DB_ERROR,
        EventType.HTTP_ERROR,
        EventType.SERVICE_ERROR,
    ):
        return delta <= config.infra_change_to_error_seconds

    # Workload burst → any error (message burst overwhelming consumer)
    if cause.event_type == EventType.WORKLOAD_BURST and effect.event_type in (
        EventType.DB_ERROR,
        EventType.HTTP_ERROR,
        EventType.SERVICE_ERROR,
        EventType.ALERT,
    ):
        return delta <= config.infra_change_to_error_seconds

    # Same service escalation
    if cause.service == effect.service:
        return delta <= config.same_service_seconds

    # Cross-service: check dependency graph (transitive)
    if graph:
        from arbiter.context.service_map import get_transitive_dependencies

        transitive_down = get_transitive_dependencies(
            cause.service, graph, max_depth=3, direction="downstream"
        )
        downstream = {d["service"] for d in transitive_down}

        # DB_ERROR on upstream → HTTP_ERROR on downstream
        if (
            cause.event_type == EventType.DB_ERROR
            and effect.event_type in (EventType.HTTP_ERROR, EventType.SERVICE_ERROR)
            and effect.service in downstream
        ):
            return delta <= config.db_to_http_seconds

        # HTTP_ERROR on upstream → SERVICE_ERROR on downstream
        if (
            cause.event_type == EventType.HTTP_ERROR
            and effect.event_type in (EventType.HTTP_ERROR, EventType.SERVICE_ERROR)
            and effect.service in downstream
        ):
            return delta <= config.cross_service_seconds

    # Fallback: same type progression on any service within cross-service threshold
    return (
        delta <= config.cross_service_seconds
        and cause.event_type in (EventType.DB_ERROR, EventType.HTTP_ERROR)
        and effect.event_type in (EventType.HTTP_ERROR, EventType.SERVICE_ERROR)
    )


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def _build_summary(
    links: list[ChainLink],
    triggers: list[ChainLink],
    detection_delay: float | None,
) -> str:
    """Auto-generate a one-line summary of the causal chain."""
    if not links:
        return ""

    parts = []

    # Root cause
    root = links[0]
    parts.append(f"{root.description[:80]} on {root.service}")

    # Propagation
    services_affected = list(dict.fromkeys(l.service for l in links if l.service != root.service))
    if services_affected:
        parts.append(f"propagated to {', '.join(services_affected[:3])}")

    # Detection delay
    if detection_delay is not None:
        parts.append(f"{format_delta(detection_delay)} detection delay")

    # Trigger
    if triggers:
        t = triggers[0]
        if t.event_type == EventType.WORKLOAD_BURST:
            parts.append(f"potential trigger: {t.description[:80]}")
        elif t.metadata.get("pr_number"):
            parts.append(f"potential trigger: PR #{t.metadata['pr_number']}")
        else:
            parts.append(f"potential trigger: {t.description[:80]}")

    return " — ".join(parts)


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def format_delta(seconds: float) -> str:
    """Format seconds as human-readable delta. 5.0 -> '5s', 8340.0 -> '2h19m'."""
    if seconds < 0:
        seconds = abs(seconds)

    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m{secs}s" if secs else f"{minutes}m"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h{minutes}m" if minutes else f"{hours}h"


def format_chain_text(chain: CausalChain) -> str:
    """Render chain as indented arrow text for reports."""
    if not chain.links:
        return "No causal chain detected."

    lines = []

    # Triggers
    for t in chain.potential_triggers:
        ts = _format_short_ts(t.timestamp)
        lines.append(f"{t.description} at {ts} ({t.delta_human})")

    # Chain links
    for i, link in enumerate(chain.links):
        ts = _format_short_ts(link.timestamp)
        indent = "  " * (i + len(chain.potential_triggers))
        arrow = "→ " if i > 0 or chain.potential_triggers else ""
        tag = " [ROOT CAUSE]" if i == chain.root_cause_index else ""
        delta = f" ({link.delta_human})" if link.delta_human else ""

        lines.append(f"{indent}{arrow}{link.description} at {ts}{tag}{delta}")

    # Detection delay
    if chain.detection_delay_seconds is not None:
        lines.append(f"\nDetection delay: {format_delta(chain.detection_delay_seconds)}")

    return "\n".join(lines)


def _format_short_ts(ts: str) -> str:
    """Format timestamp as HH:MM:SS UTC."""
    parsed = _parse_timestamp(ts)
    if parsed:
        return parsed.strftime("%H:%M:%S UTC")
    return ts[:19]


def chain_to_dict(chain: CausalChain) -> dict:
    """Serialize CausalChain to JSON-safe dict."""
    return {
        "links": [
            {
                "timestamp": l.timestamp,
                "event_type": l.event_type.value,
                "service": l.service,
                "description": l.description,
                "evidence": l.evidence,
                "delta_seconds": l.delta_seconds,
                "delta_human": l.delta_human,
                "confidence": l.confidence,
            }
            for l in chain.links
        ],
        "root_cause_index": chain.root_cause_index,
        "detection_delay_seconds": chain.detection_delay_seconds,
        "detection_delay_human": (
            format_delta(chain.detection_delay_seconds) if chain.detection_delay_seconds else None
        ),
        "potential_triggers": [
            {
                "timestamp": t.timestamp,
                "description": t.description,
                "confidence": t.confidence,
                "delta_human": t.delta_human,
            }
            for t in chain.potential_triggers
        ],
        "summary": chain.summary,
        "chain_text": format_chain_text(chain),
    }
