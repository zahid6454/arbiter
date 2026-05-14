"""Confidence scoring for incident analyses.

Uses an evidence-strength model: the score measures how well the data you
found supports the conclusion, not how many sources were checked.  Unchecked
sources are excluded from scoring (neutral), not penalized.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from arbiter.core.models import (
    ConfidenceLevel,
    ConfidenceScore,
    DataCompleteness,
    DataSourceStatus,
)

# Retention windows (days) for distinguishing EMPTY vs EXPIRED
_LOG_RETENTION_DAYS = 3
_TRACE_RETENTION_DAYS = 15

# Source weights — relative importance when a source IS checked.
_SOURCE_WEIGHTS: dict[str, int] = {
    "logs": 15,
    "traces": 15,
    "db_errors": 10,
    "upstream_traces": 8,
    "upstream_db_errors": 8,
    "cross_service_logs": 8,
    "alerts": 8,
    "github_deploys": 6,
    "github_workflow_deploys": 4,
    "git_context": 6,
    "source_code": 6,
    "causal_chain": 6,
    "gke_operations": 8,
    "cloudsql_operations": 8,
    "queue_metrics": 10,
}

# Status multipliers — ``None`` means "exclude from scoring entirely".
_STATUS_MULTIPLIERS: dict[DataSourceStatus, float | None] = {
    DataSourceStatus.AVAILABLE: 1.0,
    DataSourceStatus.EMPTY: 0.7,
    DataSourceStatus.EXPIRED: 0.2,
    DataSourceStatus.UNAVAILABLE: 0.0,
    DataSourceStatus.NOT_CHECKED: None,
    DataSourceStatus.NOT_RELEVANT: None,
}

# Mapping from collected-data JSON keys to DataCompleteness fields
_KEY_MAP: dict[str, str] = {
    "datadog_logs": "logs",
    "datadog_traces": "traces",
    "datadog_db_errors": "db_errors",
    "upstream_traces": "upstream_traces",
    "upstream_db_errors": "upstream_db_errors",
    "cross_service_logs": "cross_service_logs",
    "opsgenie_alerts": "alerts",
    "github_deploys": "github_deploys",
    "github_workflow_deploys": "github_workflow_deploys",
    "git_context": "git_context",
    "source_code": "source_code",
    "causal_chain": "causal_chain",
    "gke_operations": "gke_operations",
    "cloudsql_operations": "cloudsql_operations",
}

# Keys that use trace-level retention (longer) rather than log-level
_TRACE_RETENTION_KEYS = {"datadog_traces", "upstream_traces"}

# Infrastructure-based relevance rules.
_FIELD_RELEVANCE_RULES: dict[str, Callable[[dict], bool]] = {
    "db_errors": lambda infra: infra.get("database", "none") not in ("none", ""),
    "upstream_db_errors": lambda infra: infra.get("database", "none") not in ("none", ""),
    "github_workflow_deploys": lambda infra: infra.get("deploy_method") == "tag",
    "gke_operations": lambda infra: infra.get("platform") == "gke",
    "cloudsql_operations": lambda infra: infra.get("database") == "postgresql",
    "queue_metrics": lambda infra: bool(infra.get("message_queues")),
}


def _determine_relevance(
    field_name: str,
    infrastructure_profile: dict | None,
) -> bool:
    """Return True if *field_name* is relevant given the infrastructure profile."""
    if not infrastructure_profile:
        return True
    rule = _FIELD_RELEVANCE_RULES.get(field_name)
    if rule is None:
        return True
    return rule(infrastructure_profile)


def _days_since(date_str: str) -> float:
    """Return days between *date_str* (ISO 8601 date or datetime) and now."""
    if not date_str:
        return 0.0
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return (datetime.now(UTC) - dt).total_seconds() / 86400
    except (ValueError, TypeError):
        return 0.0


def _is_non_empty(value) -> bool:
    """Check whether a collected-data value contains actual data."""
    if value is None:
        return False
    if isinstance(value, (list, dict)):
        return len(value) > 0
    if isinstance(value, str):
        return bool(value.strip())
    return bool(value)


def _classify_source(
    key: str,
    collected: dict,
    days_old: float,
) -> DataSourceStatus:
    """Determine the status of a single data source."""
    base = key.split("_")[0]
    error_key = f"{base}_error"
    if collected.get(error_key):
        return DataSourceStatus.UNAVAILABLE

    if key == "opsgenie_alerts" and key not in collected:
        if "alert" in collected and _is_non_empty(collected["alert"]):
            return DataSourceStatus.AVAILABLE
        return DataSourceStatus.NOT_CHECKED

    if key not in collected:
        return DataSourceStatus.NOT_CHECKED

    value = collected[key]

    if key == "github_deploys" and isinstance(value, dict):
        pre = value.get("pre_incident_deploys", [])
        during = value.get("during_incident_deploys", [])
        if pre or during:
            return DataSourceStatus.AVAILABLE
        return DataSourceStatus.EMPTY

    if key == "git_context" and isinstance(value, dict):
        if value.get("recent_commits") or value.get("recent_tags"):
            return DataSourceStatus.AVAILABLE
        return DataSourceStatus.EMPTY

    if key == "causal_chain" and isinstance(value, dict):
        if value.get("links"):
            return DataSourceStatus.AVAILABLE
        return DataSourceStatus.EMPTY

    if _is_non_empty(value):
        return DataSourceStatus.AVAILABLE

    retention_days = _TRACE_RETENTION_DAYS if key in _TRACE_RETENTION_KEYS else _LOG_RETENTION_DAYS
    if days_old > retention_days:
        return DataSourceStatus.EXPIRED

    return DataSourceStatus.EMPTY


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compute_data_completeness(
    collected_data: dict,
    incident_date: str = "",
    infrastructure_profile: dict | None = None,
) -> DataCompleteness:
    """Score evidence strength from a gathered incident context JSON."""
    if not incident_date:
        time_range = collected_data.get("time_range", {})
        incident_date = time_range.get("from", "")

    days_old = _days_since(incident_date)

    statuses: dict[str, DataSourceStatus] = {}
    for json_key, field_name in _KEY_MAP.items():
        statuses[field_name] = _classify_source(json_key, collected_data, days_old)

    # Custom: queue_metrics lives inside volume_metrics.queue
    vol = collected_data.get("volume_metrics")
    if vol is not None and isinstance(vol, dict):
        queue = vol.get("queue")
        if (
            queue is not None
            and isinstance(queue, dict)
            and queue.get("current_backlog") is not None
        ):
            statuses["queue_metrics"] = DataSourceStatus.AVAILABLE
        else:
            statuses["queue_metrics"] = DataSourceStatus.NOT_CHECKED
    else:
        statuses["queue_metrics"] = DataSourceStatus.NOT_CHECKED

    if infrastructure_profile:
        for field_name in statuses:
            if statuses[field_name] == DataSourceStatus.NOT_CHECKED and not _determine_relevance(
                field_name, infrastructure_profile
            ):
                statuses[field_name] = DataSourceStatus.NOT_RELEVANT

    # Evidence-strength scoring
    score = 0.0
    total_checked_weight = 0.0
    for field_name, weight in _SOURCE_WEIGHTS.items():
        status = statuses.get(field_name, DataSourceStatus.NOT_CHECKED)
        multiplier = _STATUS_MULTIPLIERS[status]
        if multiplier is None:
            continue
        total_checked_weight += weight
        score += weight * multiplier

    final_score = round(score / total_checked_weight * 100) if total_checked_weight > 0 else 0

    return DataCompleteness(
        logs=statuses.get("logs", DataSourceStatus.NOT_CHECKED),
        traces=statuses.get("traces", DataSourceStatus.NOT_CHECKED),
        db_errors=statuses.get("db_errors", DataSourceStatus.NOT_CHECKED),
        upstream_traces=statuses.get("upstream_traces", DataSourceStatus.NOT_CHECKED),
        upstream_db_errors=statuses.get("upstream_db_errors", DataSourceStatus.NOT_CHECKED),
        cross_service_logs=statuses.get("cross_service_logs", DataSourceStatus.NOT_CHECKED),
        alerts=statuses.get("alerts", DataSourceStatus.NOT_CHECKED),
        github_deploys=statuses.get("github_deploys", DataSourceStatus.NOT_CHECKED),
        github_workflow_deploys=statuses.get(
            "github_workflow_deploys", DataSourceStatus.NOT_CHECKED
        ),
        git_context=statuses.get("git_context", DataSourceStatus.NOT_CHECKED),
        source_code=statuses.get("source_code", DataSourceStatus.NOT_CHECKED),
        causal_chain=statuses.get("causal_chain", DataSourceStatus.NOT_CHECKED),
        gke_operations=statuses.get("gke_operations", DataSourceStatus.NOT_CHECKED),
        cloudsql_operations=statuses.get("cloudsql_operations", DataSourceStatus.NOT_CHECKED),
        queue_metrics=statuses.get("queue_metrics", DataSourceStatus.NOT_CHECKED),
        score=final_score,
    )


def compute_overall_score(
    data: DataCompleteness,
    root_cause: ConfidenceLevel,
) -> tuple[ConfidenceLevel, int]:
    """Combine evidence strength with root-cause assessment."""
    rc_weights = {
        ConfidenceLevel.HIGH: 100,
        ConfidenceLevel.MEDIUM: 60,
        ConfidenceLevel.LOW: 20,
    }
    rc_weight = rc_weights[root_cause]
    raw = data.score * 0.4 + rc_weight * 0.6
    score = round(raw)

    if root_cause == ConfidenceLevel.HIGH and data.score < 30:
        level = ConfidenceLevel.MEDIUM
        score = min(score, 69)
    elif (root_cause == ConfidenceLevel.HIGH and data.score >= 80) or score >= 70:
        level = ConfidenceLevel.HIGH
    elif score >= 40:
        level = ConfidenceLevel.MEDIUM
    else:
        level = ConfidenceLevel.LOW

    return level, score


def build_confidence_score(
    collected_data: dict | None = None,
    collected_data_path: str = "",
    incident_date: str = "",
    root_cause_confidence: str = "medium",
    verification_gaps: list[str] | None = None,
    evidence_notes: str = "",
    infrastructure_profile: dict | None = None,
) -> ConfidenceScore:
    """Build a full ConfidenceScore from available inputs."""
    if collected_data is None and collected_data_path:
        path = Path(collected_data_path)
        if path.exists():
            collected_data = json.loads(path.read_text())

    if infrastructure_profile is None and collected_data:
        infrastructure_profile = collected_data.get("infrastructure_profile")

    if collected_data:
        data_completeness = compute_data_completeness(
            collected_data, incident_date, infrastructure_profile
        )
    else:
        data_completeness = DataCompleteness()

    try:
        rc_level = ConfidenceLevel(root_cause_confidence.lower())
    except ValueError:
        rc_level = ConfidenceLevel.MEDIUM

    overall_level, overall_score = compute_overall_score(data_completeness, rc_level)

    return ConfidenceScore(
        overall_level=overall_level,
        overall_score=overall_score,
        data_completeness=data_completeness,
        root_cause_confidence=rc_level,
        verification_gaps=verification_gaps or [],
        evidence_notes=evidence_notes,
    )


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

_STATUS_LABELS: dict[DataSourceStatus, str] = {
    DataSourceStatus.AVAILABLE: "available",
    DataSourceStatus.EMPTY: "empty (queried, no data found)",
    DataSourceStatus.EXPIRED: "expired (beyond retention window)",
    DataSourceStatus.UNAVAILABLE: "unavailable (collector error)",
    DataSourceStatus.NOT_CHECKED: "not checked",
    DataSourceStatus.NOT_RELEVANT: "not relevant (service doesn't use this source)",
}

_FIELD_LABELS: dict[str, str] = {
    "logs": "Datadog Logs",
    "traces": "APM Traces",
    "db_errors": "Database Errors",
    "upstream_traces": "Upstream Traces",
    "upstream_db_errors": "Upstream DB Errors",
    "cross_service_logs": "Cross-Service Logs",
    "alerts": "OpsGenie Alerts",
    "github_deploys": "GitHub Deploys",
    "github_workflow_deploys": "GitHub Workflow Deploys",
    "git_context": "Git Context",
    "source_code": "Source Code",
    "causal_chain": "Causal Chain",
    "gke_operations": "GKE Operations",
    "cloudsql_operations": "CloudSQL Operations",
    "queue_metrics": "Message Queue Metrics",
}


def format_confidence_markdown(score: ConfidenceScore) -> str:
    """Render a ``## Confidence Assessment`` section as markdown."""
    lines = [
        "## Confidence Assessment",
        "",
        f"**Overall: {score.overall_level.value.upper()} ({score.overall_score}/100)**",
        "",
        "| Dimension | Rating |",
        "|-----------|--------|",
        f"| Root Cause Confidence | {score.root_cause_confidence.value.upper()} |",
        f"| Evidence Strength | {score.data_completeness.score}/100 |",
        "",
    ]

    dc = score.data_completeness

    evidence: list[str] = []
    not_investigated: list[str] = []
    excluded: list[str] = []
    for field_name, label in _FIELD_LABELS.items():
        status = getattr(dc, field_name, DataSourceStatus.NOT_CHECKED)
        status_text = _STATUS_LABELS.get(status, status.value)
        entry = f"- {label}: {status_text}"
        if status == DataSourceStatus.NOT_CHECKED:
            not_investigated.append(entry)
        elif status == DataSourceStatus.NOT_RELEVANT:
            excluded.append(entry)
        else:
            evidence.append(entry)

    if evidence:
        lines.append("**Evidence Sources:**")
        lines.append("")
        lines.extend(evidence)
        lines.append("")

    if not_investigated:
        lines.append("**Not Investigated:**")
        lines.append("")
        lines.extend(not_investigated)
        lines.append("")

    if excluded:
        lines.append("**Excluded (not relevant to service):**")
        lines.append("")
        lines.extend(excluded)
        lines.append("")

    if score.verification_gaps:
        lines.append("**Verification Gaps:**")
        lines.append("")
        for gap in score.verification_gaps:
            lines.append(f"- {gap}")

    if score.evidence_notes:
        lines.append("")
        lines.append(f"**Evidence Notes:** {score.evidence_notes}")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def confidence_to_dict(score: ConfidenceScore) -> dict:
    """Serialize a ConfidenceScore to a JSON-compatible dict."""
    data = asdict(score)
    data["overall_level"] = score.overall_level.value
    data["root_cause_confidence"] = score.root_cause_confidence.value
    dc = data["data_completeness"]
    for field_name in _FIELD_LABELS:
        if field_name in dc and hasattr(dc[field_name], "value"):
            dc[field_name] = dc[field_name].value
    return data


def dict_to_confidence(data: dict) -> ConfidenceScore:
    """Deserialize a dict back to a ConfidenceScore."""
    dc_data = data.get("data_completeness", {})
    dc_kwargs = {}
    for field_name in _FIELD_LABELS:
        raw = dc_data.get(field_name, "not_checked")
        try:
            dc_kwargs[field_name] = DataSourceStatus(raw)
        except ValueError:
            dc_kwargs[field_name] = DataSourceStatus.NOT_CHECKED
    dc_kwargs["score"] = dc_data.get("score", 0)
    dc = DataCompleteness(**dc_kwargs)

    try:
        overall_level = ConfidenceLevel(data.get("overall_level", "medium"))
    except ValueError:
        overall_level = ConfidenceLevel.MEDIUM

    try:
        rc_level = ConfidenceLevel(data.get("root_cause_confidence", "medium"))
    except ValueError:
        rc_level = ConfidenceLevel.MEDIUM

    return ConfidenceScore(
        overall_level=overall_level,
        overall_score=data.get("overall_score", 50),
        data_completeness=dc,
        root_cause_confidence=rc_level,
        verification_gaps=data.get("verification_gaps", []),
        evidence_notes=data.get("evidence_notes", ""),
    )
