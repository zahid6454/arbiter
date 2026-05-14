"""Arbiter MCP server — exposes incident analysis tools to Claude Code."""

from __future__ import annotations

import contextlib
import functools
import inspect
import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from arbiter.collectors.datadog import DatadogCollector
from arbiter.collectors.gcp import GCPCollector
from arbiter.collectors.git import GitCollector
from arbiter.collectors.github import GitHubCollector
from arbiter.collectors.manual import ManualCollector
from arbiter.collectors.opsgenie import OpsGenieCollector
from arbiter.collectors.sentry import SentryCollector
from arbiter.context.service_map import (
    detect_environment_from_text,
    get_jira_cloud_id,
    get_blast_radius,
    get_cloudsql_instance,
    get_datadog_service,
    get_dependencies,
    get_gcp_project,
    get_github_repo,
    get_gke_cluster_config,
    get_infrastructure_profile,
    get_jira_project,
    get_related_services,
    get_service_info,
    get_source_root,
    get_transitive_dependencies,
    list_services,
    load_service_graph,
    resolve_datadog_environment,
)
from arbiter.context.workspace import (
    is_marketplace_mode,
    resolve_incidents_root,
    resolve_output_root,
    resolve_workspace,
)
from arbiter.output.renderer import render_report, save_report

logger = logging.getLogger(__name__)

API_RATE_LIMIT_DELAY = 3  # seconds between Datadog API calls

mcp = FastMCP(
    "arbiter",
    instructions="MCP-powered incident analysis and report generation",
)

WORKSPACE_ROOT = resolve_workspace()
OUTPUT_ROOT = resolve_output_root()
INCIDENTS_ROOT = resolve_incidents_root()
GRAPH = load_service_graph()

try:
    from arbiter.enrichment import collect_enrichment, get_enrichment_hints, get_providers

    ENRICHMENT_PROVIDERS = get_providers(WORKSPACE_ROOT)
except Exception as e:
    logger.warning("Failed to initialize enrichment providers: %s", e)
    ENRICHMENT_PROVIDERS = []

# Background version check — marketplace only, non-blocking
if is_marketplace_mode():
    try:
        from arbiter.core.version_check import start_background_check

        start_background_check()
    except Exception:
        logger.debug("Failed to start background version check", exc_info=True)


@mcp.resource(
    "arbiter://claude-md",
    name="claude-md",
    description=(
        "CLAUDE.md — complete investigation protocol, report format, "
        "tool reference, common pitfalls, and service mappings."
    ),
    mime_type="text/markdown",
)
def get_claude_md() -> str:
    from arbiter.context.workspace import resolve_claude_md

    path = resolve_claude_md()
    if path is None:
        return "ERROR: CLAUDE.md not found."
    content = path.read_text(encoding="utf-8")

    if is_marketplace_mode():
        try:
            from arbiter.core.version_check import get_update_state

            state = get_update_state()
            if state and state.update_available:
                banner = (
                    f"> **Arbiter update available:** v{state.current_version} → "
                    f"v{state.latest_version}. Run `/update` to upgrade.\n\n"
                )
                content = banner + content
        except Exception:
            logger.debug("Failed to check update state for banner", exc_info=True)

    return content


# Marketplace knowledge base sync — lazy-initialized on first use
_INCIDENT_SYNC = None
_INCIDENT_SYNC_INIT = False


def _get_incident_sync():
    """Return the IncidentSync instance (marketplace mode only)."""
    global _INCIDENT_SYNC, _INCIDENT_SYNC_INIT
    if not _INCIDENT_SYNC_INIT:
        _INCIDENT_SYNC_INIT = True
        from arbiter.context.workspace import is_marketplace_mode

        if is_marketplace_mode():
            from arbiter.core.incident_sync import IncidentSync

            _INCIDENT_SYNC = IncidentSync(INCIDENTS_ROOT)
            logger.info("Marketplace mode — knowledge base sync enabled")
    return _INCIDENT_SYNC


_tool_calls: list[dict] = []

# In-memory sessions created by preflight but not yet persisted to disk.
# Entries are promoted to disk on the first _save_session call.
_pending_sessions: dict[str, tuple[Path, dict, float]] = {}
_pending_lock = threading.Lock()

_TRACKED_TOOLS: set[str] = {
    "fetch_datadog_traces",
    "fetch_trace_spans",
    "fetch_cross_service_errors",
    "fetch_database_errors",
    "fetch_datadog_logs",
    "fetch_gcp_logs",
    "fetch_sentry_issues",
    "analyze_datadog_logs",
    "aggregate_trace_data",
    "fetch_github_deploys",
    "fetch_github_pr",
    "fetch_gcp_audit_logs",
    "fetch_gke_operations",
    "fetch_cloudsql_operations",
    "fetch_opsgenie_alerts",
    "get_service_enrichment_data",
    "get_platform_context",
    "read_github_file",
    "fetch_rum_errors",
    "fetch_rum_performance",
}


def _track_tool_calls(func):
    """Decorator that records tool calls for the Investigation Effort report section."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        response = func(*args, **kwargs)
        if func.__name__ not in _TRACKED_TOOLS:
            return response
        sig = inspect.signature(func)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        detail_level = bound.arguments.get("detail_level", "full")
        entry: dict = {
            "tool": func.__name__,
            "data_collection_depth": "Summary" if detail_level == "summary" else "Full",
            "estimated_tokens": len(response) // 4 if isinstance(response, str) else 0,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        tag_filter = bound.arguments.get("tag_filter")
        if tag_filter:
            entry["tag_filter"] = tag_filter
        _tool_calls.append(entry)
        return response

    return wrapper


def _serialize(obj):
    """Serialize dataclass instances and enums for JSON output."""
    if hasattr(obj, "__dataclass_fields__"):
        from dataclasses import asdict

        return asdict(obj)
    if hasattr(obj, "value"):
        return obj.value
    return str(obj)


def _get_log_field(entry, field: str, default=""):
    """Get a field from a LogEntry object or dict."""
    if isinstance(entry, dict):
        return entry.get(field, default)
    return getattr(entry, field, default)


def _dd_not_configured_error() -> str:
    if is_marketplace_mode():
        from arbiter.context.workspace import arbiter_home

        cred_path = arbiter_home() / "credentials.env"
        msg = (
            "Datadog not configured. "
            f"Set DD_API_KEY and DD_APP_KEY in {cred_path}. "
            "Run /setup for guided configuration."
        )
    else:
        msg = "Datadog not configured. Set DD_API_KEY and DD_APP_KEY."
    return json.dumps({"error": msg})


def _summarize_log_entries(logs) -> dict:
    """Summarize a list of LogEntry objects or dicts into counts, patterns, and a representative."""
    patterns: dict[str, int] = {}
    for entry in logs:
        msg = _get_log_field(entry, "message") or ""
        msg = msg[:120] if msg else "unknown"
        patterns[msg] = patterns.get(msg, 0) + 1
    top_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:5]

    timestamps = [
        _get_log_field(entry, "timestamp") for entry in logs if _get_log_field(entry, "timestamp")
    ]
    time_range_str = ""
    if len(timestamps) >= 2:
        time_range_str = f"{timestamps[-1]} — {timestamps[0]}"
    elif timestamps:
        time_range_str = str(timestamps[0])

    representative = None
    if logs:
        msg = _get_log_field(logs[0], "message") or ""
        representative = msg[:300] if msg else None

    return {
        "total": len(logs),
        "unique_patterns": [{"pattern": p, "count": c} for p, c in top_patterns],
        "time_range": time_range_str,
        "representative": representative,
        "detail_level": "summary",
    }


def _record_investigation_action(collected_data_path: str, action: str, **details):
    """Append an investigation action to the collected data file.

    Gives validate_investigation visibility into what Claude actually did.
    """
    if not collected_data_path:
        return
    try:
        p = Path(collected_data_path)
        if not p.exists():
            return
        data = json.loads(p.read_text())
        actions = data.setdefault("investigation_actions", [])
        actions.append({"action": action, "timestamp": datetime.now(UTC).isoformat(), **details})
        p.write_text(json.dumps(data, indent=2, default=str))
    except Exception:
        pass


def _compute_analysis_hints(context: dict) -> dict:
    """Compute pre-analysis signals from collected data.

    Returns a dict with error rate, intermittent flag, deploy timing,
    and volume anomaly detection.
    """
    from dateutil import parser as dateutil_parser

    hints: dict = {}
    traces = context.get("datadog_traces", [])

    total = len(traces)
    hints["total_traces"] = total

    if total > 0:
        error_traces = [
            t
            for t in traces
            if str(t.get("status_code", "")).startswith(("4", "5")) or t.get("error_type")
        ]
        success_traces = total - len(error_traces)
        error_rate = len(error_traces) / total

        hints["error_traces"] = len(error_traces)
        hints["success_traces"] = success_traces
        hints["error_rate"] = round(error_rate, 3)
        hints["intermittent"] = 0 < error_rate < 1.0

        error_timestamps = []
        for t in error_traces:
            ts = t.get("timestamp", "")
            if ts:
                with contextlib.suppress(ValueError, TypeError):
                    error_timestamps.append(dateutil_parser.isoparse(str(ts)))

        if error_timestamps:
            first_error = min(error_timestamps)
            hints["first_error_at"] = first_error.isoformat()

            last_deploy_time = _extract_last_deploy_time(context)
            if last_deploy_time:
                try:
                    deploy_dt = dateutil_parser.isoparse(last_deploy_time)
                    delta = (first_error - deploy_dt).total_seconds()
                    if delta >= 0:
                        hints["deploy_to_error_seconds"] = round(delta, 1)
                        hints["deploy_correlated"] = delta < 300
                        hints["last_deploy_at"] = last_deploy_time
                except (ValueError, TypeError):
                    pass
        # Per-endpoint error rates
        endpoint_stats: dict[str, dict] = {}
        for t in traces:
            ep = t.get("http_path") or t.get("endpoint") or ""
            if not ep:
                continue
            endpoint_stats.setdefault(ep, {"total": 0, "errors": 0})
            endpoint_stats[ep]["total"] += 1
            if str(t.get("status_code", "")).startswith(("4", "5")) or t.get("error_type"):
                endpoint_stats[ep]["errors"] += 1

        deterministic_endpoints = [
            ep for ep, s in endpoint_stats.items() if s["total"] >= 2 and s["errors"] == s["total"]
        ]
        if deterministic_endpoints:
            hints["deterministic_failure_endpoints"] = deterministic_endpoints

        if error_rate == 1.0 and not hints.get("deploy_correlated") and deterministic_endpoints:
            hints["persistent_failure"] = True
    else:
        hints["error_traces"] = 0
        hints["success_traces"] = 0
        hints["error_rate"] = 0.0
        hints["intermittent"] = False

    # Expectation signals — what does the service's configuration tell us?
    infra = context.get("infrastructure_profile", {})
    queues = infra.get("message_queues", [])
    hints["has_message_queues"] = bool(queues)

    if hints.get("error_rate", 0) == 0 and context.get("alert"):
        hints["zero_errors_with_alert"] = True

    _add_volume_hints(context, hints)

    return hints


def _add_volume_hints(context: dict, hints: dict) -> None:
    """Read pre-computed volume metrics from context (populated during primary collection).

    Falls back gracefully if volume_metrics is absent — no Datadog API calls made here.
    """
    vol = context.get("volume_metrics")
    if vol is not None:
        for key in (
            "volume_anomaly",
            "volume_check_error",
            "volume_metric_prefix",
        ):
            if key in vol:
                hints[key] = vol[key]
        if vol.get("current_rate") is not None:
            hints["request_rate_current"] = vol["current_rate"]
        if vol.get("baseline_rate") is not None:
            hints["request_rate_baseline"] = vol["baseline_rate"]
        if vol.get("volume_change_ratio") is not None:
            hints["volume_change_ratio"] = vol["volume_change_ratio"]

        # Queue backlog hints
        queue = vol.get("queue")
        if queue:
            hints["queue_backlog_current"] = queue.get("current_backlog")
            hints["queue_backlog_baseline"] = queue.get("baseline_backlog")
            hints["queue_volume_anomaly"] = queue.get("volume_anomaly")
            hints["queue_volume_change_ratio"] = queue.get("volume_change_ratio")
            hints["queue_topic"] = queue.get("topic")
        return

    hints["volume_anomaly"] = None
    hints["volume_check_error"] = "volume metrics not pre-computed during collection"


def _compute_recommended_tools(context: dict) -> list[dict]:
    """Map gathered signals + infrastructure to prioritized next-tool recommendations."""
    hints = context.get("analysis_hints", {})
    infra = context.get("infrastructure_profile", {})
    db_type = infra.get("database", "none")
    enrichment = context.get("enrichment_hints", [])
    recommendations: list[dict] = []

    if enrichment:
        recommendations.append(
            {
                "tool": "get_service_enrichment_data",
                "reason": "Architecture context available — explains why errors happen",
                "priority": "high",
            }
        )

    # Zero errors + alert = the failure isn't in the request-response path
    if hints.get("zero_errors_with_alert"):
        recommendations.insert(
            0,
            {
                "tool": "fetch_datadog_metrics",
                "reason": (
                    "0% errors but alert fired — the failure isn't in the request-response "
                    "path. Check workload patterns: message backlog, container CPU/memory, "
                    "container restarts."
                ),
                "priority": "high",
            },
        )

    # Service has message queue inputs — recommend checking them
    queues = infra.get("message_queues", [])
    if queues:
        pubsub_queues = [
            q for q in queues if q.get("type") == "pubsub" and q.get("role") in ("consumer", "both")
        ]
        if pubsub_queues:
            topic = pubsub_queues[0].get("topic", "")
            recommendations.append(
                {
                    "tool": "fetch_datadog_metrics",
                    "args": {
                        "query": (
                            f"avg:gcp.pubsub.subscription.num_undelivered_messages"
                            f"{{subscription_id:*{topic}*}}"
                        )
                    },
                    "reason": f"Service has Pub/Sub input ('{topic}') — check message backlog",
                    "priority": "high",
                }
            )

    if hints.get("deploy_correlated"):
        recommendations.append(
            {
                "tool": "fetch_github_pr",
                "reason": f"Deploy correlates with errors ({hints.get('deploy_to_error_seconds', '?')}s before first error)",
                "priority": "high",
            }
        )
        recommendations.append(
            {
                "tool": "compare_datadog_traces",
                "reason": "Compare failing traces against pre-deploy baseline",
                "priority": "high",
            }
        )
        recommendations.append(
            {
                "tool": "search_github_code",
                "reason": "Trace stack trace functions back to the deployed code change",
                "priority": "medium",
            }
        )

    deployment = infra.get("deployment", "none")
    if not hints.get("deploy_correlated"):
        recommendations.append(
            {
                "tool": "fetch_datadog_watchdog_insights",
                "args": {"change_only": True},
                "reason": "No deploy correlation — check for infrastructure changes Datadog detected",
                "priority": "high",
            }
        )
        recommendations.append(
            {
                "tool": "fetch_gcp_audit_logs",
                "reason": "No deploy correlation — check for GCP infrastructure changes",
                "priority": "medium",
            }
        )
        if deployment == "gke" and context.get("gke_cluster"):
            recommendations.append(
                {
                    "tool": "fetch_gke_operations",
                    "reason": "GKE-deployed service with no deploy correlation — check for cluster operations (upgrades, node drains)",
                    "priority": "high",
                }
            )

    if (
        db_type == "postgresql"
        and not hints.get("deploy_correlated")
        and not context.get("cloudsql_operations")
    ):
        recommendations.append(
            {
                "tool": "fetch_cloudsql_operations",
                "reason": "PostgreSQL service with no deploy correlation — check for CloudSQL scheduled maintenance",
                "priority": "high",
            }
        )

    if hints.get("intermittent"):
        recommendations.append(
            {
                "tool": "analyze_datadog_logs",
                "args": {"template": "errors_by_pod"},
                "reason": f"Intermittent failure (error rate {hints.get('error_rate', '?')}) — check if errors cluster on one pod",
                "priority": "high",
            }
        )
        recommendations.append(
            {
                "tool": "aggregate_trace_data",
                "args": {"group_by": "pod_name"},
                "reason": "Group traces by pod to find if errors cluster on specific instances",
                "priority": "medium",
            }
        )

    if db_type not in ("none", None) and context.get("datadog_db_errors"):
        recommendations.append(
            {
                "tool": "fetch_database_query_performance",
                "reason": f"DB errors detected on {db_type} — check query-level performance",
                "priority": "high",
            }
        )
        recommendations.append(
            {
                "tool": "fetch_database_health_signals",
                "reason": f"DB errors detected — check {db_type} connection pool, locks, replication",
                "priority": "medium",
            }
        )

    if hints.get("deterministic_failure_endpoints"):
        eps = ", ".join(hints["deterministic_failure_endpoints"][:3])
        recommendations.append(
            {
                "tool": "fetch_trace_spans",
                "reason": f"100% failure on {eps} — inspect child spans for hidden error details",
                "priority": "high",
            }
        )
        already_recommended = {r["tool"] for r in recommendations}
        if "search_github_code" not in already_recommended:
            recommendations.append(
                {
                    "tool": "search_github_code",
                    "reason": "100% failure suggests code bug or data issue — search for the failing handler",
                    "priority": "high",
                }
            )
        recommendations.append(
            {
                "tool": "read_github_file",
                "reason": "After identifying the failing handler, read the source to understand the code path",
                "priority": "medium",
            }
        )

    if hints.get("persistent_failure"):
        recommendations.append(
            {
                "tool": "fetch_datadog_traces",
                "args": {"time_range": "7d"},
                "reason": "Persistent failure — expand search to find when failure started (use traces, 15d retention)",
                "priority": "high",
            }
        )
        recommendations.append(
            {
                "tool": "compare_datadog_traces",
                "reason": "Compare against healthy baseline to find when behavior changed",
                "priority": "high",
            }
        )

    if hints.get("volume_anomaly"):
        recommendations.append(
            {
                "tool": "fetch_datadog_metrics",
                "reason": f"Volume anomaly detected (ratio: {hints.get('volume_change_ratio', '?')}x vs baseline) — investigate traffic pattern",
                "priority": "high",
            }
        )

    # Frontend with RUM configured — recommend client-side checks
    frontend = infra.get("frontend", {})
    if frontend.get("rum"):
        recommendations.append(
            {
                "tool": "fetch_rum_errors",
                "reason": "Service has RUM configured — check for browser-side JavaScript errors",
                "priority": "medium",
            }
        )

    recommendations.append(
        {
            "tool": "fetch_datadog_monitors",
            "reason": "Check monitor status for the service",
            "priority": "low",
        }
    )
    recommendations.append(
        {
            "tool": "fetch_datadog_slos",
            "reason": "Check SLO burn rate",
            "priority": "low",
        }
    )

    return recommendations


def _build_investigation_brief(context: dict, output_path: str) -> dict:
    """Compact summary for Claude's context window. Full data on disk."""
    brief: dict = {
        "collected_data_path": output_path,
        "title": context.get("title", ""),
        "collection_summary": context.get("collection_summary", {}),
        "analysis_hints": context.get("analysis_hints", {}),
        "infrastructure_profile": context.get("infrastructure_profile", {}),
        "similar_past_incidents": context.get("similar_past_incidents", []),
        "enrichment_hints": context.get("enrichment_hints", []),
    }

    # Top errors — deduplicated, max 5
    logs = context.get("datadog_logs", [])
    error_counts: dict[str, int] = {}
    for log in logs:
        key = log.get("message", "")[:150]
        error_counts[key] = error_counts.get(key, 0) + 1
    brief["top_errors"] = [
        {"pattern": k, "count": v} for k, v in sorted(error_counts.items(), key=lambda x: -x[1])[:5]
    ]

    # Top traces — 5 most interesting (errors first, then slowest)
    traces = context.get("datadog_traces", [])
    error_traces = [
        t
        for t in traces
        if t.get("error_type") or str(t.get("status_code", "")).startswith(("4", "5"))
    ]
    # Sort errors by duration (slowest first), fall back to all traces sorted by duration
    sorted_errors = sorted(error_traces, key=lambda t: t.get("duration_ms", 0), reverse=True)
    sorted_traces = sorted(traces, key=lambda t: t.get("duration_ms", 0), reverse=True)
    selected = sorted_errors[:5] or sorted_traces[:5]

    # Merge pre-fetched child spans onto selected traces (FR-006)
    prefetched = context.get("prefetched_child_spans", {})
    for t in selected:
        tid = t.get("trace_id", "")
        if tid and tid in prefetched and prefetched[tid]:
            t["child_span_errors"] = prefetched[tid]

    brief["top_traces"] = [
        {
            "trace_id": t.get("trace_id", ""),
            "endpoint": t.get("http_path", ""),
            "status_code": t.get("status_code", ""),
            "error_type": t.get("error_type", ""),
            "error_message": t.get("error_message", "")[:200],
            "duration_ms": t.get("duration_ms", 0),
            "pod_name": t.get("pod_name", ""),
            **({"child_span_errors": t["child_span_errors"]} if "child_span_errors" in t else {}),
        }
        for t in selected
    ]

    # DB errors — count + top pattern
    db_errors = context.get("datadog_db_errors", [])
    brief["db_error_count"] = len(db_errors)
    if db_errors:
        brief["db_error_sample"] = db_errors[0].get("message", "")[:200]

    # Deploy context — GitHub collector uses "pre_incident_deploys"/"during_incident_deploys",
    # but fallback path uses "recent_merged_prs". Handle both.
    deploys = context.get("github_deploys", {})
    pre = deploys.get("pre_incident_deploys", [])
    during = deploys.get("during_incident_deploys", [])
    recent = deploys.get("recent_merged_prs", [])
    if pre or during:
        brief["deploy_summary"] = {
            "pre_incident": len(pre),
            "during_incident": len(during),
            "latest_pr": pre[0] if pre else None,
        }
    else:
        brief["deploy_summary"] = {
            "pre_incident": len(recent),
            "during_incident": 0,
            "latest_pr": recent[0] if recent else None,
        }

    # GKE operations summary
    gke_ops = context.get("gke_operations", [])
    if gke_ops:
        brief["gke_operations_summary"] = {
            "total": len(gke_ops),
            "operations": [
                {
                    "type": op.get("operation_type", ""),
                    "status": op.get("status", ""),
                    "start": op.get("start_time", ""),
                    "end": op.get("end_time", ""),
                    "cluster": op.get("cluster", ""),
                }
                for op in gke_ops[-5:]
            ],
        }
        upgrade_ops = [op for op in gke_ops if op.get("operation_type") == "UPGRADE_NODES"]
        if upgrade_ops:
            brief["gke_operations_summary"]["pdb_configured"] = all(
                int(op.get("node_conditions", {}).get("NODE_PDB_DELAY_SECONDS", 0)) > 0
                for op in upgrade_ops
            )
        kubectl = context.get("kubectl_context")
        if kubectl:
            brief["gke_operations_summary"]["kubectl_enrichment"] = kubectl

    # CloudSQL operations summary
    cloudsql_ops = context.get("cloudsql_operations", [])
    if cloudsql_ops:
        brief["cloudsql_operations_summary"] = {
            "total": len(cloudsql_ops),
            "operations": [
                {
                    "type": op.get("operation_type", ""),
                    "status": op.get("status", ""),
                    "start": op.get("start_time", ""),
                    "end": op.get("end_time", ""),
                    "instance": op.get("instance", ""),
                }
                for op in cloudsql_ops[-5:]
            ],
            "has_maintenance": any(
                "MAINTENANCE" in op.get("operation_type", "") for op in cloudsql_ops
            ),
        }

    brief["recommended_next_tools"] = _compute_recommended_tools(context)

    # Investigation warnings — machine-enforced guardrails
    warnings = []
    hints = context.get("analysis_hints", {})

    # Primary data missing — rate limit or collection failure
    if context.get("primary_collection_failed"):
        warnings.append(
            {
                "warning": "primary_data_missing",
                "message": (
                    "Primary service data was not collected (rate limit or error). "
                    "Wait 60s and call fetch_datadog_traces / fetch_datadog_logs directly "
                    "before forming hypotheses."
                ),
                "severity": "high",
            }
        )

    # Opaque errors: traces with no error details
    error_traces_for_warn = [
        t
        for t in traces
        if t.get("error_type") or str(t.get("status_code", "")).startswith(("4", "5"))
    ]
    if error_traces_for_warn:
        opaque_count = sum(
            1
            for t in error_traces_for_warn
            if not t.get("error_type") and not t.get("error_message")
        )
        if opaque_count > 0:
            warnings.append(
                {
                    "warning": "opaque_errors",
                    "message": (
                        f"{opaque_count} of {len(error_traces_for_warn)} error traces "
                        "have no error_type or error_message — the actual error is in "
                        "child spans. Use fetch_trace_spans with the trace_id to find it."
                    ),
                    "severity": "high",
                }
            )

    # Wrong service: logs/traces suggest this service proxies or doesn't handle the workload
    logs = context.get("datadog_logs", [])
    skip_phrases = (
        "not supported",
        "skipping",
        "forwarding",
        "proxying",
        "upstream",
        "connection refused",
        "bad gateway",
    )
    skip_patterns = sum(
        1 for log in logs if any(p in log.get("message", "").lower() for p in skip_phrases)
    )
    traces_502 = sum(1 for t in traces if str(t.get("status_code", "")) == "502")
    wrong_service_signals = skip_patterns + traces_502
    total_signals = len(logs) + len(traces)
    if (
        total_signals > 0
        and wrong_service_signals > total_signals * 0.3
        and wrong_service_signals >= 3
    ):
        warnings.append(
            {
                "warning": "service_may_not_handle_workload",
                "message": (
                    f"{wrong_service_signals} signals (skip-patterns in logs + 502s in traces) "
                    "indicate this service proxies or doesn't handle the failing operation. "
                    "Consider gathering context for the upstream service."
                ),
                "severity": "high",
            }
        )

    # Deterministic failure pattern
    deterministic_eps = hints.get("deterministic_failure_endpoints", [])
    if deterministic_eps:
        warnings.append(
            {
                "warning": "deterministic_failure",
                "message": (
                    f"100% error rate on {', '.join(deterministic_eps[:3])}. "
                    "This is NOT transient infrastructure — hypothesize code bugs, "
                    "data corruption, or missing dependencies."
                ),
                "severity": "high",
            }
        )

    # GKE cluster config missing
    brief_infra = context.get("infrastructure_profile", {})
    if (
        brief_infra.get("deployment") == "gke"
        and not context.get("gke_operations")
        and "gke_error" not in context
    ):
        gke_step = next(
            (
                s
                for s in context.get("collection_summary", {}).get("steps", [])
                if s.get("step") == "GKE operations"
                and s.get("reason") == "no GKE cluster configured"
            ),
            None,
        )
        if gke_step:
            warnings.append(
                {
                    "warning": "gke_cluster_config_missing",
                    "message": (
                        "Service is deployed on GKE but no cluster configuration found in "
                        "services.yaml. Add gke_cluster to the service's infrastructure "
                        "block to enable GKE operations collection."
                    ),
                    "severity": "medium",
                }
            )

    # Unmet expectation: message queues configured but not checked
    queues = brief_infra.get("message_queues", [])
    vol = context.get("volume_metrics", {})
    queue_data = vol.get("queue")
    queue_checked = isinstance(queue_data, dict) and queue_data.get("current_backlog") is not None
    if queues and not queue_checked:
        topic_names = ", ".join(q.get("topic", "?") for q in queues[:3])
        warnings.append(
            {
                "warning": "expected_input_not_checked",
                "message": (
                    f"Service has message queue inputs ({topic_names}) but queue "
                    "metrics were not collected. The volume check only measured HTTP "
                    "request rate. Use fetch_datadog_metrics to check Pub/Sub "
                    "subscription backlog before concluding."
                ),
                "severity": "high",
            }
        )

    # Universal: zero errors but alert fired
    if hints.get("error_rate", 0) == 0 and context.get("alert"):
        warnings.append(
            {
                "warning": "zero_errors_alert_fired",
                "message": (
                    "0% error rate but an alert fired. The failure is not in the "
                    "request-response path. Before concluding, ask: what are this "
                    "service's inputs? What drives its activity? Check workload "
                    "patterns, container metrics, and resource utilization."
                ),
                "severity": "high",
            }
        )

    # Known noise: service has noise_filters and traces may include noise
    service_name = context.get("service_name", "")
    noise_filters: list[dict] = []
    if service_name:
        from arbiter.context.service_map import get_noise_filters as _get_noise_filters

        noise_filters = _get_noise_filters(service_name)
    if noise_filters and traces:
        labels = [f.get("label", f.get("pattern", "")) for f in noise_filters]
        suggestions = []
        for nf in noise_filters:
            field = nf.get("field", "")
            pattern = nf.get("pattern", "")
            if field and pattern:
                suggestions.append(f"-@{field}:{pattern}")
        warnings.append(
            {
                "warning": "known_noise_present",
                "message": (
                    f"Service has known noise sources: {', '.join(labels)}. "
                    f"Error rates may be inflated. Use tag_filter on fetch_datadog_traces "
                    f"to exclude"
                    + (f' (e.g. tag_filter="{suggestions[0]}").' if suggestions else ".")
                ),
                "severity": "medium",
                "noise_filters": noise_filters,
                "suggested_tag_filters": suggestions,
            }
        )

    brief["investigation_warnings"] = warnings

    return brief


def _enrich_with_caveats(matches: list[dict]) -> list[dict]:
    """Add warning caveats to past incident matches to prevent anchoring."""
    for match in matches:
        caveats = []
        status = match.get("status", "")
        if status and status != "resolved":
            caveats.append(f"\u26a0\ufe0f This incident was never resolved (status: {status})")
        if match.get("resolved_by") == "unresolved":
            caveats.append(
                "\u26a0\ufe0f Root cause was never fixed"
                " \u2014 same error signature does NOT mean same root cause"
            )
        if match.get("confidence_level") == "low":
            caveats.append(
                "\u26a0\ufe0f Original analysis had low confidence \u2014 treat as weak signal"
            )
        ks = match.get("knowledge_source", "arbiter")
        if ks == "human":
            caveats.append(
                "\u26a0\ufe0f Root cause was identified by human investigation, not Arbiter "
                "\u2014 Arbiter only recorded the finding"
            )
        elif ks == "arbiter & human":
            caveats.append(
                "\u26a0\ufe0f Root cause was jointly identified \u2014 Arbiter found the mechanism, "
                "human investigation completed the root cause"
            )
        if caveats:
            match["caveats"] = caveats
    return matches


def _extract_last_deploy_time(context: dict) -> str | None:
    """Find the most recent deploy time from github_deploys or github_workflow_deploys."""
    deploy_times: list[str] = []

    gh_deploys = context.get("github_deploys", {})
    for pr in gh_deploys.get("pre_incident_deploys", []):
        merged = pr.get("merged_at", "")
        if merged:
            deploy_times.append(merged)

    for run in context.get("github_workflow_deploys", []):
        created = run.get("created_at", "")
        if created:
            deploy_times.append(created)

    if not deploy_times:
        return None

    from dateutil import parser as dateutil_parser

    parsed = []
    for t in deploy_times:
        with contextlib.suppress(ValueError, TypeError):
            parsed.append(dateutil_parser.isoparse(t))

    return max(parsed).isoformat() if parsed else None


# ---------------------------------------------------------------------------
# Shared implementation functions — used by both gather_incident_context
# (single-pass) and the phased investigation tools.
# ---------------------------------------------------------------------------


def _preflight_impl(
    service_name: str,
    time_range: str,
    from_time: str,
    to_time: str,
    env: str,
    conversation: str,
    alert_text: str,
) -> dict:
    """Resolve service metadata and prepare context dict. Zero API calls."""
    if env == "production":
        detected = detect_environment_from_text(f"{conversation} {alert_text}")
        if detected:
            dd_env = detected
            logger.info("Auto-detected environment '%s' from conversation/alert", dd_env)
        else:
            dd_env = env
    else:
        dd_env = resolve_datadog_environment(env)

    context: dict = {
        "service": service_name,
        "generated_at": datetime.now(UTC).isoformat(),
        "time_range": {"from": from_time or f"now-{time_range}", "to": to_time or "now"},
        "environment": dd_env,
    }

    try:
        svc_info = get_service_info(service_name, GRAPH)
        context["service_info"] = _serialize(svc_info)
        blast = get_blast_radius(service_name, GRAPH)
        context["blast_radius"] = [_serialize(b) for b in blast]
    except Exception as e:
        logger.warning("Failed to load service info: %s", e)
        context["service_info"] = {}
        context["blast_radius"] = []

    infra = get_infrastructure_profile(service_name, GRAPH)
    context["infrastructure_profile"] = infra

    if infra.get("deployment") == "gke":
        gke_cluster = get_gke_cluster_config(service_name, GRAPH)
        if gke_cluster:
            context["gke_cluster"] = gke_cluster

    dd_service = get_datadog_service(service_name, GRAPH)
    context["datadog_service_name"] = dd_service

    dd_kwargs: dict = {"env": dd_env}
    if from_time:
        dd_kwargs["from_time"] = from_time
        dd_kwargs["to_time"] = to_time or "now"

    transitive_upstream = get_transitive_dependencies(
        service_name, GRAPH, max_depth=2, direction="upstream"
    )
    context["dependency_graph"] = transitive_upstream

    return {
        "context": context,
        "dd_env": dd_env,
        "dd_service": dd_service,
        "dd_kwargs": dd_kwargs,
        "infra": infra,
        "transitive_upstream": transitive_upstream,
    }


def _collect_primary_impl(
    dd: DatadogCollector,
    dd_service: str,
    time_range: str,
    context: dict,
    dd_kwargs: dict,
) -> list[dict]:
    """Collect APM traces, logs, UUIDs, and DB errors for the primary service.

    Dispatches traces, logs, DB errors, and volume metrics concurrently using
    ThreadPoolExecutor. Each thread uses its own DatadogCollector instance.
    Falls back to sequential execution on ThreadPoolExecutor failure.

    Mutates context in-place. Returns steps list.
    """
    import re
    import time

    steps: list[dict] = []

    dd_api_key, dd_app_key, dd_site = dd.api_key, dd.app_key, dd.site

    def _fetch_traces():
        t0 = time.time()
        _dd = DatadogCollector(api_key=dd_api_key, app_key=dd_app_key, site=dd_site)
        result = _dd.search_traces(
            service=dd_service, time_range=time_range, status_code="", limit=50, **dd_kwargs
        )
        return result, int((time.time() - t0) * 1000)

    def _fetch_logs():
        t0 = time.time()
        _dd = DatadogCollector(api_key=dd_api_key, app_key=dd_app_key, site=dd_site)
        result = _dd.collect_logs(service=dd_service, time_range=time_range, limit=100, **dd_kwargs)
        return result, int((time.time() - t0) * 1000)

    def _fetch_db_errors():
        t0 = time.time()
        _dd = DatadogCollector(api_key=dd_api_key, app_key=dd_app_key, site=dd_site)
        result = _dd.search_database_errors(service=dd_service, time_range=time_range, **dd_kwargs)
        return result, int((time.time() - t0) * 1000)

    def _fetch_http_volume(_dd, dd_svc, inc_start, inc_end, bl_start, bl_end):
        """Check HTTP request rate across framework prefixes."""
        prefixes = ["http", "flask", "fastapi", "grpc", "django", "express"]
        errs: list[str] = []
        for pfx in prefixes:
            q = f"sum:trace.{pfx}.request.hits{{service:{dd_svc}}}.as_rate()"
            try:
                cur = _dd.query_metrics(
                    query=q, from_time=inc_start.isoformat(), to_time=inc_end.isoformat()
                )
            except Exception as e:
                errs.append(f"{pfx}: {e}")
                continue
            pts = cur[0].get("points", []) if cur else []
            vals = [p["value"] for p in pts if p.get("value") is not None]
            if not vals:
                continue
            cr = sum(vals) / len(vals)
            br = None
            try:
                bl = _dd.query_metrics(
                    query=q, from_time=bl_start.isoformat(), to_time=bl_end.isoformat()
                )
            except Exception as e:
                errs.append(f"{pfx} baseline: {e}")
                return {
                    "current_rate": round(cr, 2),
                    "baseline_rate": None,
                    "volume_change_ratio": None,
                    "volume_anomaly": None,
                    "volume_metric_prefix": pfx,
                    "volume_check_error": f"baseline failed: {e}",
                }
            bp = bl[0].get("points", []) if bl else []
            bvals = [p["value"] for p in bp if p.get("value") is not None]
            if bvals:
                br = sum(bvals) / len(bvals)
            if br is not None and br > 0:
                ratio = cr / br
                return {
                    "current_rate": round(cr, 2),
                    "baseline_rate": round(br, 2),
                    "volume_change_ratio": round(ratio, 2),
                    "volume_anomaly": ratio > 2.0 or ratio < 0.3,
                    "volume_metric_prefix": pfx,
                    "volume_check_error": None,
                }
            else:
                return {
                    "current_rate": round(cr, 2),
                    "baseline_rate": None,
                    "volume_change_ratio": None,
                    "volume_anomaly": None,
                    "volume_metric_prefix": pfx,
                    "volume_check_error": "baseline window returned no data",
                }
        err = (
            f"API errors: {'; '.join(errs)}"
            if errs
            else "no request rate metrics found for any framework"
        )
        return {
            "current_rate": None,
            "baseline_rate": None,
            "volume_change_ratio": None,
            "volume_anomaly": None,
            "volume_metric_prefix": None,
            "volume_check_error": err,
        }

    def _fetch_queue_volume(_dd, queues, inc_start, inc_end, bl_start, bl_end):
        """Check message queue backlog for configured consumer subscriptions."""
        for q in queues:
            if q.get("type") != "pubsub" or q.get("role") not in ("consumer", "both"):
                continue
            topic = q.get("topic", "")
            if not topic:
                continue
            metric = (
                f"avg:gcp.pubsub.subscription.num_undelivered_messages"
                f"{{subscription_id:*{topic}*}}"
            )
            try:
                cur = _dd.query_metrics(
                    query=metric,
                    from_time=inc_start.isoformat(),
                    to_time=inc_end.isoformat(),
                )
            except Exception:
                continue
            pts = cur[0].get("points", []) if cur else []
            vals = [p["value"] for p in pts if p.get("value") is not None]
            if not vals:
                continue
            current_backlog = max(vals)
            baseline_backlog = None
            try:
                bl = _dd.query_metrics(
                    query=metric,
                    from_time=bl_start.isoformat(),
                    to_time=bl_end.isoformat(),
                )
                bp = bl[0].get("points", []) if bl else []
                bvals = [p["value"] for p in bp if p.get("value") is not None]
                if bvals:
                    baseline_backlog = max(bvals)
            except Exception:
                pass
            ratio = None
            anomaly = None
            if baseline_backlog is not None and baseline_backlog > 0:
                ratio = round(current_backlog / baseline_backlog, 2)
                anomaly = ratio > 2.0 or ratio < 0.3
            elif current_backlog > 100:
                anomaly = True
            return {
                "current_backlog": round(current_backlog, 1),
                "baseline_backlog": (
                    round(baseline_backlog, 1) if baseline_backlog is not None else None
                ),
                "volume_change_ratio": ratio,
                "volume_anomaly": anomaly,
                "volume_metric_type": "pubsub_backlog",
                "topic": topic,
            }
        return None

    def _fetch_volume_metrics():
        t0 = time.time()
        vol: dict = {}
        dd_svc = context.get("datadog_service_name", "")
        ti = context.get("time_range", {})
        fs = ti.get("from", "")
        ts = ti.get("to", "")
        if not dd_svc:
            return {
                "current_rate": None,
                "baseline_rate": None,
                "volume_change_ratio": None,
                "volume_anomaly": None,
                "volume_metric_prefix": None,
                "volume_check_error": "no datadog service name in context",
            }, int((time.time() - t0) * 1000)
        if not fs or fs.startswith("now"):
            return {
                "current_rate": None,
                "baseline_rate": None,
                "volume_change_ratio": None,
                "volume_anomaly": None,
                "volume_metric_prefix": None,
                "volume_check_error": "absolute time range required for volume comparison",
            }, int((time.time() - t0) * 1000)
        try:
            from dateutil import parser as dateutil_parser

            inc_start = dateutil_parser.isoparse(fs)
            inc_end = dateutil_parser.isoparse(ts) if ts and ts != "now" else datetime.now(UTC)
            dur = inc_end - inc_start
            if dur.total_seconds() <= 0:
                return {
                    "current_rate": None,
                    "baseline_rate": None,
                    "volume_change_ratio": None,
                    "volume_anomaly": None,
                    "volume_metric_prefix": None,
                    "volume_check_error": "invalid time range: end is before start",
                }, int((time.time() - t0) * 1000)
            bl_end = inc_start - timedelta(hours=24)
            bl_start = bl_end - dur
            _dd = DatadogCollector(api_key=dd_api_key, app_key=dd_app_key, site=dd_site)

            # Path 1: HTTP request rate (existing logic)
            vol = _fetch_http_volume(_dd, dd_svc, inc_start, inc_end, bl_start, bl_end)

            # Path 2: Message queue backlog (runs after HTTP, not as fallback)
            infra = context.get("infrastructure_profile", {})
            queues = infra.get("message_queues", [])
            if queues:
                queue_vol = _fetch_queue_volume(_dd, queues, inc_start, inc_end, bl_start, bl_end)
                if queue_vol:
                    vol["queue"] = queue_vol
        except Exception as e:
            vol = {
                "current_rate": None,
                "baseline_rate": None,
                "volume_change_ratio": None,
                "volume_anomaly": None,
                "volume_metric_prefix": None,
                "volume_check_error": str(e),
            }
        return vol, int((time.time() - t0) * 1000)

    # Dispatch all 4 fetches concurrently.
    # THREAD SAFETY: context is read-only during concurrent dispatch.
    # _fetch_volume_metrics reads context["datadog_service_name"] and context["time_range"]
    # which are set by preflight before this function is called. No thread mutates context.
    # Per-future error handling: keep successful results, only re-run failed fetches.
    with ThreadPoolExecutor(max_workers=4) as executor:
        trace_future = executor.submit(_fetch_traces)
        log_future = executor.submit(_fetch_logs)
        db_future = executor.submit(_fetch_db_errors)
        vol_future = executor.submit(_fetch_volume_metrics)

    try:
        traces, trace_ms = trace_future.result()
    except Exception as e:
        logger.warning("Concurrent trace fetch failed, falling back to sequential: %s", e)
        t0 = time.time()
        traces = dd.search_traces(
            service=dd_service, time_range=time_range, status_code="", limit=50, **dd_kwargs
        )
        trace_ms = int((time.time() - t0) * 1000)

    try:
        logs, log_ms = log_future.result()
    except Exception as e:
        logger.warning("Concurrent log fetch failed, falling back to sequential: %s", e)
        time.sleep(dd.recommended_delay())
        t0 = time.time()
        logs = dd.collect_logs(service=dd_service, time_range=time_range, limit=100, **dd_kwargs)
        log_ms = int((time.time() - t0) * 1000)

    try:
        db_errors, db_ms = db_future.result()
    except Exception as e:
        logger.warning("Concurrent DB error fetch failed, falling back to sequential: %s", e)
        time.sleep(dd.recommended_delay())
        t0 = time.time()
        db_errors = dd.search_database_errors(
            service=dd_service, time_range=time_range, **dd_kwargs
        )
        db_ms = int((time.time() - t0) * 1000)

    try:
        volume_data, vol_ms = vol_future.result()
    except Exception as e:
        logger.warning("Concurrent volume metrics failed: %s", e)
        volume_data = {
            "current_rate": None,
            "baseline_rate": None,
            "volume_change_ratio": None,
            "volume_anomaly": None,
            "volume_metric_prefix": None,
            "volume_check_error": f"volume metrics failed: {e}",
        }
        vol_ms = 0

    # Assign results to context sequentially (no concurrent mutation)
    context["datadog_traces"] = traces
    steps.append(
        {"step": "APM traces", "status": "collected", "count": len(traces), "duration_ms": trace_ms}
    )

    context["datadog_logs"] = [_serialize(entry) for entry in logs]
    context["datadog_log_count"] = len(logs)
    steps.append(
        {"step": "Datadog logs", "status": "collected", "count": len(logs), "duration_ms": log_ms}
    )

    # UUID extraction after logs (FR-010)
    uuids = []
    for entry in logs:
        m = re.search(r'"uuid":\s*"([^"]+)"', entry.message)
        if m:
            uuids.append({"uuid": m.group(1), "timestamp": entry.timestamp})
    context["extracted_uuids"] = uuids

    context["datadog_db_errors"] = [_serialize(entry) for entry in db_errors]
    steps.append(
        {
            "step": "Database errors (primary)",
            "status": "collected",
            "count": len(db_errors),
            "duration_ms": db_ms,
        }
    )

    # Child span prefetch — sequential after traces (FR-006)
    t0 = time.time()
    prefetched: dict[str, list[dict]] = {}
    opaque_primary = [
        t
        for t in traces
        if (str(t.get("status_code", "")).startswith(("4", "5")) or t.get("error_type"))
        and not t.get("error_type")
        and not t.get("error_message")
        and t.get("trace_id")
    ]
    if opaque_primary:
        try:
            span_dd = DatadogCollector(api_key=dd.api_key, app_key=dd.app_key, site=dd.site)
            if span_dd.is_configured():
                for t in opaque_primary[:5]:
                    try:
                        ts = t.get("timestamp", "")
                        span_kwargs: dict = {}
                        if ts:
                            from dateutil import parser as _dp

                            try:
                                dt = _dp.isoparse(str(ts))
                                span_kwargs["from_time"] = (dt - timedelta(hours=1)).isoformat()
                                span_kwargs["to_time"] = (dt + timedelta(hours=1)).isoformat()
                            except (ValueError, TypeError):
                                pass
                        child_spans = span_dd.search_trace_spans(t["trace_id"], **span_kwargs)
                        detailed_errors = [
                            s
                            for s in child_spans
                            if s.get("is_error") and (s.get("error_type") or s.get("error_message"))
                        ]
                        if detailed_errors:
                            prefetched[t["trace_id"]] = [
                                {
                                    "service": s.get("service", ""),
                                    "error_type": s.get("error_type", ""),
                                    "error_message": s.get("error_message", "")[:200],
                                }
                                for s in detailed_errors[:3]
                            ]
                    except Exception:
                        pass
        except Exception:
            pass
    context["prefetched_child_spans"] = prefetched
    steps.append(
        {
            "step": "Child span prefetch",
            "status": "collected",
            "count": len(prefetched),
            "duration_ms": int((time.time() - t0) * 1000),
        }
    )

    # Volume metrics — already fetched concurrently (FR-007)
    context["volume_metrics"] = volume_data
    steps.append(
        {
            "step": "Volume metrics",
            "status": "collected" if volume_data.get("current_rate") is not None else "skipped",
            "duration_ms": vol_ms,
        }
    )

    return steps


def _collect_dependency_impl(
    dd: DatadogCollector,
    service_name: str,
    time_range: str,
    context: dict,
    dd_kwargs: dict,
    transitive_upstream: list[dict],
) -> list[dict]:
    """Collect upstream traces, upstream DB errors, cross-service logs, UUID correlation.

    Mutates context in-place. Returns steps list.
    """
    import time

    steps: list[dict] = []

    context["dependency_graph"] = transitive_upstream

    # Upstream traces + DB errors (merged single-pass loop)
    t0 = time.time()
    upstream_traces: dict = {}
    upstream_db_errors: dict = {}
    for dep in transitive_upstream:
        upstream = dep["service"]
        try:
            dd_upstream = get_datadog_service(upstream, GRAPH)
            time.sleep(dd.recommended_delay())
            ut = dd.search_traces(
                service=dd_upstream,
                time_range=time_range,
                status_code="500",
                limit=10,
                **dd_kwargs,
            )
            if ut:
                upstream_traces[upstream] = ut
            time.sleep(dd.recommended_delay())
            ub_errors = dd.search_database_errors(
                service=dd_upstream,
                time_range=time_range,
                **dd_kwargs,
            )
            if ub_errors:
                upstream_db_errors[upstream] = [_serialize(entry) for entry in ub_errors]
        except Exception as e:
            logger.warning("Collection failed for %s: %s", upstream, e)
    if upstream_traces:
        context["upstream_traces"] = upstream_traces
    if upstream_db_errors:
        context["upstream_db_errors"] = upstream_db_errors
    steps.append(
        {
            "step": "Upstream signals",
            "status": "collected",
            "trace_count": sum(len(v) for v in upstream_traces.values()),
            "db_error_count": sum(len(v) for v in upstream_db_errors.values()),
            "duration_ms": int((time.time() - t0) * 1000),
        }
    )

    # Cross-service logs
    t0 = time.time()
    related = get_related_services(service_name, GRAPH)
    transitive_services = [d["service"] for d in transitive_upstream]
    all_related = sorted(set(related + transitive_services))
    dd_related = [get_datadog_service(s, GRAPH) for s in all_related]
    cross = dd.collect_logs_multi(
        services=dd_related,
        time_range=time_range,
        **dd_kwargs,
    )
    context["cross_service_logs"] = {
        svc: [_serialize(entry) for entry in svc_logs] for svc, svc_logs in cross.items()
    }
    steps.append(
        {
            "step": "Cross-service logs",
            "status": "collected",
            "count": sum(len(v) for v in cross.values()),
            "duration_ms": int((time.time() - t0) * 1000),
        }
    )

    # UUID correlation
    uuids = context.get("extracted_uuids", [])
    if uuids:
        t0 = time.time()
        time.sleep(dd.recommended_delay())
        uuid_results: dict = {}
        for u in uuids[:5]:
            time.sleep(dd.recommended_delay())
            try:
                matched = dd.search_by_uuid(
                    u["uuid"],
                    time_range=time_range,
                    **dd_kwargs,
                )
                uuid_results[u["uuid"]] = [_serialize(entry) for entry in matched]
            except Exception as e:
                logger.warning("UUID search failed for %s: %s", u["uuid"], e)
        context["uuid_correlation"] = uuid_results
        steps.append(
            {
                "step": "UUID correlation",
                "status": "collected",
                "count": len(uuid_results),
                "duration_ms": int((time.time() - t0) * 1000),
            }
        )

    return steps


def _collect_auxiliary_impl(
    service_name: str,
    time_range: str,
    from_time: str,
    to_time: str,
    dd_env: str,
    context: dict,
    infra: dict,
) -> list[dict]:
    """Run Sentry, GCP, OpsGenie, Git, GitHub collectors in parallel.

    Mutates context in-place. Returns steps list.
    """
    import time

    observability = infra.get("observability", [])

    def _collect_sentry():
        t0 = time.time()
        result = {
            "_step": {"step": "Sentry", "status": "skipped", "reason": "not in observability stack"}
        }
        if "sentry" not in observability:
            return result
        try:
            sentry = SentryCollector()
            if sentry.is_configured():
                sentry_logs = sentry.collect_logs(
                    service=service_name, time_range=time_range, env=dd_env
                )
                if sentry_logs:
                    result["sentry_issues"] = [_serialize(entry) for entry in sentry_logs]
                result["_step"] = {
                    "step": "Sentry",
                    "status": "collected",
                    "count": len(sentry_logs) if sentry_logs else 0,
                    "duration_ms": int((time.time() - t0) * 1000),
                }
            else:
                result["_step"] = {
                    "step": "Sentry",
                    "status": "skipped",
                    "reason": "not configured",
                }
        except Exception as e:
            result["sentry_error"] = str(e)
            result["_step"] = {"step": "Sentry", "status": "error", "error": str(e)}
        return result

    def _collect_gcp():
        t0 = time.time()
        result = {
            "_step": {
                "step": "GCP logs",
                "status": "skipped",
                "reason": "not in observability stack",
            }
        }
        if "gcp" not in observability:
            return result
        try:
            gcp = GCPCollector()
            if gcp.is_configured():
                gcp_project = get_gcp_project(service_name, GRAPH)
                if gcp_project:
                    gcp_logs = gcp.collect_logs(
                        service=service_name,
                        time_range=time_range,
                        from_time=from_time or None,
                        to_time=to_time or None,
                        project_override=gcp_project,
                    )
                    if gcp_logs:
                        result["gcp_logs"] = [_serialize(entry) for entry in gcp_logs]
                    audit_logs = []
                    try:
                        audit_logs = gcp.collect_audit_logs(
                            project=gcp_project,
                            time_range=time_range,
                            from_time=from_time or None,
                            to_time=to_time or None,
                            limit=20,
                        )
                        if audit_logs:
                            result["gcp_audit_logs"] = [_serialize(entry) for entry in audit_logs]
                    except Exception as ae:
                        logger.warning("GCP audit log collection failed: %s", ae)
                    total = (len(gcp_logs) if gcp_logs else 0) + (
                        len(audit_logs) if audit_logs else 0
                    )
                    result["_step"] = {
                        "step": "GCP logs",
                        "status": "collected",
                        "count": total,
                        "duration_ms": int((time.time() - t0) * 1000),
                    }
                else:
                    result["_step"] = {
                        "step": "GCP logs",
                        "status": "skipped",
                        "reason": "no GCP project configured",
                    }
            else:
                result["_step"] = {
                    "step": "GCP logs",
                    "status": "skipped",
                    "reason": "not configured",
                }
        except Exception as e:
            result["gcp_error"] = str(e)
            result["_step"] = {"step": "GCP logs", "status": "error", "error": str(e)}
        return result

    def _collect_opsgenie():
        t0 = time.time()
        result = {}
        try:
            opsgenie = OpsGenieCollector()
            if opsgenie.is_configured():
                og_alerts = opsgenie.get_structured_alerts(
                    service=service_name, time_range=time_range
                )
                if og_alerts:
                    result["opsgenie_alerts"] = [_serialize(a) for a in og_alerts]
                result["_step"] = {
                    "step": "OpsGenie",
                    "status": "collected",
                    "count": len(og_alerts) if og_alerts else 0,
                    "duration_ms": int((time.time() - t0) * 1000),
                }
            else:
                result["_step"] = {
                    "step": "OpsGenie",
                    "status": "skipped",
                    "reason": "not configured",
                }
        except Exception as e:
            result["opsgenie_error"] = str(e)
            result["_step"] = {"step": "OpsGenie", "status": "error", "error": str(e)}
        return result

    def _collect_git():
        import subprocess

        t0 = time.time()
        result = {}
        try:
            git = GitCollector(WORKSPACE_ROOT)
            repo_path = WORKSPACE_ROOT / service_name
            if repo_path.is_dir():
                try:
                    subprocess.run(
                        ["git", "fetch", "--all"], cwd=repo_path, capture_output=True, timeout=30
                    )
                except subprocess.TimeoutExpired:
                    logger.warning(
                        "git fetch timed out for %s — continuing with local state", service_name
                    )
            result["git_context"] = git.gather_context(service_name, hours_back=72)
            result["_step"] = {
                "step": "Git context",
                "status": "collected",
                "duration_ms": int((time.time() - t0) * 1000),
            }
        except Exception as e:
            logger.warning("Git collection failed for %s: %s", service_name, e)
            result["git_context"] = {}
            result["_step"] = {"step": "Git context", "status": "error", "error": str(e)}
        return result

    def _collect_github():
        t0 = time.time()
        result = {}
        try:
            gh = GitHubCollector()
            if gh.is_configured():
                gh_repo = get_github_repo(service_name, GRAPH)
                if from_time:
                    deploy_corr = gh.get_deploy_correlation(
                        gh_repo, incident_start=from_time, window_hours=6
                    )
                    result["github_deploys"] = deploy_corr
                else:
                    merged = gh.get_merged_prs(gh_repo, hours_back=48)
                    if merged:
                        result["github_deploys"] = {"recent_merged_prs": merged}
                workflow_runs = gh.get_workflow_deploys(
                    gh_repo,
                    hours_back=48,
                    from_time=from_time or None,
                    to_time=to_time or None,
                )
                if workflow_runs:
                    result["github_workflow_deploys"] = workflow_runs
                tags = gh.get_recent_tags(gh_repo, limit=10)
                if tags:
                    result["github_tags"] = tags

                svc_infra = get_infrastructure_profile(service_name, GRAPH)
                if svc_infra.get("deploy_mechanism") == "tag":
                    try:
                        releases = gh.get_releases(
                            gh_repo,
                            limit=5,
                            from_time=from_time or None,
                            to_time=to_time or None,
                        )
                        if releases:
                            result["github_releases"] = releases
                    except Exception as re_err:
                        logger.warning("Release fetch failed for %s: %s", service_name, re_err)

                result["_step"] = {
                    "step": "GitHub deploys",
                    "status": "collected",
                    "duration_ms": int((time.time() - t0) * 1000),
                }
            else:
                result["_step"] = {
                    "step": "GitHub deploys",
                    "status": "skipped",
                    "reason": "not configured",
                }
        except Exception as e:
            result["github_error"] = str(e)
            result["_step"] = {"step": "GitHub deploys", "status": "error", "error": str(e)}
        return result

    def _collect_gke_operations():
        t0 = time.time()
        result = {
            "_step": {
                "step": "GKE operations",
                "status": "skipped",
                "reason": "not on GKE",
            }
        }
        if infra.get("deployment") != "gke":
            return result
        try:
            cluster_config = get_gke_cluster_config(service_name, GRAPH)
            if not cluster_config:
                result["_step"]["reason"] = "no GKE cluster configured"
                return result

            gcp = GCPCollector()
            if not gcp._get_access_token():
                result["_step"]["reason"] = "GCP not authenticated (run gcloud auth login)"
                return result

            ops = gcp.collect_gke_operations(
                project=cluster_config["project"],
                location=cluster_config["location"],
                cluster=cluster_config["name"],
                time_range=time_range,
                from_time=from_time or None,
                to_time=to_time or None,
            )
            if ops:
                result["gke_operations"] = ops
            result["_step"] = {
                "step": "GKE operations",
                "status": "collected",
                "count": len(ops) if ops else 0,
                "duration_ms": int((time.time() - t0) * 1000),
            }
        except Exception as e:
            result["gke_error"] = str(e)
            result["_step"] = {"step": "GKE operations", "status": "error", "error": str(e)}
        return result

    def _collect_kubectl_context():
        t0 = time.time()
        result = {
            "_step": {
                "step": "K8s pod context",
                "status": "skipped",
                "reason": "not on GKE",
            }
        }
        if infra.get("deployment") != "gke":
            return result
        try:
            cluster_config = get_gke_cluster_config(service_name, GRAPH)
            if not cluster_config:
                result["_step"]["reason"] = "no GKE cluster configured"
                return result

            from arbiter.collectors.kubernetes import (
                KubernetesCollector,
                kubectl_context_name,
            )

            ctx_name = kubectl_context_name(
                cluster_config["project"],
                cluster_config["location"],
                cluster_config["name"],
            )
            kube = KubernetesCollector(context=ctx_name, namespace=service_name)
            kubectl_data = kube.collect_pod_context(service_name=service_name)
            if kubectl_data:
                result["kubectl_context"] = kubectl_data
            result["_step"] = {
                "step": "K8s pod context",
                "status": "collected",
                "duration_ms": int((time.time() - t0) * 1000),
            }
        except Exception as e:
            logger.debug("kubectl enrichment skipped: %s", e)
            result["_step"] = {
                "step": "K8s pod context",
                "status": "skipped",
                "reason": str(e)[:100],
            }
        return result

    def _collect_cloudsql_operations():
        t0 = time.time()
        result = {
            "_step": {
                "step": "CloudSQL operations",
                "status": "skipped",
                "reason": "not PostgreSQL",
            }
        }
        if infra.get("database") != "postgresql":
            return result
        try:
            instance, project = get_cloudsql_instance(service_name, GRAPH)
            if not instance:
                result["_step"]["reason"] = "no CloudSQL instance configured"
                return result

            gcp = GCPCollector()
            ops = gcp.collect_cloudsql_operations(
                instance=instance,
                project=project,
                time_range=time_range,
                from_time=from_time or None,
                to_time=to_time or None,
            )
            if ops:
                result["cloudsql_operations"] = ops
            result["_step"] = {
                "step": "CloudSQL operations",
                "status": "collected",
                "count": len(ops) if ops else 0,
                "duration_ms": int((time.time() - t0) * 1000),
            }
        except Exception as e:
            result["cloudsql_error"] = str(e)
            result["_step"] = {
                "step": "CloudSQL operations",
                "status": "error",
                "error": str(e),
            }
        return result

    def _collect_status_pages():
        t0 = time.time()
        result = {}
        try:
            from arbiter.collectors.status_pages import check_cloudflare_status, check_gcp_status

            gcp_incidents = check_gcp_status(
                time_range=time_range,
                from_time=from_time or None,
                to_time=to_time or None,
            )
            cf_incidents = check_cloudflare_status(
                time_range=time_range,
                from_time=from_time or None,
                to_time=to_time or None,
            )
            total = len(gcp_incidents) + len(cf_incidents)
            if gcp_incidents:
                result["status_page_gcp"] = gcp_incidents
            if cf_incidents:
                result["status_page_cloudflare"] = cf_incidents
            result["_step"] = {
                "step": "Status pages",
                "status": "collected",
                "count": total,
                "duration_ms": int((time.time() - t0) * 1000),
            }
        except Exception as e:
            result["_step"] = {"step": "Status pages", "status": "error", "error": str(e)}
        return result

    collector_display_names = {
        "sentry": "Sentry",
        "gcp": "GCP logs",
        "gke": "GKE operations",
        "kubectl": "K8s pod context",
        "cloudsql": "CloudSQL operations",
        "status_pages": "Status pages",
        "opsgenie": "OpsGenie",
        "git": "Git context",
        "github": "GitHub deploys",
    }

    steps: list[dict] = []
    skipped: list[str] = []
    with ThreadPoolExecutor(max_workers=9) as executor:
        futures = {
            executor.submit(_collect_sentry): "sentry",
            executor.submit(_collect_gcp): "gcp",
            executor.submit(_collect_gke_operations): "gke",
            executor.submit(_collect_kubectl_context): "kubectl",
            executor.submit(_collect_cloudsql_operations): "cloudsql",
            executor.submit(_collect_status_pages): "status_pages",
            executor.submit(_collect_opsgenie): "opsgenie",
            executor.submit(_collect_git): "git",
            executor.submit(_collect_github): "github",
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
            except Exception as e:
                logger.warning("Parallel collector %s failed: %s", name, e)
                display = collector_display_names.get(name, name)
                steps.append({"step": display, "status": "error", "error": str(e)})
                continue
            step_info = result.pop("_step", None)
            if step_info:
                steps.append(step_info)
                if step_info["status"] == "skipped" and step_info["step"] in ("Sentry", "GCP logs"):
                    skipped.append(f"{step_info['step'].lower()}: {step_info.get('reason', '')}")
            context.update(result)

    if skipped:
        context["skipped_collectors"] = skipped

    return steps


def _finalize_context_impl(
    service_name: str,
    context: dict,
    steps: list[dict],
    conversation: str,
    gather_start: float,
    title: str,
    output_path: Path | None = None,
) -> str:
    """Source code analysis, KB search, causal chain, analysis hints, save, build brief.

    Args:
        output_path: If provided, write to this path instead of creating a new file.
            Used by the phased flow to write back to the session file.

    Returns JSON string (investigation brief or full context fallback).
    """
    import time

    if title and "title" not in context:
        context["title"] = title

    # Source code analysis
    try:
        from arbiter.collectors.source_code import SourceCodeCollector

        source = SourceCodeCollector(WORKSPACE_ROOT)
        source_root = get_source_root(service_name, GRAPH)
        code_context = source.analyze(service_name, context, source_root=source_root)
        if code_context:
            context["source_code"] = code_context
    except Exception as e:
        logger.warning("Source code analysis failed: %s", e)

    # Sync knowledge base from GitHub (marketplace mode only)
    try:
        sync = _get_incident_sync()
        if sync is not None:
            sync.pull_index()
    except Exception as e:
        logger.warning("Marketplace index sync failed: %s", e)

    # Search knowledge base for similar past incidents
    t0 = time.time()
    try:
        from arbiter.core.incident_store import IncidentStore, extract_error_signatures

        incidents_dir = INCIDENTS_ROOT
        store = IncidentStore(incidents_dir)
        sigs = extract_error_signatures(context)
        if sigs:
            context["_extracted_signatures"] = sigs
        similar = store.find_similar(signatures=sigs, service=service_name)
        if similar:
            context["similar_past_incidents"] = _enrich_with_caveats(similar)
        steps.append(
            {
                "step": "Knowledge base",
                "status": "collected",
                "count": len(similar) if similar else 0,
                "duration_ms": int((time.time() - t0) * 1000),
            }
        )
    except Exception as e:
        logger.warning("Knowledge base search failed: %s", e)

    # Causal chain detection
    t0 = time.time()
    try:
        from arbiter.core.causal_chain import chain_to_dict, detect_causal_chain

        chain = detect_causal_chain(context, GRAPH)
        if chain.links:
            context["causal_chain"] = chain_to_dict(chain)
        steps.append(
            {
                "step": "Causal chain",
                "status": "collected",
                "count": len(chain.links) if chain.links else 0,
                "duration_ms": int((time.time() - t0) * 1000),
            }
        )
    except Exception as e:
        logger.warning("Causal chain detection failed: %s", e)

    # Enrichment hints
    if ENRICHMENT_PROVIDERS:
        try:
            hints = get_enrichment_hints(service_name, ENRICHMENT_PROVIDERS)
            if hints:
                context["enrichment_hints"] = hints
        except Exception as e:
            logger.warning("Enrichment hints failed: %s", e)

    # Conversation
    if conversation:
        manual = ManualCollector()
        context["conversation"] = manual.parse_thread(conversation)

    # Analysis hints
    try:
        context["analysis_hints"] = _compute_analysis_hints(context)
    except Exception as e:
        logger.warning("Analysis hints computation failed: %s", e)

    # Collection summary
    context["collection_summary"] = {
        "steps": steps,
        "total_duration_ms": int((time.time() - gather_start) * 1000),
        "sources_collected": sum(1 for s in steps if s["status"] == "collected"),
        "sources_skipped": sum(1 for s in steps if s["status"] == "skipped"),
        "sources_errored": sum(1 for s in steps if s["status"] == "error"),
    }

    # Save to output/collected-data/
    # When output_path is provided (phased flow), write to that path directly.
    # Otherwise (single-pass gather), create a new file.
    try:
        if output_path is not None:
            data_path = output_path
            data_path.parent.mkdir(parents=True, exist_ok=True)
            data_path.write_text(json.dumps(context, indent=2, default=str))
            with _pending_lock:
                _pending_sessions.pop(data_path.stem, None)
        else:
            data_dir = OUTPUT_ROOT / "collected-data"
            data_dir.mkdir(parents=True, exist_ok=True)
            date_str = datetime.now(UTC).strftime("%Y-%m-%d")
            from arbiter.core.models import slugify

            if title:
                slug = slugify(title, strip_leading_date=True)
            if not title or not slug:
                ts = datetime.now(UTC).strftime("%H%M%S")
                slug = f"{slugify(service_name)}-{ts}"
            data_path = data_dir / f"{date_str}-{slug}.json"
            if data_path.exists():
                base = data_path.stem
                i = 2
                while (data_dir / f"{base}-{i}.json").exists():
                    i += 1
                data_path = data_dir / f"{base}-{i}.json"
            data_path.write_text(json.dumps(context, indent=2, default=str))
        context["_saved_to"] = str(data_path)
        _record_investigation_action(str(data_path), "gather", service=service_name)
    except Exception as e:
        logger.warning("Failed to save collected data: %s", e)
        context["_save_error"] = str(e)

    # Build compact investigation brief
    saved_path = context.get("_saved_to", "")
    if saved_path:
        try:
            brief = _build_investigation_brief(context, saved_path)
            if brief.get("investigation_warnings"):
                try:
                    p = Path(saved_path)
                    data = json.loads(p.read_text())
                    data["investigation_warnings"] = brief["investigation_warnings"]
                    data["analysis_hints"] = brief.get("analysis_hints", {})
                    p.write_text(json.dumps(data, indent=2, default=str))
                except Exception:
                    pass
            return json.dumps(brief, indent=2, default=str)
        except Exception as e:
            logger.warning("Failed to build investigation brief: %s", e)

    return json.dumps(context, indent=2, default=str)


# ---------------------------------------------------------------------------
# Session helpers — used by the phased investigation tools
# ---------------------------------------------------------------------------


def _validate_session_id(session_id: str) -> None:
    """Reject session IDs with path traversal characters."""
    if ".." in session_id or "/" in session_id or "\\" in session_id:
        raise ValueError(f"Invalid session_id: {session_id!r}")


def _load_session(session_id: str) -> tuple[Path, dict]:
    """Load a phased investigation session — checks in-memory first, then disk."""
    _validate_session_id(session_id)
    with _pending_lock:
        if session_id in _pending_sessions:
            path, context, _ts = _pending_sessions[session_id]
            _pending_sessions[session_id] = (path, context, time.monotonic())
            return path, context
    data_dir = OUTPUT_ROOT / "collected-data"
    data_path = data_dir / f"{session_id}.json"
    if not data_path.exists():
        raise FileNotFoundError(f"Session {session_id} not found at {data_path}")
    try:
        return data_path, json.loads(data_path.read_text())
    except json.JSONDecodeError as e:
        raise ValueError(f"Session {session_id} has corrupted data: {e}") from e


def _save_session(data_path: Path, context: dict, steps: list[dict]) -> None:
    """Append steps to session and persist to disk.

    If the session was pending (in-memory only), this promotes it to disk.
    """
    summary = context.setdefault("collection_summary", {})
    existing = list(summary.get("steps", []))
    existing.extend(steps)
    summary["steps"] = existing
    data_path.parent.mkdir(parents=True, exist_ok=True)
    data_path.write_text(json.dumps(context, indent=2, default=str))
    with _pending_lock:
        _pending_sessions.pop(data_path.stem, None)


def _create_session(service_name: str, title: str, context: dict) -> tuple[str, Path]:
    """Create a new in-memory session. Returns (session_id, data_path).

    The session is held in _pending_sessions until the first _save_session call
    promotes it to disk, avoiding orphaned stub files from abandoned preflights.
    """
    from arbiter.core.models import slugify

    data_dir = OUTPUT_ROOT / "collected-data"
    data_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now(UTC).strftime("%Y-%m-%d")
    title = title.strip() if title else ""
    if title:
        slug = slugify(title, strip_leading_date=True)
    else:
        ts = datetime.now(UTC).strftime("%H%M%S")
        slug = f"{slugify(service_name)}-{ts}"
    if not slug:
        ts = datetime.now(UTC).strftime("%H%M%S")
        slug = f"{slugify(service_name)}-{ts}"
    if title:
        context["title"] = title
    session_id = f"{date_str}-{slug}"
    data_path = data_dir / f"{session_id}.json"
    with _pending_lock:
        if data_path.exists() or session_id in _pending_sessions:
            base = data_path.stem
            i = 2
            while (data_dir / f"{base}-{i}.json").exists() or f"{base}-{i}" in _pending_sessions:
                i += 1
            session_id = f"{base}-{i}"
            data_path = data_dir / f"{session_id}.json"
        # Evict stale pending sessions (>1 hour idle) to prevent unbounded growth
        now = time.monotonic()
        if len(_pending_sessions) > 10:
            stale = [sid for sid, (_, _, ts) in _pending_sessions.items() if now - ts > 3600]
            for sid in stale:
                del _pending_sessions[sid]
        _pending_sessions[session_id] = (data_path, context, now)
    return session_id, data_path


def _estimate_duration(dep_count: int, configured_count: int) -> tuple[int, str]:
    """Estimate investigation duration in seconds + human text."""
    base = 15
    dep_time = dep_count * 5
    aux_time = 10
    total = base + dep_time + aux_time
    parts = []
    if dep_count:
        parts.append(f"{dep_count} upstream {'dependency' if dep_count == 1 else 'dependencies'}")
    parts.append(f"{configured_count} sources")
    return total, f"~{total} seconds ({', '.join(parts)})"


# ---------------------------------------------------------------------------
# Tool: Gather incident context (single-pass, calls shared _impl functions)
# ---------------------------------------------------------------------------
@mcp.tool()
def gather_incident_context(
    service_name: str,
    time_range: str = "2h",
    from_time: str = "",
    to_time: str = "",
    severity: str = "P2",
    conversation: str = "",
    alert_text: str = "",
    title: str = "",
    env: str = "production",
) -> str:
    """Collect all incident data from every available source in a single pass.

    Collects: Datadog logs + APM traces + database errors + UUID correlation,
    Sentry issues, GCP logs, OpsGenie alerts, git deploys, blast radius.

    Args:
        service_name: Primary affected service (e.g. "flags", "datafile-build-service")
        time_range: How far back to look (e.g. "1h", "2h", "6h")
        from_time: Absolute start time (ISO 8601), overrides time_range
        to_time: Absolute end time (ISO 8601)
        severity: Incident severity (P1-P4)
        conversation: Pasted incident thread/conversation
        alert_text: Pasted OpsGenie/PagerDuty alert text
        title: Incident title (used for filename to match report name)
        env: Environment (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
    """
    import time

    gather_start = time.time()

    preflight = _preflight_impl(
        service_name, time_range, from_time, to_time, env, conversation, alert_text
    )
    context = preflight["context"]
    context["severity"] = severity
    if alert_text:
        context["alert"] = alert_text

    if not title and (alert_text or conversation):
        from arbiter.collectors.manual import derive_title_from_text

        title = derive_title_from_text(
            alert_text=alert_text, conversation=conversation, service_name=service_name
        )

    dd_env = preflight["dd_env"]
    dd_service = preflight["dd_service"]
    dd_kwargs = preflight["dd_kwargs"]
    infra = preflight["infra"]
    transitive_upstream = preflight["transitive_upstream"]

    steps: list[dict] = []

    try:
        dd = DatadogCollector()
        if not dd.is_configured():
            steps.append({"step": "Datadog", "status": "skipped", "reason": "not configured"})
        else:
            steps.extend(_collect_primary_impl(dd, dd_service, time_range, context, dd_kwargs))
            steps.extend(
                _collect_dependency_impl(
                    dd, service_name, time_range, context, dd_kwargs, transitive_upstream
                )
            )
    except Exception as e:
        is_rate_limit = "429" in str(e) or "rate" in str(e).lower()
        if is_rate_limit:
            import time as _time

            delay = min(getattr(dd, "recommended_delay", lambda: 30)(), 60)
            logger.warning("Datadog rate-limited in gather, retrying in %ds: %s", delay, e)
            _time.sleep(delay)
            try:
                steps.extend(_collect_primary_impl(dd, dd_service, time_range, context, dd_kwargs))
                steps.extend(
                    _collect_dependency_impl(
                        dd, service_name, time_range, context, dd_kwargs, transitive_upstream
                    )
                )
            except Exception as retry_err:
                context["datadog_error"] = str(retry_err)
                context["primary_collection_failed"] = True
                steps.append(
                    {"step": "Datadog", "status": "error", "error": f"retry failed: {retry_err}"}
                )
        else:
            context["datadog_error"] = str(e)
            context["primary_collection_failed"] = True
            steps.append({"step": "Datadog", "status": "error", "error": str(e)})

    steps.extend(
        _collect_auxiliary_impl(
            service_name, time_range, from_time, to_time, dd_env, context, infra
        )
    )

    return _finalize_context_impl(service_name, context, steps, conversation, gather_start, title)


# ---------------------------------------------------------------------------
# Phased investigation tools — progressive data collection with narration
# ---------------------------------------------------------------------------
@mcp.tool()
def preflight_investigation(
    service_name: str,
    time_range: str = "2h",
    from_time: str = "",
    to_time: str = "",
    severity: str = "P2",
    conversation: str = "",
    alert_text: str = "",
    title: str = "",
    env: str = "production",
) -> str:
    """Identify the service, its connections, and available data sources before collecting data.

    Call this first. Returns session_id for subsequent collect_* phases.
    Zero API calls — all data from local service graph.

    Args:
        service_name: Primary affected service (e.g. "flags", "datafile-build-service")
        time_range: How far back to look (e.g. "1h", "2h", "6h")
        from_time: Absolute start time (ISO 8601), overrides time_range
        to_time: Absolute end time (ISO 8601)
        severity: Incident severity (P1-P4)
        conversation: Pasted incident thread/conversation
        alert_text: Pasted OpsGenie/PagerDuty alert text
        title: Incident title (used for filename to match report name)
        env: Environment (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
    """
    try:
        preflight = _preflight_impl(
            service_name, time_range, from_time, to_time, env, conversation, alert_text
        )
    except Exception as e:
        return json.dumps({"error": f"Preflight failed: {e}"})

    context = preflight["context"]
    context["severity"] = severity
    if alert_text:
        context["alert"] = alert_text

    if not title and (alert_text or conversation):
        from arbiter.collectors.manual import derive_title_from_text

        title = derive_title_from_text(
            alert_text=alert_text, conversation=conversation, service_name=service_name
        )

    infra = preflight["infra"]
    transitive_upstream = preflight["transitive_upstream"]

    configured_sources: list[str] = []
    skipped_sources: list[str] = []

    for name, cls in [
        ("Datadog", DatadogCollector),
        ("Sentry", SentryCollector),
        ("GCP", GCPCollector),
        ("OpsGenie", OpsGenieCollector),
        ("GitHub", GitHubCollector),
    ]:
        try:
            if cls().is_configured():
                configured_sources.append(name)
            else:
                skipped_sources.append(name)
        except Exception:
            skipped_sources.append(name)
    configured_sources.append("Git")

    enrichment_hints = []
    if ENRICHMENT_PROVIDERS:
        with contextlib.suppress(Exception):
            enrichment_hints = get_enrichment_hints(service_name, ENRICHMENT_PROVIDERS)
        for provider in ENRICHMENT_PROVIDERS:
            if hasattr(provider, "warm"):
                with contextlib.suppress(Exception):
                    provider.warm()

    dep_count = len(transitive_upstream)
    duration_seconds, duration_text = _estimate_duration(dep_count, len(configured_sources))

    try:
        session_id, data_path = _create_session(service_name, title, context)
    except Exception as e:
        return json.dumps({"error": f"Session creation failed: {e}"})

    dep_names = [d["service"] for d in transitive_upstream]

    return json.dumps(
        {
            "session_id": session_id,
            "collected_data_path": str(data_path),
            "service": service_name,
            "environment": preflight["dd_env"],
            "datadog_service": preflight["dd_service"],
            "infrastructure_profile": infra,
            "message_queues": infra.get("message_queues", []),
            "dependency_count": dep_count,
            "dependency_names": dep_names,
            "configured_sources": configured_sources,
            "skipped_sources": skipped_sources,
            "jira_project": get_jira_project(service_name, GRAPH),
            "atlassian_cloud_id": get_jira_cloud_id(),
            "enrichment_hints": enrichment_hints,
            "estimated_duration_seconds": duration_seconds,
            "estimated_duration": duration_text,
        },
        indent=2,
        default=str,
    )


@mcp.tool()
def collect_primary_signals(
    session_id: str,
    service_name: str,
    time_range: str = "2h",
    from_time: str = "",
    to_time: str = "",
    env: str = "production",
) -> str:
    """Search for errors, failed requests, and database issues on the service.

    Phase 1 of phased investigation. Takes session_id from preflight_investigation.

    Args:
        session_id: Session ID from preflight_investigation
        service_name: Primary affected service
        time_range: How far back to look (e.g. "1h", "2h", "6h")
        from_time: Absolute start time (ISO 8601), overrides time_range
        to_time: Absolute end time (ISO 8601)
        env: Environment (default: "production")
    """
    try:
        data_path, context = _load_session(session_id)
    except (FileNotFoundError, ValueError) as e:
        return json.dumps({"error": str(e)})

    dd_service = context.get("datadog_service_name", get_datadog_service(service_name, GRAPH))
    dd_env = context.get("environment", resolve_datadog_environment(env))
    dd_kwargs: dict = {"env": dd_env}
    if from_time:
        dd_kwargs["from_time"] = from_time
        dd_kwargs["to_time"] = to_time or "now"
    elif context.get("time_range", {}).get("from", "").startswith("20"):
        dd_kwargs["from_time"] = context["time_range"]["from"]
        to_val = context["time_range"].get("to", "now")
        if to_val != "now":
            dd_kwargs["to_time"] = to_val

    try:
        dd = DatadogCollector()
        if not dd.is_configured():
            steps = [{"step": "Datadog", "status": "skipped", "reason": "not configured"}]
            _save_session(data_path, context, steps)
            return json.dumps(
                {
                    "session_id": session_id,
                    "collected_data_path": str(data_path),
                    "signals": {"status": "skipped", "reason": "Datadog not configured"},
                    "steps": steps,
                },
                indent=2,
                default=str,
            )

        steps = _collect_primary_impl(dd, dd_service, time_range, context, dd_kwargs)
    except Exception as e:
        # Retry once on rate limits (429) after a delay
        is_rate_limit = "429" in str(e) or "rate" in str(e).lower()
        if is_rate_limit:
            import time as _time

            delay = min(getattr(dd, "recommended_delay", lambda: 30)(), 60)
            logger.warning("Primary signals rate-limited, retrying in %ds: %s", delay, e)
            _time.sleep(delay)
            try:
                steps = _collect_primary_impl(dd, dd_service, time_range, context, dd_kwargs)
            except Exception as retry_err:
                context["datadog_error"] = str(retry_err)
                context["primary_collection_failed"] = True
                steps = [
                    {"step": "Datadog", "status": "error", "error": f"retry failed: {retry_err}"}
                ]
        else:
            context["datadog_error"] = str(e)
            context["primary_collection_failed"] = True
            steps = [{"step": "Datadog", "status": "error", "error": str(e)}]

    _save_session(data_path, context, steps)

    # Compute signal summary
    traces = context.get("datadog_traces", [])
    error_traces = [
        t
        for t in traces
        if str(t.get("status_code", "")).startswith(("4", "5")) or t.get("error_type")
    ]
    total = len(traces)
    error_count = len(error_traces)
    error_rate = round(error_count / total, 3) if total > 0 else 0.0

    endpoint_counts: dict[str, int] = {}
    for t in error_traces:
        ep = t.get("http_path") or t.get("endpoint") or ""
        if ep:
            endpoint_counts[ep] = endpoint_counts.get(ep, 0) + 1
    top_endpoints = sorted(endpoint_counts.items(), key=lambda x: -x[1])[:3]

    error_patterns: dict[str, int] = {}
    for t in error_traces:
        pattern = t.get("error_type") or str(t.get("status_code", ""))
        error_patterns[pattern] = error_patterns.get(pattern, 0) + 1
    top_patterns = sorted(error_patterns.items(), key=lambda x: -x[1])[:3]

    signals = {
        "trace_count": total,
        "error_trace_count": error_count,
        "error_rate": error_rate,
        "log_count": context.get("datadog_log_count", 0),
        "db_error_count": len(context.get("datadog_db_errors", [])),
        "uuid_count": len(context.get("extracted_uuids", [])),
        "top_endpoints": [{"endpoint": ep, "count": c} for ep, c in top_endpoints],
        "top_error_patterns": [{"pattern": p, "count": c} for p, c in top_patterns],
    }

    return json.dumps(
        {
            "session_id": session_id,
            "collected_data_path": str(data_path),
            "signals": signals,
            "steps": steps,
        },
        indent=2,
        default=str,
    )


@mcp.tool()
def collect_dependency_signals(
    session_id: str,
    service_name: str,
    time_range: str = "2h",
    from_time: str = "",
    to_time: str = "",
    env: str = "production",
) -> str:
    """Check the services this one depends on for related errors.

    Phase 2 of phased investigation. Duration scales with dependency count.

    Args:
        session_id: Session ID from preflight_investigation
        service_name: Primary affected service
        time_range: How far back to look (e.g. "1h", "2h", "6h")
        from_time: Absolute start time (ISO 8601), overrides time_range
        to_time: Absolute end time (ISO 8601)
        env: Environment (default: "production")
    """
    try:
        data_path, context = _load_session(session_id)
    except (FileNotFoundError, ValueError) as e:
        return json.dumps({"error": str(e)})

    dd_env = context.get("environment", resolve_datadog_environment(env))
    dd_kwargs: dict = {"env": dd_env}
    if from_time:
        dd_kwargs["from_time"] = from_time
        dd_kwargs["to_time"] = to_time or "now"
    elif context.get("time_range", {}).get("from", "").startswith("20"):
        dd_kwargs["from_time"] = context["time_range"]["from"]
        to_val = context["time_range"].get("to", "now")
        if to_val != "now":
            dd_kwargs["to_time"] = to_val

    transitive_upstream = get_transitive_dependencies(
        service_name, GRAPH, max_depth=2, direction="upstream"
    )

    try:
        dd = DatadogCollector()
        if not dd.is_configured():
            steps = [{"step": "Datadog (deps)", "status": "skipped", "reason": "not configured"}]
            _save_session(data_path, context, steps)
            return json.dumps(
                {
                    "session_id": session_id,
                    "collected_data_path": str(data_path),
                    "signals": {"status": "skipped", "reason": "Datadog not configured"},
                    "steps": steps,
                },
                indent=2,
                default=str,
            )

        steps = _collect_dependency_impl(
            dd, service_name, time_range, context, dd_kwargs, transitive_upstream
        )
    except Exception as e:
        context["datadog_error"] = str(e)
        steps = [{"step": "Datadog (deps)", "status": "error", "error": str(e)}]

    _save_session(data_path, context, steps)

    # Compute dependency signal summary
    upstream_traces = context.get("upstream_traces", {})
    deps_with_errors = [svc for svc, traces in upstream_traces.items() if traces]
    upstream_db = context.get("upstream_db_errors", {})
    deps_with_db_errors = [svc for svc, errs in upstream_db.items() if errs]
    cross_logs = context.get("cross_service_logs", {})
    uuid_corr = context.get("uuid_correlation", {})

    dep_status: list[dict] = []
    for dep in transitive_upstream:
        svc = dep["service"]
        dep_status.append(
            {
                "service": svc,
                "has_errors": svc in deps_with_errors,
                "error_trace_count": len(upstream_traces.get(svc, [])),
                "has_db_errors": svc in deps_with_db_errors,
            }
        )

    signals = {
        "dependency_count": len(transitive_upstream),
        "dependencies_with_errors": deps_with_errors,
        "dependencies_with_db_errors": deps_with_db_errors,
        "cross_service_log_count": sum(len(v) for v in cross_logs.values()),
        "uuid_matches": len(uuid_corr),
        "dependency_status": dep_status,
    }

    return json.dumps(
        {
            "session_id": session_id,
            "collected_data_path": str(data_path),
            "signals": signals,
            "steps": steps,
        },
        indent=2,
        default=str,
    )


@mcp.tool()
def collect_auxiliary_signals(
    session_id: str,
    service_name: str,
    time_range: str = "2h",
    from_time: str = "",
    to_time: str = "",
    severity: str = "P2",
    conversation: str = "",
    alert_text: str = "",
    env: str = "production",
) -> str:
    """Collect data from Sentry, GCP, GitHub, and OpsGenie to complete the picture.

    Phase 3 (final) of phased investigation. Returns the investigation brief —
    identical structure to gather_incident_context.

    Args:
        session_id: Session ID from preflight_investigation
        service_name: Primary affected service
        time_range: How far back to look (e.g. "1h", "2h", "6h")
        from_time: Absolute start time (ISO 8601), overrides time_range
        to_time: Absolute end time (ISO 8601)
        severity: Incident severity (P1-P4)
        conversation: Pasted incident thread/conversation
        alert_text: Pasted OpsGenie/PagerDuty alert text
        env: Environment (default: "production")
    """
    import time as _time

    try:
        data_path, context = _load_session(session_id)
    except (FileNotFoundError, ValueError) as e:
        return json.dumps({"error": str(e)})

    dd_env = context.get("environment", resolve_datadog_environment(env))
    infra = context.get("infrastructure_profile", get_infrastructure_profile(service_name, GRAPH))

    if severity and severity != context.get("severity"):
        context["severity"] = severity
    if alert_text and "alert" not in context:
        context["alert"] = alert_text

    aux_steps = _collect_auxiliary_impl(
        service_name, time_range, from_time, to_time, dd_env, context, infra
    )

    # Accumulate all steps from prior phases + this phase
    prior_steps = context.get("collection_summary", {}).get("steps", [])
    all_steps = prior_steps + aux_steps

    # Use the session creation time as gather_start for duration calculation
    generated_at = context.get("generated_at", "")
    if generated_at:
        try:
            from dateutil import parser as _dp

            gather_start = _dp.isoparse(generated_at).timestamp()
        except (ValueError, TypeError):
            gather_start = _time.time() - 60
    else:
        gather_start = _time.time() - 60

    # Clear the existing partial collection_summary before finalize rebuilds it
    context.pop("collection_summary", None)

    return _finalize_context_impl(
        service_name,
        context,
        all_steps,
        conversation,
        gather_start,
        context.get("title", ""),
        output_path=data_path,
    )


# ---------------------------------------------------------------------------
# Tool: Fetch Datadog logs
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_datadog_logs(
    service: str = "",
    query: str = "status:error",
    time_range: str = "2h",
    env: str = "production",
    limit: int = 50,
    detail_level: str = "summary",
) -> str:
    """Fetch error logs from Datadog for a service.

    Args:
        service: Service name (e.g. "flags", "frontdoor")
        query: Datadog log query (default: "status:error")
        time_range: How far back (e.g. "1h", "2h", "6h")
        env: Environment (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
        limit: Max entries (default: 50)
        detail_level: "summary" (default) or "full"
    """
    try:
        dd = DatadogCollector()
        if not dd.is_configured():
            return _dd_not_configured_error()
        dd_env = resolve_datadog_environment(env)
        logs = dd.collect_logs(
            service=service or None,
            query=query,
            time_range=time_range,
            env=dd_env,
            limit=limit,
        )

        if detail_level == "summary":
            return json.dumps(_summarize_log_entries(logs), indent=2, default=str)

        return json.dumps(
            {"total": len(logs), "logs": [_serialize(l) for l in logs], "detail_level": "full"},
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Datadog error summary
# ---------------------------------------------------------------------------
@mcp.tool()
def fetch_datadog_error_summary(
    service: str,
    time_range: str = "2h",
    env: str = "production",
) -> str:
    """Get a summary of errors grouped by pattern for a service from Datadog.

    Args:
        service: Service name
        time_range: How far back (e.g. "1h", "2h", "6h")
        env: Environment (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
    """
    try:
        dd = DatadogCollector()
        dd_env = resolve_datadog_environment(env)
        summary = dd.get_error_summary(service=service, time_range=time_range, env=dd_env)
        return json.dumps(summary, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Cross-service scan
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_cross_service_errors(
    primary_service: str,
    time_range: str = "2h",
    env: str = "production",
    detail_level: str = "summary",
) -> str:
    """Scan the service and all related services for errors.

    Args:
        primary_service: The service experiencing the incident
        time_range: How far back (e.g. "1h", "2h", "6h")
        env: Environment (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
        detail_level: "summary" (default) or "full"
    """
    try:
        dd = DatadogCollector()
        dd_env = resolve_datadog_environment(env)
        related = get_related_services(primary_service, GRAPH)
        all_services = [primary_service, *related]

        results = dd.collect_logs_multi(
            services=all_services,
            time_range=time_range,
            env=dd_env,
            limit_per_service=20,
        )

        if detail_level == "summary":
            services_with_errors = []
            services_clean = []
            for svc, logs in results.items():
                if logs:
                    error_types: dict[str, int] = {}
                    for entry in logs:
                        msg = entry.message[:100] if entry.message else "unknown"
                        error_types[msg] = error_types.get(msg, 0) + 1
                    top_error = max(error_types, key=error_types.get) if error_types else "unknown"
                    services_with_errors.append(
                        {"service": svc, "error_count": len(logs), "top_error_type": top_error}
                    )
                else:
                    services_clean.append(svc)

            return json.dumps(
                {
                    "primary_service": primary_service,
                    "services_checked": len(all_services),
                    "services_with_errors": services_with_errors,
                    "services_clean": services_clean,
                    "detail_level": "summary",
                },
                indent=2,
                default=str,
            )

        summary = {}
        for svc, logs in results.items():
            summary[svc] = {
                "error_count": len(logs),
                "sample_errors": [l.message[:200] for l in logs[:5]],
            }

        return json.dumps(
            {
                "primary_service": primary_service,
                "services_checked": all_services,
                "summary": summary,
                "detail_level": "full",
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Datadog APM traces
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_datadog_traces(
    service: str,
    time_range: str = "2h",
    env: str = "production",
    status_code: str = "500",
    limit: int = 20,
    from_time: str = "",
    to_time: str = "",
    tag_filter: str = "",
    detail_level: str = "summary",
) -> str:
    """Fetch error traces from Datadog — failed requests with error details and stack traces.

    Use this to find WHY a service returned errors. Includes error type,
    error message, and stack trace from the server side.

    Args:
        service: Service name (will be resolved to Datadog name)
        time_range: How far back (e.g. "1h", "2h", "6h")
        env: Environment (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
        status_code: HTTP status code to filter (default: "500")
        limit: Max traces (default: 20)
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
        tag_filter: Additional Datadog query filter (e.g. "-@http.useragent:libcurl*" to exclude noise)
        detail_level: "summary" (default) or "full"
    """
    try:
        dd = DatadogCollector()
        dd_service = get_datadog_service(service, GRAPH)
        dd_env = resolve_datadog_environment(env)
        traces = dd.search_traces(
            service=dd_service,
            time_range=time_range,
            env=dd_env,
            status_code=status_code,
            limit=limit,
            from_time=from_time or None,
            to_time=to_time or None,
            tag_filter=tag_filter,
        )

        if detail_level == "summary":
            error_traces = [
                t
                for t in traces
                if t.get("error_type")
                or t.get("error_message")
                or int(t.get("status_code", 0)) >= 400
            ]
            endpoint_counts: dict[str, int] = {}
            error_type_counts: dict[str, int] = {}
            for t in error_traces:
                ep = t.get("http_path") or t.get("endpoint") or "unknown"
                endpoint_counts[ep] = endpoint_counts.get(ep, 0) + 1
                et = t.get("error_type") or "unknown"
                error_type_counts[et] = error_type_counts.get(et, 0) + 1

            top_endpoints = sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            top_error_types = sorted(error_type_counts.items(), key=lambda x: x[1], reverse=True)[
                :3
            ]

            representative = None
            if error_traces:
                rep = error_traces[0]
                stack = rep.get("error_stack") or ""
                stack_lines = stack.split("\n")
                stack_top = "\n".join(stack_lines[:15]) if len(stack_lines) > 15 else stack
                representative = {
                    "trace_id": rep.get("trace_id"),
                    "endpoint": rep.get("http_path") or rep.get("endpoint"),
                    "error_type": rep.get("error_type"),
                    "error_message": rep.get("error_message"),
                    "stack_top": stack_top if stack_top else None,
                }

            result = {
                "total": len(traces),
                "error_count": len(error_traces),
                "error_rate": (
                    f"{round(len(error_traces) / len(traces) * 100)}%" if traces else "0%"
                ),
                "top_endpoints": [{"endpoint": ep, "error_count": c} for ep, c in top_endpoints],
                "top_error_types": [{"error_type": et, "count": c} for et, c in top_error_types],
                "representative_error": representative,
                "detail_level": "summary",
            }
            return json.dumps(result, indent=2, default=str)

        return json.dumps(
            {"total": len(traces), "traces": traces, "detail_level": "full"},
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Fetch trace spans (child span inspection)
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_trace_spans(
    trace_id: str,
    time_range: str = "2h",
    from_time: str = "",
    to_time: str = "",
    collected_data_path: str = "",
    detail_level: str = "summary",
) -> str:
    """Inspect a request's full execution path to find where exactly it failed.

    Parent spans often have empty error details. The actual error (TypeError,
    ABORTED, etc.) lives in child spans. Use this when error traces have no
    error_type or error_message.

    Args:
        trace_id: The trace ID to inspect (from fetch_datadog_traces results)
        time_range: How far back (e.g. "1h", "2h", "6h")
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
        collected_data_path: Path to collected data file (for investigation tracking)
        detail_level: "summary" (default) or "full"
    """
    try:
        dd = DatadogCollector()
        spans = dd.search_trace_spans(
            trace_id=trace_id,
            time_range=time_range,
            from_time=from_time or None,
            to_time=to_time or None,
        )
        error_spans = [s for s in spans if s.get("is_error")]
        services = sorted({s.get("service", "") for s in spans if s.get("service")})

        _record_investigation_action(
            collected_data_path,
            "child_spans_inspected",
            trace_id=trace_id,
            total_spans=len(spans),
            error_spans=len(error_spans),
        )

        if detail_level == "summary":
            error_types = sorted(
                {s.get("error_type", "unknown") for s in error_spans if s.get("error_type")}
            )

            deepest_error = None
            if error_spans:
                deepest = max(
                    error_spans,
                    key=lambda s: s.get("duration_ms", 0) if s.get("error_type") else 0,
                    default=error_spans[0],
                )
                stack = deepest.get("error_stack") or ""
                stack_lines = stack.split("\n")
                stack_top = "\n".join(stack_lines[:15]) if len(stack_lines) > 15 else stack
                deepest_error = {
                    "service": deepest.get("service"),
                    "resource": deepest.get("resource_name"),
                    "error_type": deepest.get("error_type"),
                    "error_message": deepest.get("error_message"),
                    "stack_top": stack_top if stack_top else None,
                }

            return json.dumps(
                {
                    "trace_id": trace_id,
                    "total_spans": len(spans),
                    "error_spans": len(error_spans),
                    "services": services,
                    "error_types": error_types,
                    "deepest_error": deepest_error,
                    "detail_level": "summary",
                },
                indent=2,
                default=str,
            )

        return json.dumps(
            {
                "trace_id": trace_id,
                "total_spans": len(spans),
                "error_spans": len(error_spans),
                "services": services,
                "spans": spans,
                "detail_level": "full",
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Search by request UUID
# ---------------------------------------------------------------------------
@mcp.tool()
def search_request_uuid(
    uuid: str,
    time_range: str = "2h",
    from_time: str = "",
    to_time: str = "",
) -> str:
    """Trace a specific request ID across all services to find where it failed.

    When a service returns a 500 with a UUID, use this to find the
    server-side error that caused it.

    Args:
        uuid: The request UUID from the error response
        time_range: How far back (e.g. "1h", "2h", "6h")
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
    """
    try:
        dd = DatadogCollector()
        logs = dd.search_by_uuid(
            uuid=uuid,
            time_range=time_range,
            from_time=from_time or None,
            to_time=to_time or None,
        )
        return json.dumps(
            {"uuid": uuid, "total": len(logs), "logs": [_serialize(l) for l in logs]},
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Database error search
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_database_errors(
    service: str,
    time_range: str = "2h",
    env: str = "production",
    from_time: str = "",
    to_time: str = "",
    detail_level: str = "summary",
) -> str:
    """Search for database errors — failed queries, deadlocks, and connection failures.

    Args:
        service: Service name
        time_range: How far back (e.g. "1h", "2h", "6h")
        env: Environment (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
        detail_level: "summary" (default) or "full"
    """
    try:
        dd = DatadogCollector()
        dd_service = get_datadog_service(service, GRAPH)
        dd_env = resolve_datadog_environment(env)
        logs = dd.search_database_errors(
            service=dd_service,
            time_range=time_range,
            env=dd_env,
            from_time=from_time or None,
            to_time=to_time or None,
        )

        if detail_level == "summary":
            error_types: dict[str, int] = {}
            tables: set[str] = set()
            for entry in logs:
                msg = entry.message or ""
                for keyword in (
                    "ABORTED",
                    "DEADLINE_EXCEEDED",
                    "UNAVAILABLE",
                    "ALREADY_EXISTS",
                    "NOT_FOUND",
                    "PERMISSION_DENIED",
                    "RESOURCE_EXHAUSTED",
                ):
                    if keyword in msg.upper():
                        error_types[keyword] = error_types.get(keyword, 0) + 1
                        break
                else:
                    short = msg[:80] if msg else "unknown"
                    error_types[short] = error_types.get(short, 0) + 1
                for field in (entry.metadata or {}).values():
                    if isinstance(field, str) and ("table" in field.lower() or "." in field):
                        tables.add(field)

            representative = None
            if logs:
                representative = logs[0].message[:300] if logs[0].message else None

            return json.dumps(
                {
                    "total": len(logs),
                    "error_types": dict(
                        sorted(error_types.items(), key=lambda x: x[1], reverse=True)[:5]
                    ),
                    "affected_tables": sorted(tables) if tables else [],
                    "representative": representative,
                    "detail_level": "summary",
                },
                indent=2,
                default=str,
            )

        return json.dumps(
            {"total": len(logs), "logs": [_serialize(l) for l in logs], "detail_level": "full"},
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Datadog metrics (timeseries)
# ---------------------------------------------------------------------------
@mcp.tool()
def fetch_datadog_metrics(
    query: str,
    time_range: str = "2h",
    from_time: str = "",
    to_time: str = "",
) -> str:
    """Fetch metrics over time — request rates, latency, error rates, and custom queries.

    Returns timeseries points for the given metric query. Metric names vary
    by framework (e.g. trace.flask.request.hits vs trace.http.request.hits).

    Args:
        query: Datadog metric query (e.g. "sum:trace.http.request.hits{service:cmab}.as_rate()")
        time_range: How far back (e.g. "1h", "2h", "6h")
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
    """
    try:
        dd = DatadogCollector()
        result = dd.query_metrics(
            query=query,
            time_range=time_range,
            from_time=from_time or None,
            to_time=to_time or None,
        )
        return json.dumps(
            {
                "query": query,
                "time_range": time_range,
                "series_count": len(result),
                "series": result,
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Datadog monitors
# ---------------------------------------------------------------------------
@mcp.tool()
def fetch_datadog_monitors(
    service: str,
    env: str = "production",
    include_dependencies: bool = False,
    detail_level: str = "summary",
) -> str:
    """Check Datadog monitors for a service — highlights any that are currently alerting.

    Args:
        service: Service name
        env: Environment (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
        include_dependencies: Also fetch monitors for transitive upstream services
        detail_level: "summary" (default) or "full"
    """
    try:
        dd = DatadogCollector()
        if not dd.is_configured():
            return _dd_not_configured_error()

        dd_service = get_datadog_service(service, GRAPH)
        dd_env = resolve_datadog_environment(env)
        monitor_query = f"tag:service:{dd_service} tag:env:{dd_env}"
        monitors = dd.search_monitors(query=monitor_query)

        result: dict = {"service": service, "datadog_service": dd_service, "env": dd_env}

        if include_dependencies:
            deps = get_transitive_dependencies(service, GRAPH, max_depth=2)
            dep_monitors: dict[str, list[dict]] = {}
            for dep in deps:
                dep_dd = get_datadog_service(dep["service"], GRAPH)
                dep_monitors[dep["service"]] = dd.search_monitors(
                    query=f"tag:service:{dep_dd} tag:env:{dd_env}"
                )
            result["dependency_monitors"] = {
                svc: {
                    "total": len(mons),
                    "alerting": len([m for m in mons if m["overall_state"] in ("Alert", "Warn")]),
                }
                for svc, mons in dep_monitors.items()
            }

        if detail_level == "summary":
            alerting = [m for m in monitors if m["overall_state"] in ("Alert", "Warn")]
            result.update(
                {
                    "total": len(monitors),
                    "ok": len([m for m in monitors if m["overall_state"] == "OK"]),
                    "alerting": len(alerting),
                    "alert_names": [m["name"] for m in alerting],
                }
            )
        else:
            result.update({"total": len(monitors), "monitors": monitors})

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Datadog SLOs
# ---------------------------------------------------------------------------
@mcp.tool()
def fetch_datadog_slos(
    service: str,
    env: str = "production",
    detail_level: str = "summary",
) -> str:
    """Check service level objectives (SLOs) — current status, targets, and remaining error budget.

    Args:
        service: Service name
        env: Environment (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
        detail_level: "summary" (default) or "full"
    """
    try:
        dd = DatadogCollector()
        if not dd.is_configured():
            return _dd_not_configured_error()

        dd_service = get_datadog_service(service, GRAPH)
        dd_env = resolve_datadog_environment(env)
        slos = dd.search_slos(service=dd_service, query=f"env:{dd_env}")

        result: dict = {
            "service": service,
            "datadog_service": dd_service,
            "env": dd_env,
            "total": len(slos),
        }

        if detail_level == "summary":
            summary_items = []
            for slo in slos:
                item: dict = {"name": slo["name"], "type": slo["type"]}
                for th in slo.get("thresholds", []):
                    item["target"] = th.get("target_display", th.get("target"))
                    item["sli_value"] = th.get("sli_value")
                    item["error_budget_remaining"] = th.get("error_budget_remaining")
                    item["status"] = th.get("status", "unknown")
                    break
                summary_items.append(item)
            result["slos"] = summary_items
        else:
            result["slos"] = slos

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Datadog log analytics
# ---------------------------------------------------------------------------

_LOG_ANALYTICS_TEMPLATES: dict[str, dict] = {
    "errors_by_endpoint": {
        "group_by": ["@http.url_details.path"],
        "compute": [{"type": "total", "aggregation": "count"}],
    },
    "errors_by_pod": {
        "group_by": ["pod_name"],
        "compute": [{"type": "total", "aggregation": "count"}],
    },
    "errors_by_status": {
        "group_by": ["@http.status_code"],
        "compute": [{"type": "total", "aggregation": "count"}],
    },
    "errors_by_version": {
        "group_by": ["version"],
        "compute": [{"type": "total", "aggregation": "count"}],
    },
    "latency_by_endpoint": {
        "group_by": ["@http.url_details.path"],
        "compute": [
            {"type": "total", "aggregation": "avg", "metric": "@duration"},
            {"type": "total", "aggregation": "pc95", "metric": "@duration"},
            {"type": "total", "aggregation": "max", "metric": "@duration"},
        ],
    },
}


@mcp.tool()
@_track_tool_calls
def analyze_datadog_logs(
    service: str,
    time_range: str = "2h",
    env: str = "production",
    template: str = "errors_by_endpoint",
    group_by: str = "",
    query: str = "status:error",
    from_time: str = "",
    to_time: str = "",
    detail_level: str = "summary",
) -> str:
    """Break down errors by endpoint, pod, status code, or version to find patterns.

    Args:
        service: Service name
        time_range: How far back (e.g. "1h", "2h", "6h")
        env: Environment (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
        template: Pre-built aggregation template or "custom"
        group_by: Comma-separated facet names (only used when template="custom")
        query: Datadog log query (default: "status:error")
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
    """
    try:
        dd = DatadogCollector()
        if not dd.is_configured():
            return _dd_not_configured_error()

        dd_service = get_datadog_service(service, GRAPH)
        dd_env = resolve_datadog_environment(env)

        if template == "custom":
            facets = (
                [f.strip() for f in group_by.split(",") if f.strip()]
                if group_by
                else ["@http.url_details.path"]
            )
            compute_spec = [{"type": "total", "aggregation": "count"}]
        elif template in _LOG_ANALYTICS_TEMPLATES:
            tmpl = _LOG_ANALYTICS_TEMPLATES[template]
            facets = tmpl["group_by"]
            compute_spec = tmpl["compute"]
        else:
            return json.dumps(
                {
                    "error": f"Unknown template: {template}",
                    "available_templates": [*_LOG_ANALYTICS_TEMPLATES.keys(), "custom"],
                }
            )

        result = dd.aggregate_logs(
            service=dd_service,
            time_range=time_range,
            env=dd_env,
            from_time=from_time or None,
            to_time=to_time or None,
            group_by=facets,
            compute=compute_spec,
            query=query,
        )

        result["service"] = service
        result["template"] = template

        if result.get("error"):
            return json.dumps(result, indent=2, default=str)

        if detail_level == "summary":
            buckets = result.get("buckets", [])
            top_values = []
            for b in sorted(
                buckets, key=lambda x: x.get("computes", {}).get("c0", 0), reverse=True
            )[:5]:
                by_vals = b.get("by", {})
                label = next(iter(by_vals.values()), "unknown") if by_vals else "unknown"
                count = b.get("computes", {}).get("c0", 0)
                top_values.append({"value": label, "count": count})
            return json.dumps(
                {
                    "service": service,
                    "template": template,
                    "facet": ", ".join(facets),
                    "total_groups": len(buckets),
                    "top_values": top_values,
                    "detail_level": "summary",
                },
                indent=2,
                default=str,
            )

        result["detail_level"] = "full"
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Datadog Watchdog insights (anomalies + change detection)
# ---------------------------------------------------------------------------
@mcp.tool()
def fetch_datadog_watchdog_insights(
    service: str,
    time_range: str = "2h",
    env: str = "production",
    include_dependencies: bool = False,
    change_only: bool = False,
    from_time: str = "",
    to_time: str = "",
    detail_level: str = "summary",
) -> str:
    """Detect anomalies and unexpected changes in service behavior.

    Args:
        service: Service name
        time_range: How far back (e.g. "1h", "2h", "6h")
        env: Environment (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
        include_dependencies: Also check transitive upstream services
        change_only: If true, only return change detection events (not anomalies)
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
        detail_level: "summary" (default) or "full"
    """
    try:
        dd = DatadogCollector()
        if not dd.is_configured():
            return _dd_not_configured_error()

        dd_service = get_datadog_service(service, GRAPH)
        dd_env = resolve_datadog_environment(env)
        events = dd.search_watchdog_events(
            service=dd_service,
            time_range=time_range,
            env=dd_env,
            from_time=from_time or None,
            to_time=to_time or None,
            change_only=change_only,
        )

        result: dict = {
            "service": service,
            "env": dd_env,
            "change_only": change_only,
            "total": len(events),
        }

        if include_dependencies:
            deps = get_transitive_dependencies(service, GRAPH, max_depth=2)
            dep_events: dict[str, int] = {}
            for dep in deps:
                dep_dd = get_datadog_service(dep["service"], GRAPH)
                dep_evts = dd.search_watchdog_events(
                    service=dep_dd,
                    time_range=time_range,
                    from_time=from_time or None,
                    to_time=to_time or None,
                    change_only=change_only,
                )
                if dep_evts:
                    dep_events[dep["service"]] = len(dep_evts)
            if dep_events:
                result["dependency_events"] = dep_events

        # Cross-reference change events with GitHub deploys (optional)
        if change_only and events:
            try:
                from dateutil import parser as dateutil_parser

                gh = GitHubCollector()
                repo = get_github_repo(service, GRAPH)
                deploys = gh.get_merged_prs(repo, limit=10)
                if deploys:
                    result["deploy_correlations"] = []
                    for evt in events:
                        evt_ts = evt.get("timestamp", "")
                        if not evt_ts:
                            continue
                        try:
                            evt_dt = dateutil_parser.isoparse(str(evt_ts))
                        except (ValueError, TypeError):
                            continue
                        for pr in deploys:
                            pr_ts = pr.get("mergedAt", "") or pr.get("merged_at", "")
                            if not pr_ts:
                                continue
                            try:
                                pr_dt = dateutil_parser.isoparse(str(pr_ts))
                            except (ValueError, TypeError):
                                continue
                            delta_minutes = abs((evt_dt - pr_dt).total_seconds()) / 60
                            if delta_minutes <= 30:
                                result["deploy_correlations"].append(
                                    {
                                        "event_title": evt.get("title", ""),
                                        "pr_number": pr.get("number"),
                                        "pr_title": pr.get("title", ""),
                                        "delta_minutes": round(delta_minutes, 1),
                                    }
                                )
                                break
            except Exception:
                pass

        if detail_level == "summary":
            result["events"] = [
                {
                    "title": e.get("title", ""),
                    "timestamp": e.get("timestamp", ""),
                    "alert_type": e.get("alert_type", ""),
                }
                for e in events
            ]
        else:
            result["events"] = events
            result["detail_level"] = "full"

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Compare Datadog traces (bottleneck analysis + baseline comparison)
# ---------------------------------------------------------------------------
@mcp.tool()
def compare_datadog_traces(
    service: str,
    endpoint: str = "",
    time_range: str = "2h",
    env: str = "production",
    baseline_time: str = "",
    from_time: str = "",
    to_time: str = "",
    detail_level: str = "summary",
) -> str:
    """Compare current request performance against a healthy baseline to spot regressions.

    Args:
        service: Service name
        endpoint: Endpoint/resource to filter traces (optional)
        time_range: How far back for incident window (e.g. "1h", "2h")
        env: Environment (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
        baseline_time: Custom baseline center time (ISO 8601). Defaults to 24h before incident.
        from_time: Absolute start time (ISO 8601) for incident window
        to_time: Absolute end time (ISO 8601) for incident window
        detail_level: "summary" (default) or "full"
    """
    from datetime import datetime as dt
    from datetime import timedelta

    try:
        dd = DatadogCollector()
        if not dd.is_configured():
            return _dd_not_configured_error()

        dd_service = get_datadog_service(service, GRAPH)
        dd_env = resolve_datadog_environment(env)

        # Fetch incident traces
        incident_traces = dd.search_traces(
            service=dd_service,
            time_range=time_range,
            env=dd_env,
            from_time=from_time or None,
            to_time=to_time or None,
            limit=50,
            status_code="",
            resource_name=endpoint,
        )

        # Compute baseline window (24h before incident, or custom)
        if baseline_time:
            baseline_center = dt.fromisoformat(baseline_time.replace("Z", "+00:00"))
            baseline_from = (baseline_center - timedelta(minutes=5)).isoformat()
            baseline_to = (baseline_center + timedelta(minutes=5)).isoformat()
        elif from_time:
            incident_start = dt.fromisoformat(from_time.replace("Z", "+00:00"))
            baseline_from = (incident_start - timedelta(hours=24, minutes=5)).isoformat()
            baseline_to = (incident_start - timedelta(hours=24)).isoformat()
        else:
            baseline_from = None
            baseline_to = None

        baseline_traces = dd.search_traces(
            service=dd_service,
            time_range="10m" if not baseline_from else time_range,
            env=dd_env,
            from_time=baseline_from,
            to_time=baseline_to,
            limit=50,
            status_code="",
            resource_name=endpoint,
        )

        # Analyze differences
        def _span_stats(traces: list[dict]) -> dict:
            if not traces:
                return {"count": 0, "avg_duration_ms": 0, "error_count": 0, "endpoints": {}}
            durations = [t.get("duration_ms", 0) for t in traces]
            error_count = sum(
                1
                for t in traces
                if t.get("error_type") or str(t.get("status_code", "")).startswith(("4", "5"))
            )
            endpoints: dict[str, dict] = {}
            for t in traces:
                ep = t.get("http_path", t.get("endpoint", "unknown"))
                if ep not in endpoints:
                    endpoints[ep] = {"count": 0, "error_count": 0, "total_duration": 0}
                endpoints[ep]["count"] += 1
                endpoints[ep]["total_duration"] += t.get("duration_ms", 0)
                if t.get("error_type") or str(t.get("status_code", "")).startswith(("4", "5")):
                    endpoints[ep]["error_count"] += 1
            for ep_stats in endpoints.values():
                ep_stats["avg_duration_ms"] = (
                    round(ep_stats["total_duration"] / ep_stats["count"], 2)
                    if ep_stats["count"]
                    else 0
                )
                del ep_stats["total_duration"]
            return {
                "count": len(traces),
                "avg_duration_ms": round(sum(durations) / len(durations), 2),
                "error_count": error_count,
                "error_rate": round(error_count / len(traces), 3),
                "endpoints": endpoints,
            }

        incident_stats = _span_stats(incident_traces)
        baseline_stats = _span_stats(baseline_traces)

        # Compute endpoint-level diffs
        changes = []
        all_endpoints = set(
            list(incident_stats["endpoints"].keys()) + list(baseline_stats["endpoints"].keys())
        )
        for ep in all_endpoints:
            inc_ep = incident_stats["endpoints"].get(
                ep, {"count": 0, "error_count": 0, "avg_duration_ms": 0}
            )
            base_ep = baseline_stats["endpoints"].get(
                ep, {"count": 0, "error_count": 0, "avg_duration_ms": 0}
            )
            change: dict = {"endpoint": ep}
            if base_ep["count"] == 0 and inc_ep["count"] > 0:
                change["status"] = "new_in_incident"
            elif inc_ep["count"] == 0 and base_ep["count"] > 0:
                change["status"] = "missing_in_incident"
            else:
                change["status"] = "changed"
                if base_ep["avg_duration_ms"] > 0:
                    change["duration_change"] = round(
                        inc_ep["avg_duration_ms"] - base_ep["avg_duration_ms"], 2
                    )
                    change["duration_ratio"] = (
                        round(inc_ep["avg_duration_ms"] / base_ep["avg_duration_ms"], 2)
                        if base_ep["avg_duration_ms"] > 0
                        else None
                    )
                change["error_change"] = inc_ep["error_count"] - base_ep["error_count"]
            changes.append(change)

        changes.sort(
            key=lambda c: abs(c.get("duration_change", 0)) + abs(c.get("error_change", 0)) * 100,
            reverse=True,
        )

        result: dict = {
            "service": service,
            "incident": {
                "trace_count": incident_stats["count"],
                "avg_duration_ms": incident_stats["avg_duration_ms"],
                "error_rate": incident_stats.get("error_rate", 0),
            },
            "baseline": {
                "trace_count": baseline_stats["count"],
                "avg_duration_ms": baseline_stats["avg_duration_ms"],
                "error_rate": baseline_stats.get("error_rate", 0),
            },
        }

        if detail_level == "summary":
            result["top_changes"] = changes[:5]
            result["detail_level"] = "summary"
        else:
            result["changes"] = changes
            result["incident_traces"] = incident_traces
            result["baseline_traces"] = baseline_traces
            result["detail_level"] = "full"

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Datadog Error Tracking
# ---------------------------------------------------------------------------
@mcp.tool()
def fetch_datadog_error_tracking(
    service: str,
    time_range: str = "2h",
    env: str = "production",
    from_time: str = "",
    to_time: str = "",
    detail_level: str = "summary",
) -> str:
    """Fetch grouped error issues from Datadog Error Tracking for a service.

    Args:
        service: Service name
        time_range: How far back (e.g. "1h", "2h", "6h")
        env: Environment (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
        detail_level: "summary" (default) or "full"
    """
    try:
        dd = DatadogCollector()
        if not dd.is_configured():
            return _dd_not_configured_error()

        dd_service = get_datadog_service(service, GRAPH)
        dd_env = resolve_datadog_environment(env)

        issues = dd.search_error_tracking_issues(
            service=dd_service,
            time_range=time_range,
            env=dd_env,
            from_time=from_time or None,
            to_time=to_time or None,
        )

        # Normalize error signatures for KB comparison
        from arbiter.core.incident_store import normalize_error_message

        for issue in issues:
            msg = issue.get("error_message", "") or issue.get("title", "")
            issue["normalized_signature"] = normalize_error_message(msg)

        # Classify new vs pre-existing based on incident window
        if from_time:
            from dateutil import parser as dateutil_parser

            try:
                incident_start_dt = dateutil_parser.isoparse(from_time)
            except (ValueError, TypeError):
                incident_start_dt = None

            if incident_start_dt:
                for issue in issues:
                    first = issue.get("first_seen", "")
                    if not first:
                        issue["appeared_during_incident"] = False
                        continue
                    try:
                        first_dt = dateutil_parser.isoparse(str(first))
                        issue["appeared_during_incident"] = first_dt >= incident_start_dt
                    except (ValueError, TypeError):
                        issue["appeared_during_incident"] = False

        # Optional Sentry cross-reference
        sentry_overlap: list[str] = []
        try:
            sentry = SentryCollector()
            if sentry.is_configured():
                sentry_issues = sentry.collect_issues(
                    project=service, time_range=time_range, env=dd_env
                )
                sentry_titles = (
                    {i.get("title", "") for i in sentry_issues} if sentry_issues else set()
                )
                for issue in issues:
                    title = issue.get("title", "")
                    if title and title in sentry_titles:
                        sentry_overlap.append(title)
        except Exception:
            pass

        result: dict = {"service": service, "total": len(issues)}

        if sentry_overlap:
            result["sentry_overlap"] = sentry_overlap

        if detail_level == "summary":
            new_issues = [i for i in issues if i.get("appeared_during_incident")]
            result["new_during_incident"] = len(new_issues)
            result["pre_existing"] = len(issues) - len(new_issues)
            # Group by error_type
            type_counts: dict[str, int] = {}
            for issue in issues:
                et = issue.get("error_type") or "unknown"
                type_counts[et] = type_counts.get(et, 0) + 1
            result["by_error_type"] = type_counts
            result["top_issues"] = [
                {
                    "title": i.get("title", ""),
                    "count": i.get("count", 0),
                    "status": i.get("status", ""),
                }
                for i in sorted(issues, key=lambda x: x.get("count", 0), reverse=True)[:5]
            ]
        else:
            result["issues"] = issues

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Database query performance (DBM)
# ---------------------------------------------------------------------------
@mcp.tool()
def fetch_database_query_performance(
    service: str,
    time_range: str = "2h",
    env: str = "production",
    from_time: str = "",
    to_time: str = "",
    detail_level: str = "summary",
) -> str:
    """Fetch database query performance — slow queries, error rates, and execution counts.

    Args:
        service: Service name
        time_range: How far back (e.g. "1h", "2h", "6h")
        env: Environment (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
        detail_level: "summary" (default) or "full"
    """
    try:
        dd = DatadogCollector()
        if not dd.is_configured():
            return _dd_not_configured_error()

        dd_service = get_datadog_service(service, GRAPH)
        dd_env = resolve_datadog_environment(env)
        infra = get_infrastructure_profile(service, GRAPH)
        db_type = infra.get("database", "unknown")

        result_data = dd.search_database_queries(
            service=dd_service,
            time_range=time_range,
            env=dd_env,
            from_time=from_time or None,
            to_time=to_time or None,
        )

        if result_data.get("error") == "unavailable":
            return json.dumps(result_data)

        result: dict = {
            "service": service,
            "database_type": db_type,
            "total_queries": result_data.get("total", 0),
        }

        queries = result_data.get("queries", [])

        # Optional KB cross-reference (load index once, not per query)
        try:
            from arbiter.core.incident_store import IncidentStore

            incidents_dir = INCIDENTS_ROOT
            store = IncidentStore(incidents_dir)
            all_sigs = [q.get("query_signature", "") for q in queries if q.get("query_signature")]
            if all_sigs:
                matches = store.find_similar(signatures=all_sigs, service=service, max_results=5)
                if matches:
                    matched_sigs = {
                        sig for m in matches for sig in m.get("matches", {}).get("signatures", [])
                    }
                    for q in queries:
                        qsig = q.get("query_signature", "")
                        if qsig and qsig in matched_sigs:
                            match = next(
                                (
                                    m
                                    for m in matches
                                    if qsig in m.get("matches", {}).get("signatures", [])
                                ),
                                None,
                            )
                            if match:
                                q["past_incident_match"] = match.get("incident_id", "")
        except Exception:
            pass

        if detail_level == "summary":
            result["top_queries"] = [
                {
                    "query_signature": q.get("query_signature", "")[:100],
                    "avg_latency_ms": q.get("avg_latency_ms", 0),
                    "error_count": q.get("error_count", 0),
                    "executions": q.get("total_executions", 0),
                }
                for q in sorted(queries, key=lambda x: x.get("error_count", 0), reverse=True)[:5]
            ]
        else:
            result["queries"] = queries

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Database health signals
# ---------------------------------------------------------------------------
@mcp.tool()
def fetch_database_health_signals(
    service: str,
    env: str = "production",
    detail_level: str = "summary",
) -> str:
    """Check database health — connection pools, lock contention, and replication status.

    Args:
        service: Service name
        env: Environment (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
        detail_level: "summary" (default) or "full"
    """
    try:
        dd = DatadogCollector()
        if not dd.is_configured():
            return _dd_not_configured_error()

        dd_service = get_datadog_service(service, GRAPH)
        dd_env = resolve_datadog_environment(env)
        infra = get_infrastructure_profile(service, GRAPH)
        db_type = infra.get("database", "none")

        if db_type == "none":
            return json.dumps({"error": f"Service '{service}' has no database configured."})

        # Select metrics by DB type — scope by service and env
        env_scope = f"service:{dd_service},env:{dd_env}"
        metric_queries: dict[str, str] = {}
        if db_type == "spanner":
            metric_queries = {
                "request_count": f"sum:spanner.api.request_count{{{env_scope}}}.as_rate()",
                "request_latency": f"avg:spanner.api.request_latencies{{{env_scope}}}",
            }
        elif db_type == "postgresql":
            metric_queries = {
                "connections": f"avg:postgresql.connections{{{env_scope}}}",
                "locks": f"sum:postgresql.locks{{{env_scope}}}",
                "deadlocks": f"sum:postgresql.deadlocks{{{env_scope}}}.as_rate()",
            }
        elif db_type == "elasticsearch":
            metric_queries = {
                "search_rate": f"sum:elasticsearch.search.query.total{{{env_scope}}}.as_rate()",
                "search_latency": f"avg:elasticsearch.search.query.time{{{env_scope}}}",
            }

        # Fetch metrics
        metrics_result: dict[str, list] = {}
        for name, query in metric_queries.items():
            try:
                series = dd.query_metrics(query=query, time_range="2h")
                metrics_result[name] = series
            except Exception:
                metrics_result[name] = []

        # Fetch DB-related monitors
        monitors = dd.search_monitors(query=f"tag:service:{dd_service} tag:env:{dd_env}")
        db_monitors = [
            m
            for m in monitors
            if any(
                kw in m.get("name", "").lower()
                for kw in [
                    "database",
                    "db",
                    "spanner",
                    "postgres",
                    "sql",
                    "connection",
                    "lock",
                    "deadlock",
                ]
            )
        ]

        result: dict = {
            "service": service,
            "database_type": db_type,
        }

        if detail_level == "summary":
            result["monitors"] = {
                "total_db_monitors": len(db_monitors),
                "alerting": [
                    m["name"] for m in db_monitors if m.get("overall_state") in ("Alert", "Warn")
                ],
            }
            # Extract latest values from metrics
            metrics_summary: dict = {}
            for name, series_list in metrics_result.items():
                if series_list and series_list[0].get("points"):
                    points = series_list[0]["points"]
                    latest = next((p for p in reversed(points) if p.get("value") is not None), None)
                    metrics_summary[name] = latest["value"] if latest else None
                else:
                    metrics_summary[name] = None
            result["metrics"] = metrics_summary
        else:
            result["monitors"] = db_monitors
            result["metrics"] = metrics_result

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Monitor coverage analysis
# ---------------------------------------------------------------------------
@mcp.tool()
def get_monitor_coverage(
    service: str,
    include_dependencies: bool = True,
    detail_level: str = "summary",
) -> str:
    """Identify monitoring gaps across the service and its dependencies.

    Args:
        service: Service name
        include_dependencies: Include transitive upstream services (default: true)
        detail_level: "summary" (default) or "full"
    """
    try:
        dd = DatadogCollector()
        if not dd.is_configured():
            return _dd_not_configured_error()

        dd_service = get_datadog_service(service, GRAPH)
        monitors = dd.search_monitors(service=dd_service)

        coverage: dict[str, dict] = {
            service: {
                "total": len(monitors),
                "by_type": {},
                "alerting": len(
                    [m for m in monitors if m.get("overall_state") in ("Alert", "Warn")]
                ),
            }
        }
        type_counts: dict[str, int] = {}
        for m in monitors:
            t = m.get("type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1
        coverage[service]["by_type"] = type_counts

        gaps: list[str] = []
        if not monitors:
            gaps.append(service)

        if include_dependencies:
            deps = get_transitive_dependencies(service, GRAPH, max_depth=2)
            for dep in deps:
                dep_dd = get_datadog_service(dep["service"], GRAPH)
                dep_monitors = dd.search_monitors(service=dep_dd)
                dep_type_counts: dict[str, int] = {}
                for m in dep_monitors:
                    t = m.get("type", "unknown")
                    dep_type_counts[t] = dep_type_counts.get(t, 0) + 1
                coverage[dep["service"]] = {
                    "total": len(dep_monitors),
                    "by_type": dep_type_counts,
                    "alerting": len(
                        [m for m in dep_monitors if m.get("overall_state") in ("Alert", "Warn")]
                    ),
                }
                if not dep_monitors:
                    gaps.append(dep["service"])

        result: dict = {
            "service": service,
            "total_services": len(coverage),
            "services_with_no_monitors": gaps,
        }

        if detail_level == "summary":
            result["coverage"] = {
                svc: {"total": data["total"], "alerting": data["alerting"]}
                for svc, data in coverage.items()
            }
        else:
            result["coverage"] = coverage

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Service info
# ---------------------------------------------------------------------------
@mcp.tool()
def get_service_details(service_name: str) -> str:
    """Get the service's architecture, dependencies, and configuration.

    Args:
        service_name: Service name (e.g. "flags", "change-history")
    """
    try:
        svc = get_service_info(service_name, GRAPH)
        deps = get_dependencies(service_name, GRAPH)
        infra = get_infrastructure_profile(service_name, GRAPH)
        return json.dumps(
            {
                "service": _serialize(svc),
                "dependencies": deps,
                "infrastructure": infra,
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Git deploys
# ---------------------------------------------------------------------------
@mcp.tool()
def get_recent_deploys(service_name: str, hours_back: int = 24) -> str:
    """Get recent code changes and deployments for a service.

    Args:
        service_name: Service name matching the repo directory
        hours_back: How far back to look (default: 24)
    """
    try:
        git = GitCollector(WORKSPACE_ROOT)
        ctx = git.gather_context(service_name, hours_back=hours_back)
        return json.dumps(ctx, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Fetch GitHub PR details
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_github_pr(
    service: str,
    pr_number: int,
    include_files: bool = True,
    include_reviews: bool = True,
    detail_level: str = "summary",
) -> str:
    """Get full details for a pull request — title, description, changed files, and reviews.

    Use this when an incident report references a specific PR, or when you need
    to understand what a deploy changed.

    Args:
        service: Service name (resolved to GitHub repo via services.yaml)
        pr_number: PR number
        include_files: Include changed files with diffs (default: True)
        include_reviews: Include review comments (default: True)
        detail_level: "summary" (default) or "full"
    """
    try:
        gh = GitHubCollector()
        if not gh.is_configured():
            return json.dumps({"error": "GitHub CLI (gh) not configured. Run: gh auth login"})
        repo = get_github_repo(service, GRAPH)
        pr = gh.get_pr(repo, pr_number)
        if not pr:
            return json.dumps({"error": f"PR #{pr_number} not found in {repo}"})

        if detail_level == "summary":
            files = gh.get_pr_files(repo, pr_number) if include_files else []
            file_names = [f.get("filename", "") for f in files] if files else []
            additions = sum(f.get("additions", 0) for f in files)
            deletions = sum(f.get("deletions", 0) for f in files)
            reviews = gh.get_pr_reviews(repo, pr_number) if include_reviews else []
            statuses = [r.get("state", "") for r in reviews] if reviews else []
            review_status = (
                "approved"
                if "APPROVED" in statuses
                else ("changes_requested" if "CHANGES_REQUESTED" in statuses else "pending")
            )
            return json.dumps(
                {
                    "title": pr.get("title"),
                    "author": pr.get("author"),
                    "merged_at": pr.get("merged_at"),
                    "files_changed": len(file_names),
                    "additions": additions,
                    "deletions": deletions,
                    "review_status": review_status,
                    "file_names": file_names,
                    "detail_level": "summary",
                },
                indent=2,
                default=str,
            )

        result: dict = {"pr": pr, "detail_level": "full"}
        if include_files:
            result["files"] = gh.get_pr_files(repo, pr_number)
        if include_reviews:
            result["reviews"] = gh.get_pr_reviews(repo, pr_number)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: GitHub deploy correlation
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_github_deploys(
    service: str,
    hours_back: int = 48,
    incident_start: str = "",
    detail_level: str = "summary",
) -> str:
    """Find recent code deployments to the service.

    When incident_start is provided, splits results into pre-incident and
    during-incident deploys with hours-before-incident for each PR.

    Args:
        service: Service name (resolved to GitHub repo via services.yaml)
        hours_back: How far back to search (default: 48)
        incident_start: Incident start time (ISO 8601) for deploy correlation
        detail_level: "summary" (default) or "full"
    """
    try:
        gh = GitHubCollector()
        if not gh.is_configured():
            return json.dumps({"error": "GitHub CLI (gh) not configured. Run: gh auth login"})
        repo = get_github_repo(service, GRAPH)

        if incident_start:
            result = gh.get_deploy_correlation(repo, incident_start)
            if detail_level == "summary":
                deploys = []
                for phase in ("pre_incident", "during_incident"):
                    for pr in result.get(phase, []):
                        deploys.append(
                            {
                                "pr_number": pr.get("number"),
                                "title": pr.get("title"),
                                "author": pr.get("author"),
                                "merged_at": pr.get("merged_at"),
                                "correlation": phase.replace("_", "-"),
                            }
                        )
                return json.dumps(
                    {
                        "repo": repo,
                        "total": len(deploys),
                        "deploys": deploys,
                        "detail_level": "summary",
                    },
                    indent=2,
                    default=str,
                )
            result["detail_level"] = "full"
            return json.dumps(result, indent=2, default=str)

        prs = gh.get_merged_prs(repo, hours_back=hours_back)

        if detail_level == "summary":
            deploys = [
                {
                    "pr_number": pr.get("number"),
                    "title": pr.get("title"),
                    "author": pr.get("author"),
                    "merged_at": pr.get("merged_at"),
                }
                for pr in prs
            ]
            return json.dumps(
                {
                    "repo": repo,
                    "total": len(deploys),
                    "deploys": deploys,
                    "detail_level": "summary",
                },
                indent=2,
                default=str,
            )

        return json.dumps(
            {"repo": repo, "total": len(prs), "merged_prs": prs, "detail_level": "full"},
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Aggregate trace data
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def aggregate_trace_data(
    collected_data_path: str, group_by: str = "pod_name", detail_level: str = "summary"
) -> str:
    """Group collected traces by pod, version, status code, or endpoint to find patterns.

    Reads traces from a previously saved collected-data JSON file and groups them
    by the specified key.

    Args:
        collected_data_path: Path to the collected-data JSON file
        group_by: Trace field to group by (e.g. "pod_name", "version", "status_code", "http_path")
        detail_level: "summary" (default) or "full"
    """
    try:
        from arbiter.core.analyzer import aggregate_traces

        data_path = Path(collected_data_path)
        if not data_path.exists():
            return json.dumps({"error": f"File not found: {collected_data_path}"})

        context = json.loads(data_path.read_text())
        traces = context.get("datadog_traces", [])
        if not traces:
            return json.dumps({"error": "No traces found in collected data"})

        groups = aggregate_traces(traces, group_by=group_by)

        if detail_level == "summary":
            top_groups = sorted(
                groups.items(),
                key=lambda x: len(x[1]) if isinstance(x[1], list) else x[1],
                reverse=True,
            )[:5]
            return json.dumps(
                {
                    "group_by": group_by,
                    "total_traces": len(traces),
                    "total_groups": len(groups),
                    "top_groups": [
                        {"value": k, "count": len(v) if isinstance(v, list) else v}
                        for k, v in top_groups
                    ],
                    "detail_level": "summary",
                },
                indent=2,
                default=str,
            )

        return json.dumps(
            {
                "group_by": group_by,
                "total_traces": len(traces),
                "groups": groups,
                "detail_level": "full",
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: GitHub workflow deploys
# ---------------------------------------------------------------------------
@mcp.tool()
def fetch_github_workflow_deploys(
    service: str,
    hours_back: int = 48,
    workflow_name: str = "",
) -> str:
    """Find deployments triggered by GitHub Actions workflows.

    Tag-based deploys are invisible to PR-only detection. Use this to find
    workflow runs and tags that triggered deployments.

    Args:
        service: Service name (resolved to GitHub repo via services.yaml)
        hours_back: How far back to search (default: 48)
        workflow_name: Filter by workflow filename (e.g. "deploy.yml")
    """
    try:
        gh = GitHubCollector()
        if not gh.is_configured():
            return json.dumps({"error": "GitHub CLI (gh) not configured. Run: gh auth login"})
        repo = get_github_repo(service, GRAPH)

        runs = gh.get_workflow_deploys(
            repo,
            workflow_name=workflow_name,
            hours_back=hours_back,
        )
        tags = gh.get_recent_tags(repo, limit=10)
        return json.dumps(
            {"repo": repo, "workflow_runs": runs, "recent_tags": tags},
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: GitHub code search
# ---------------------------------------------------------------------------
@mcp.tool()
def search_github_code(
    query: str,
    service: str = "",
    language: str = "",
    filename: str = "",
    path: str = "",
    search_dependencies: bool = False,
    limit: int = 20,
    detail_level: str = "summary",
) -> str:
    """Search GitHub code across repos — find function definitions, error messages, usage patterns.

    Args:
        query: Search term (function name, error message, variable name)
        service: Service name (resolved to GitHub repo). If empty, searches org-wide.
        language: Filter by language (python, go, javascript)
        filename: Filter by filename (e.g. "models.py")
        path: Filter by path prefix
        search_dependencies: If true, also search repos of direct upstream dependencies (depth=1)
        limit: Max results (default: 20)
        detail_level: "summary" (default) or "full"
    """
    import time as _time

    from arbiter.collectors.github import strip_variable_parts

    try:
        gh = GitHubCollector()
        if not gh.is_configured():
            return json.dumps({"error": "GitHub CLI (gh) not configured. Run: gh auth login"})

        cleaned_query = strip_variable_parts(query)
        if cleaned_query == query:
            cleaned_query = query

        repos_to_search: list[tuple[str, str]] = []  # (repo, service_name)
        if service:
            repo = get_github_repo(service, GRAPH)
            repos_to_search.append((repo, service))

            if search_dependencies:
                deps = get_dependencies(service, GRAPH)
                for dep in deps:
                    try:
                        repos_to_search.append((get_github_repo(dep, GRAPH), dep))
                    except Exception:
                        continue

        warnings: list[str] = []
        if search_dependencies and len(repos_to_search) > 4:
            warnings.append(
                f"Searching {len(repos_to_search)} repos — this may be slow due to GitHub rate limits"
            )

        all_results: list[dict] = []
        for i, (search_repo, svc_name) in enumerate(repos_to_search):
            if i > 0:
                _time.sleep(1)
            results = gh.search_code(
                cleaned_query,
                repo=search_repo,
                language=language,
                filename=filename,
                path=path,
                limit=limit,
            )
            for r in results:
                r["service"] = svc_name
            all_results.extend(results)

        if not repos_to_search:
            all_results = gh.search_code(
                cleaned_query, language=language, filename=filename, path=path, limit=limit
            )

        output: dict = {
            "query": cleaned_query,
            "total": len(all_results),
        }
        if detail_level == "summary":
            output["results"] = [
                {
                    "path": r.get("path", ""),
                    "repo": r.get("repo", ""),
                    "matches": [
                        tm.get("fragment", "")[:120] for tm in (r.get("text_matches") or [])[:2]
                    ],
                }
                for r in all_results
            ]
        else:
            output["results"] = all_results
        if warnings:
            output["warnings"] = warnings
        if cleaned_query != query:
            output["original_query"] = query
            output["note"] = "Variable parts (UUIDs, timestamps, IDs) were stripped for search"

        return json.dumps(output, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: GitHub releases
# ---------------------------------------------------------------------------
@mcp.tool()
def fetch_github_releases(
    service: str,
    limit: int = 10,
    from_time: str = "",
    to_time: str = "",
    detail_level: str = "summary",
) -> str:
    """Fetch GitHub releases for a service — release notes, tags, and publish times.

    Args:
        service: Service name (resolved to GitHub repo via services.yaml)
        limit: Max releases to return (default: 10)
        from_time: Filter releases published after this time (ISO 8601)
        to_time: Filter releases published before this time
        detail_level: "summary" (default) or "full"
    """
    try:
        gh = GitHubCollector()
        if not gh.is_configured():
            return json.dumps({"error": "GitHub CLI (gh) not configured. Run: gh auth login"})
        repo = get_github_repo(service, GRAPH)

        releases = gh.get_releases(
            repo,
            limit=limit,
            from_time=from_time or None,
            to_time=to_time or None,
        )

        if from_time:
            from dateutil import parser as dateutil_parser

            try:
                incident_dt = dateutil_parser.isoparse(from_time)
            except (ValueError, TypeError):
                incident_dt = None

            if incident_dt:
                for r in releases:
                    published = r.get("published_at", "")
                    if published:
                        try:
                            pub_dt = dateutil_parser.isoparse(published)
                            delta = incident_dt - pub_dt
                            if delta.total_seconds() > 0:
                                mins = int(delta.total_seconds() / 60)
                                if mins < 60:
                                    r["_timing"] = f"Published {mins} minutes before incident start"
                                else:
                                    hours = round(mins / 60, 1)
                                    r["_timing"] = f"Published {hours} hours before incident start"
                            else:
                                r["_timing"] = "Published during/after incident"
                        except (ValueError, TypeError):
                            pass

        for r in releases:
            if r.get("prerelease"):
                r["_flag"] = "PRE-RELEASE — may indicate canary/RC deploy"

        result: dict = {"repo": repo, "total": len(releases)}
        if detail_level == "summary":
            result["releases"] = [
                {
                    "tag": r.get("tag") or r.get("tag_name", ""),
                    "published_at": r.get("published_at", ""),
                    "title": (r.get("body") or "")[:80].split("\n")[0],
                    **({k: r[k] for k in ("_timing", "_flag") if k in r}),
                }
                for r in releases
            ]
        else:
            result["releases"] = releases

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Read GitHub file
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def read_github_file(
    service: str,
    path: str,
    ref: str = "",
    start_line: int = 0,
    end_line: int = 0,
    detail_level: str = "summary",
) -> str:
    """Read a source file from GitHub to inspect code during investigation.

    Use when you have a stack trace pointing to a specific file/function and
    need to see the actual source code to understand the failure. Also useful
    for checking configuration files, middleware, and error handlers.

    Args:
        service: Service name (resolved to GitHub repo via services.yaml)
        path: File path within the repo (e.g. "src/app.py", "backend/flags/api.py")
        ref: Branch, tag, or commit SHA (default: repo default branch)
        start_line: Start line (1-indexed, inclusive). 0 = from beginning.
        end_line: End line (1-indexed, inclusive). 0 = to end.
        detail_level: "summary" (default, caps output at 500 lines) or "full"
    """
    try:
        gh = GitHubCollector()
        if not gh.is_configured():
            return json.dumps({"error": "GitHub CLI (gh) not configured. Run: gh auth login"})

        repo = get_github_repo(service, GRAPH)
        result = gh.read_file(
            repo,
            path=path,
            ref=ref,
            start_line=start_line,
            end_line=end_line,
        )

        if "error" in result:
            return json.dumps(result)

        if detail_level == "summary":
            lines = result["content"].splitlines()
            if len(lines) > 500:
                result["content"] = "\n".join(lines[:500])
                result["truncated"] = True
                result["showing"] = f"1-500 of {result['total_lines']}"
                result["_note"] = (
                    "Truncated to 500 lines. Use a narrower line range or detail_level='full' to see more."
                )

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Datadog RUM errors
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_rum_errors(
    service: str = "",
    time_range: str = "2h",
    env: str = "production",
    from_time: str = "",
    to_time: str = "",
    limit: int = 20,
    detail_level: str = "summary",
) -> str:
    """Fetch browser-side errors from Datadog RUM — JavaScript exceptions, network failures.

    Use when the symptom is UI/frontend ("not loading", "blank page") and the
    service has frontend.rum configured. Shows what users actually experience
    in their browsers, not what the server sees.

    Args:
        service: Service name (optional — searches all RUM apps if empty)
        time_range: How far back (e.g. "1h", "2h", "6h")
        env: Environment (default: "production")
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
        limit: Max events (default: 20)
        detail_level: "summary" (default) or "full"
    """
    try:
        dd = DatadogCollector()
        dd_env = resolve_datadog_environment(env)
        events = dd.search_rum_events(
            service=service,
            query="@type:error",
            time_range=time_range,
            env=dd_env,
            from_time=from_time or None,
            to_time=to_time or None,
            limit=limit,
        )

        if not events:
            return json.dumps(
                {
                    "total": 0,
                    "events": [],
                    "note": "No RUM error events found. Verify RUM is configured for this service in Datadog.",
                }
            )

        if detail_level == "summary":
            error_types: dict[str, int] = {}
            error_sources: dict[str, int] = {}
            view_urls: dict[str, int] = {}
            for e in events:
                et = e.get("error_type") or e.get("error_source") or "unknown"
                error_types[et] = error_types.get(et, 0) + 1
                src = e.get("error_source") or "unknown"
                error_sources[src] = error_sources.get(src, 0) + 1
                url = e.get("view_url", "")
                if url:
                    view_urls[url] = view_urls.get(url, 0) + 1

            representative = events[0] if events else None
            result = {
                "total": len(events),
                "top_error_types": sorted(error_types.items(), key=lambda x: -x[1])[:5],
                "top_error_sources": sorted(error_sources.items(), key=lambda x: -x[1])[:3],
                "top_view_urls": sorted(view_urls.items(), key=lambda x: -x[1])[:3],
                "representative_error": (
                    {
                        "error_type": representative.get("error_type", ""),
                        "error_message": representative.get("error_message", "")[:200],
                        "error_source": representative.get("error_source", ""),
                        "view_url": representative.get("view_url", ""),
                        "browser": representative.get("browser", ""),
                    }
                    if representative
                    else None
                ),
                "detail_level": "summary",
            }
            return json.dumps(result, indent=2, default=str)

        return json.dumps(
            {"total": len(events), "events": events, "detail_level": "full"},
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Datadog RUM performance
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_rum_performance(
    service: str = "",
    time_range: str = "2h",
    env: str = "production",
    from_time: str = "",
    to_time: str = "",
    limit: int = 20,
    detail_level: str = "summary",
) -> str:
    """Fetch browser page load performance from Datadog RUM — load times, resource loading.

    Use when investigating slow page loads or asset delivery issues.
    Shows view events with timing data from real user browsers.

    Args:
        service: Service name (optional)
        time_range: How far back (e.g. "1h", "2h", "6h")
        env: Environment (default: "production")
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
        limit: Max events (default: 20)
        detail_level: "summary" (default) or "full"
    """
    try:
        dd = DatadogCollector()
        dd_env = resolve_datadog_environment(env)
        events = dd.search_rum_performance(
            service=service,
            time_range=time_range,
            env=dd_env,
            from_time=from_time or None,
            to_time=to_time or None,
            limit=limit,
        )

        if not events:
            return json.dumps(
                {
                    "total": 0,
                    "events": [],
                    "note": "No RUM view events found. Verify RUM is configured for this service in Datadog.",
                }
            )

        if detail_level == "summary":
            view_names: dict[str, int] = {}
            for e in events:
                name = e.get("view_name") or e.get("view_url") or "unknown"
                view_names[name] = view_names.get(name, 0) + 1

            result = {
                "total": len(events),
                "top_views": sorted(view_names.items(), key=lambda x: -x[1])[:5],
                "detail_level": "summary",
            }
            return json.dumps(result, indent=2, default=str)

        return json.dumps(
            {"total": len(events), "events": events, "detail_level": "full"},
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Parse logs
# ---------------------------------------------------------------------------
@mcp.tool()
def parse_error_logs(raw_logs: str) -> str:
    """Parse pasted error logs into structured entries.

    Args:
        raw_logs: Raw log text to parse
    """
    try:
        manual = ManualCollector()
        entries = manual.parse_logs(raw_logs)
        return json.dumps([_serialize(e) for e in entries], indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Parse thread
# ---------------------------------------------------------------------------
@mcp.tool()
def parse_incident_thread(raw_thread: str) -> str:
    """Parse a Slack/Teams thread into structured timeline entries.

    Args:
        raw_thread: Raw chat thread text
    """
    try:
        manual = ManualCollector()
        entries = manual.parse_thread(raw_thread)
        return json.dumps(entries, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: List services
# ---------------------------------------------------------------------------
@mcp.tool()
def list_available_services() -> str:
    """List all known services."""
    try:
        services = list_services(GRAPH)
        return json.dumps({"services": services})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Save report
# ---------------------------------------------------------------------------
@mcp.tool()
def save_incident_report(
    title: str, content: str, output_dir: str = "", collected_data_path: str = ""
) -> str:
    """Save the incident report.

    Args:
        title: Incident title (used for filename)
        content: Full report markdown content
        output_dir: Directory to save to (default: arbiter/output/reports/)
        collected_data_path: Path to collected-data JSON (title fallback)
    """
    title = (title or "").strip()
    if not title and collected_data_path:
        try:
            data = json.loads(Path(collected_data_path).read_text())
            title = (data.get("title", "") or "").strip()
        except Exception:
            pass
    try:
        out_dir = Path(output_dir) if output_dir else OUTPUT_ROOT / "reports"
        path = save_report(title, content, out_dir)
        return json.dumps(
            {
                "saved_to": str(path),
                "title": title,
                "pdf_hint": "After the investigation is complete and the incident record "
                "is saved, offer the user a PDF version by calling "
                "generate_pdf_report with this path.",
                "next_step": "IMPORTANT: Now call save_incident_record to save structured "
                "findings to the knowledge base. Include: root_cause_category, "
                "root_cause_detail, error_signatures, affected_tables, resolved_by, "
                "and related_prs. This enables future investigations to find this "
                "incident when similar patterns occur. Also include "
                "root_cause_confidence (high/medium/low) and verification_gaps "
                "(what could NOT be verified) for confidence scoring.",
            }
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Generate PDF report
# ---------------------------------------------------------------------------
@mcp.tool()
def generate_pdf_report(report_path: str) -> str:
    """Generate a PDF version of a saved incident report.

    Args:
        report_path: Path to the saved markdown report file
    """
    try:
        from arbiter.output.pdf_renderer import generate_pdf

        md_path = Path(report_path)
        if not md_path.is_absolute():
            md_path = OUTPUT_ROOT.parent / md_path

        pdf_path = generate_pdf(md_path)
        return json.dumps(
            {
                "pdf_path": str(pdf_path),
                "size_kb": round(pdf_path.stat().st_size / 1024, 1),
                "message": f"PDF report generated: {pdf_path.name}",
            }
        )
    except OSError as e:
        err_msg = str(e)
        if "pango" in err_msg.lower() or "gobject" in err_msg.lower() or "cairo" in err_msg.lower():
            return json.dumps(
                {
                    "error": "PDF system dependencies not installed",
                    "install": "brew install pango (macOS) or apt install libpango1.0-dev libcairo2-dev (Linux)",
                    "detail": err_msg,
                }
            )
        return json.dumps({"error": f"PDF generation failed: {err_msg}"})
    except (FileNotFoundError, ValueError) as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"PDF generation failed: {e}"})


# ---------------------------------------------------------------------------
# Tool: Fetch Sentry issues
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_sentry_issues(
    project: str,
    time_range: str = "2h",
    env: str = "production",
    limit: int = 25,
    detail_level: str = "summary",
) -> str:
    """Fetch unresolved error issues from Sentry.

    Args:
        project: Sentry project slug (often matches service name)
        time_range: How far back (e.g. "1h", "2h", "24h")
        env: Environment filter (default: "production"). Aliases like "develrc", "rc" are auto-resolved.
        limit: Max issues (default: 25)
        detail_level: "summary" (default) or "full"
    """
    try:
        sentry = SentryCollector()
        if not sentry.is_configured():
            return json.dumps(
                {"error": "Sentry not configured. Set SENTRY_AUTH_TOKEN and SENTRY_ORG."}
            )
        dd_env = resolve_datadog_environment(env)
        logs = sentry.collect_logs(
            service=project,
            time_range=time_range,
            env=dd_env,
            limit=limit,
        )

        if detail_level == "summary":
            return json.dumps(_summarize_log_entries(logs), indent=2, default=str)

        return json.dumps(
            {"total": len(logs), "issues": [_serialize(l) for l in logs], "detail_level": "full"},
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Fetch GCP logs
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_gcp_logs(
    service: str,
    time_range: str = "2h",
    limit: int = 50,
    query: str = "",
    detail_level: str = "summary",
) -> str:
    """Fetch error logs from Google Cloud Logging.

    Args:
        service: Service name to filter by
        time_range: How far back (e.g. "1h", "2h", "6h")
        limit: Max entries (default: 50)
        query: Custom Cloud Logging filter (optional)
        detail_level: "summary" (default) or "full"
    """
    try:
        gcp = GCPCollector()
        if not gcp.is_configured():
            return json.dumps(
                {
                    "error": "GCP not configured. Run 'gcloud auth login', or set GCP_ACCESS_TOKEN / GCP_SERVICE_ACCOUNT_KEY_FILE."
                }
            )
        gcp_project = get_gcp_project(service, GRAPH)
        logs = gcp.collect_logs(
            service=service,
            time_range=time_range,
            limit=limit,
            query=query,
            project_override=gcp_project,
        )

        if detail_level == "summary":
            return json.dumps(_summarize_log_entries(logs), indent=2, default=str)

        return json.dumps(
            {"total": len(logs), "logs": [_serialize(l) for l in logs], "detail_level": "full"},
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Fetch GCP audit logs
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_gcp_audit_logs(
    service: str,
    time_range: str = "6h",
    from_time: str = "",
    to_time: str = "",
    detail_level: str = "summary",
) -> str:
    """Check for recent infrastructure changes that could explain the failure.

    Use when no code or config change explains the failure — check if
    infrastructure changed in the incident window. Returns Admin Activity
    audit log entries showing who changed what and when.

    Args:
        service: Service name (resolved to GCP project via services.yaml)
        time_range: How far back (e.g. "2h", "6h", "24h")
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
        detail_level: "summary" (default) or "full"
    """
    try:
        gcp = GCPCollector()
        if not gcp.is_configured():
            return json.dumps(
                {
                    "error": "GCP not configured. Run 'gcloud auth login', or set GCP_ACCESS_TOKEN / GCP_SERVICE_ACCOUNT_KEY_FILE."
                }
            )
        gcp_project = get_gcp_project(service, GRAPH)
        if not gcp_project:
            return json.dumps({"error": f"No GCP project configured for service '{service}'"})
        logs = gcp.collect_audit_logs(
            project=gcp_project,
            time_range=time_range,
            from_time=from_time or None,
            to_time=to_time or None,
        )

        if detail_level == "summary":
            change_types = sorted({l.message[:80] for l in logs if l.message} if logs else set())
            actors = sorted(
                {
                    l.metadata.get("actor", "")
                    for l in logs
                    if l.metadata and l.metadata.get("actor")
                }
                if logs
                else set()
            )
            most_recent = logs[0].message[:200] if logs and logs[0].message else None
            return json.dumps(
                {
                    "total": len(logs),
                    "project": gcp_project,
                    "change_types": change_types[:5],
                    "actors": actors[:5],
                    "most_recent": most_recent,
                    "detail_level": "summary",
                },
                indent=2,
                default=str,
            )

        return json.dumps(
            {
                "total": len(logs),
                "project": gcp_project,
                "logs": [_serialize(l) for l in logs],
                "detail_level": "full",
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Fetch Load Balancer logs
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_lb_logs(
    service: str,
    time_range: str = "2h",
    from_time: str = "",
    to_time: str = "",
    detail_level: str = "summary",
) -> str:
    """Fetch load balancer logs showing failed requests (5xx errors).

    Use when the alert mentions LB-level 5XX or when you need to see the
    LB perspective of backend failures.

    Args:
        service: Service name (resolved to GCP project via services.yaml)
        time_range: How far back (e.g. "1h", "2h", "6h")
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
        detail_level: "summary" (default) or "full"
    """
    try:
        gcp = GCPCollector()
        if not gcp.is_configured():
            return json.dumps({"error": "GCP not configured. Run 'gcloud auth login'."})
        gcp_project = get_gcp_project(service, GRAPH)
        if not gcp_project:
            return json.dumps({"error": f"No GCP project configured for service '{service}'"})

        logs = gcp.collect_lb_logs(
            project=gcp_project,
            time_range=time_range,
            from_time=from_time or None,
            to_time=to_time or None,
        )

        if detail_level == "summary":
            status_counts: dict[int, int] = {}
            backend_counts: dict[str, int] = {}
            for log in logs:
                sc = log.metadata.get("status_code", 0)
                status_counts[sc] = status_counts.get(sc, 0) + 1
                bk = log.metadata.get("backend", "")
                if bk:
                    backend_counts[bk] = backend_counts.get(bk, 0) + 1
            return json.dumps(
                {
                    "total": len(logs),
                    "project": gcp_project,
                    "by_status": dict(sorted(status_counts.items())),
                    "by_backend": dict(sorted(backend_counts.items(), key=lambda x: -x[1])[:5]),
                    "detail_level": "summary",
                },
                indent=2,
                default=str,
            )

        return json.dumps(
            {
                "total": len(logs),
                "project": gcp_project,
                "logs": [_serialize(l) for l in logs],
                "detail_level": "full",
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Fetch CloudSQL instance logs
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_cloudsql_logs(
    service: str,
    time_range: str = "2h",
    from_time: str = "",
    to_time: str = "",
    detail_level: str = "summary",
) -> str:
    """Fetch database server logs — restarts, connection drops, and PostgreSQL errors.

    Use to see the database perspective during incidents — maintenance restarts,
    connection failures, and error messages from PostgreSQL itself.

    Args:
        service: Service name (resolved to CloudSQL instance via services.yaml)
        time_range: How far back (e.g. "1h", "2h", "6h")
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
        detail_level: "summary" (default) or "full"
    """
    try:
        instance, project = get_cloudsql_instance(service, GRAPH)
        if not instance:
            infra = get_infrastructure_profile(service, GRAPH)
            if infra.get("database") != "postgresql":
                return json.dumps({"error": f"Service '{service}' does not use PostgreSQL"})
            return json.dumps({"error": f"No cloudsql_instance configured for service '{service}'"})

        gcp = GCPCollector()
        if not gcp.is_configured():
            return json.dumps({"error": "GCP not configured. Run 'gcloud auth login'."})

        logs = gcp.collect_cloudsql_logs(
            instance=instance,
            project=project,
            time_range=time_range,
            from_time=from_time or None,
            to_time=to_time or None,
        )

        if detail_level == "summary":
            error_patterns: dict[str, int] = {}
            for log in logs:
                key = log.message[:100] if log.message else "unknown"
                error_patterns[key] = error_patterns.get(key, 0) + 1
            return json.dumps(
                {
                    "total": len(logs),
                    "instance": instance,
                    "project": project,
                    "top_patterns": [
                        {"pattern": p, "count": c}
                        for p, c in sorted(error_patterns.items(), key=lambda x: -x[1])[:5]
                    ],
                    "detail_level": "summary",
                },
                indent=2,
                default=str,
            )

        return json.dumps(
            {
                "total": len(logs),
                "instance": instance,
                "project": project,
                "logs": [_serialize(l) for l in logs],
                "detail_level": "full",
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Fetch GKE cluster operations
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_gke_operations(
    service: str,
    time_range: str = "6h",
    from_time: str = "",
    to_time: str = "",
    detail_level: str = "summary",
) -> str:
    """Check for cluster operations (upgrades, repairs) that may have disrupted the service.

    Use when pod disruption is suspected but no deploy or config change explains
    the failure. GKE operations like node pool upgrades drain nodes and evict pods.

    Args:
        service: Service name (resolved to GKE cluster via services.yaml)
        time_range: How far back (e.g. "2h", "6h", "24h")
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
        detail_level: "summary" (default) or "full"
    """
    try:
        cluster_config = get_gke_cluster_config(service, GRAPH)
        if not cluster_config:
            infra = get_infrastructure_profile(service, GRAPH)
            if infra.get("deployment") != "gke":
                return json.dumps({"error": f"Service '{service}' is not deployed on GKE"})
            return json.dumps(
                {
                    "error": (
                        f"Service '{service}' is on GKE but no cluster configured in services.yaml. "
                        "Add gke_cluster to the service's infrastructure block."
                    )
                }
            )

        gcp = GCPCollector()
        if not gcp._get_access_token():
            return json.dumps({"error": "GCP not authenticated. Run 'gcloud auth login'."})

        ops = gcp.collect_gke_operations(
            project=cluster_config["project"],
            location=cluster_config["location"],
            cluster=cluster_config["name"],
            time_range=time_range,
            from_time=from_time or None,
            to_time=to_time or None,
        )

        result = {
            "cluster": cluster_config["name"],
            "project": cluster_config["project"],
            "total": len(ops),
            "detail_level": detail_level,
        }

        if detail_level == "summary":
            result["operations"] = [
                {
                    "type": op["operation_type"],
                    "status": op["status"],
                    "start": op["start_time"],
                    "end": op["end_time"],
                    "target": op["target"],
                }
                for op in ops
            ]
            if any(op["operation_type"] == "UPGRADE_NODES" for op in ops):
                result["pdb_configured"] = all(
                    int(op.get("node_conditions", {}).get("NODE_PDB_DELAY_SECONDS", 0)) > 0
                    for op in ops
                    if op["operation_type"] == "UPGRADE_NODES"
                )
        else:
            result["operations"] = ops

        try:
            from arbiter.collectors.kubernetes import (
                KubernetesCollector,
                kubectl_context_name,
            )

            ctx_name = kubectl_context_name(
                cluster_config["project"],
                cluster_config["location"],
                cluster_config["name"],
            )
            kube = KubernetesCollector(context=ctx_name, namespace=service)
            kubectl_data = kube.collect_pod_context(service_name=service)
            result["kubectl_enrichment"] = kubectl_data
        except Exception:
            result["kubectl_enrichment"] = None

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Fetch CloudSQL operations
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_cloudsql_operations(
    service: str,
    time_range: str = "6h",
    from_time: str = "",
    to_time: str = "",
    detail_level: str = "summary",
) -> str:
    """Check for database maintenance, failovers, or restarts that may have caused disruption.

    CloudSQL scheduled maintenance is ONLY visible through this API — it does
    not appear in admin activity or system event audit logs. Use when a
    PostgreSQL service has unexplained errors and no deploy correlation.

    Args:
        service: Service name (resolved to CloudSQL instance via services.yaml)
        time_range: How far back (e.g. "2h", "6h", "24h")
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
        detail_level: "summary" (default) or "full"
    """
    try:
        instance, project = get_cloudsql_instance(service, GRAPH)
        if not instance:
            infra = get_infrastructure_profile(service, GRAPH)
            if infra.get("database") != "postgresql":
                return json.dumps({"error": f"Service '{service}' does not use PostgreSQL"})
            return json.dumps(
                {
                    "error": (
                        f"Service '{service}' uses PostgreSQL but no cloudsql_instance "
                        "configured in services.yaml."
                    )
                }
            )

        import shutil

        if not shutil.which("gcloud"):
            return json.dumps(
                {
                    "error": "gcloud CLI not found. Install Google Cloud SDK or run 'gcloud auth login'."
                }
            )

        gcp = GCPCollector()
        ops = gcp.collect_cloudsql_operations(
            instance=instance,
            project=project,
            time_range=time_range,
            from_time=from_time or None,
            to_time=to_time or None,
        )

        result = {
            "instance": instance,
            "project": project,
            "total": len(ops),
            "detail_level": detail_level,
        }

        if detail_level == "summary":
            result["operations"] = [
                {
                    "type": op["operation_type"],
                    "status": op["status"],
                    "start": op["start_time"],
                    "end": op["end_time"],
                }
                for op in ops
            ]
            maintenance_ops = [op for op in ops if "MAINTENANCE" in op.get("operation_type", "")]
            if maintenance_ops:
                result["has_maintenance"] = True
        else:
            result["operations"] = ops

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Fetch public status pages
# ---------------------------------------------------------------------------
@mcp.tool()
def fetch_status_pages(
    time_range: str = "6h",
    from_time: str = "",
    to_time: str = "",
) -> str:
    """Check public status pages for platform-wide outages (GCP, Cloudflare).

    No auth needed. Use when multiple services are affected simultaneously
    or when no deploy/config change explains the failure.

    Args:
        time_range: How far back (e.g. "2h", "6h", "24h")
        from_time: Absolute start time (ISO 8601)
        to_time: Absolute end time (ISO 8601)
    """
    from arbiter.collectors.status_pages import check_cloudflare_status, check_gcp_status

    gcp_incidents = check_gcp_status(
        time_range=time_range,
        from_time=from_time or None,
        to_time=to_time or None,
    )
    cf_incidents = check_cloudflare_status(
        time_range=time_range,
        from_time=from_time or None,
        to_time=to_time or None,
    )

    return json.dumps(
        {
            "gcp": {"total": len(gcp_incidents), "incidents": gcp_incidents[:5]},
            "cloudflare": {"total": len(cf_incidents), "incidents": cf_incidents[:5]},
        },
        indent=2,
        default=str,
    )


# ---------------------------------------------------------------------------
# Tool: Fetch OpsGenie alerts
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def fetch_opsgenie_alerts(
    service: str = "",
    time_range: str = "2h",
    query: str = "",
    detail_level: str = "summary",
) -> str:
    """Fetch recent alerts from OpsGenie.

    Args:
        service: Filter by service tag (optional)
        time_range: How far back (e.g. "1h", "2h", "24h")
        query: Custom OpsGenie query (optional)
        detail_level: "summary" (default) or "full"
    """
    try:
        og = OpsGenieCollector()
        if not og.is_configured():
            return json.dumps({"error": "OpsGenie not configured. Set OPSGENIE_API_KEY."})
        alerts = og.get_structured_alerts(service=service or None, time_range=time_range)

        if detail_level == "summary":
            by_priority: dict[str, int] = {}
            for a in alerts:
                p = (
                    a.priority
                    if hasattr(a, "priority")
                    else (a.get("priority") if isinstance(a, dict) else "unknown")
                )
                by_priority[str(p)] = by_priority.get(str(p), 0) + 1
            most_recent = None
            if alerts:
                first = alerts[0]
                if hasattr(first, "title"):
                    most_recent = {
                        "title": first.title,
                        "created_at": str(first.timestamp),
                        "priority": str(first.priority),
                    }
                elif isinstance(first, dict):
                    most_recent = {
                        "title": first.get("title"),
                        "created_at": first.get("created_at"),
                        "priority": first.get("priority"),
                    }
            return json.dumps(
                {
                    "total": len(alerts),
                    "by_priority": by_priority,
                    "most_recent": most_recent,
                    "detail_level": "summary",
                },
                indent=2,
                default=str,
            )

        return json.dumps(
            {
                "total": len(alerts),
                "alerts": [_serialize(a) for a in alerts],
                "detail_level": "full",
            },
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: OpsGenie alert timeline
# ---------------------------------------------------------------------------
@mcp.tool()
def fetch_opsgenie_alert_timeline(alert_id: str) -> str:
    """Get the full activity history of an OpsGenie alert.

    Args:
        alert_id: OpsGenie alert ID
    """
    try:
        og = OpsGenieCollector()
        if not og.is_configured():
            return json.dumps({"error": "OpsGenie not configured."})
        events = og.get_alert_timeline(alert_id)
        return json.dumps(
            {"alert_id": alert_id, "events": [_serialize(e) for e in events]},
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Get report template
# ---------------------------------------------------------------------------
@mcp.tool()
def get_report_template() -> str:
    """Get the incident report template."""
    try:
        from arbiter.core.models import IncidentContext, Severity

        ctx = IncidentContext(
            title="[Incident Title]",
            severity=Severity.P1,
            primary_service="[service-name]",
            time_range_start="[start]",
            time_range_end="[end]",
            summary="[Brief summary of what happened]",
        )
        return render_report(ctx)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Get investigation effort
# ---------------------------------------------------------------------------
@mcp.tool()
def get_investigation_effort() -> str:
    """Get a summary of which tools were used and how much data was collected.

    Returns which tools were called, their data collection depth (Summary or Full),
    and estimated token usage. Include this in the report under an Investigation Effort section.
    Resets the tracker after returning.
    """
    global _tool_calls
    if not _tool_calls:
        return json.dumps({"message": "No tool calls recorded for this investigation."})

    total_tokens = sum(tc["estimated_tokens"] for tc in _tool_calls)
    result = {
        "tool_calls": _tool_calls,
        "total_tool_calls": len(_tool_calls),
        "total_estimated_tokens": total_tokens,
    }
    _tool_calls = []
    return json.dumps(result, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tool: Save incident record
# ---------------------------------------------------------------------------
@mcp.tool()
def save_incident_record(
    title: str,
    date: str,
    service: str,
    severity: str = "P2",
    status: str = "resolved",
    root_cause_category: str = "unknown",
    root_cause_detail: str = "",
    error_signatures: str = "",
    affected_services: str = "",
    affected_tables: str = "",
    affected_endpoints: str = "",
    resolved_by: str = "unresolved",
    mttr_minutes: int = 0,
    related_prs: str = "",
    remediation_tickets: str = "",
    collected_data_path: str = "",
    report_path: str = "",
    tags: str = "",
    root_cause_confidence: str = "",
    verification_gaps: str = "",
    evidence_notes: str = "",
    knowledge_source: str = "arbiter",
) -> str:
    """Save findings to the knowledge base for future investigations.

    Saves the incident record locally. Does NOT create a GitHub PR — use
    sync_incident_record for that after asking the user.

    Call this after writing an incident report. The knowledge base enables
    finding similar past incidents during future investigations.

    Args:
        title: Incident title (e.g. "Flags -- Unable to Duplicate Flag")
        date: Incident date (ISO 8601, e.g. "2026-04-11")
        service: Primary affected service canonical name
        severity: P1/P2/P3/P4
        status: investigating, resolved, or closed
        root_cause_category: database_contention, deploy_regression, infrastructure_failure,
            third_party, config_change, resource_exhaustion, code_bug,
            external_client_misconfiguration, unknown
        root_cause_detail: Human-written root cause explanation
        error_signatures: JSON array or comma-separated normalized error patterns
        affected_services: JSON array of {service, role, impact} objects
        affected_tables: Comma-separated DB table names
        affected_endpoints: Comma-separated API endpoints
        resolved_by: code_fix, rollback, config_change, restart, self_healed,
            manual_intervention, unresolved
        mttr_minutes: Minutes from first alert to resolution (0 if unknown)
        related_prs: Comma-separated PR references (e.g. "acme-platform/catalog#42")
        remediation_tickets: JSON array of {ticket_key, summary, status, created_at, url, type} objects.
            Malformed JSON is silently ignored (defaults to empty list)
        collected_data_path: Path to the collected-data JSON file (title fallback if title is empty)
        report_path: Path to the report markdown file
        tags: Comma-separated tags
        root_cause_confidence: Confidence in root cause: high, medium, or low
        verification_gaps: Comma-separated or JSON array of things that could NOT be verified
        evidence_notes: Free-text summary of evidence quality
        knowledge_source: Who identified the root cause: "arbiter", "human", or "arbiter & human"
    """

    from arbiter.core.incident_store import (
        IncidentStore,
        generate_incident_id,
        parse_csv_or_json_list,
    )
    from arbiter.core.models import (
        IncidentRecord,
        IncidentStatus,
        KnowledgeSource,
        ResolutionType,
        RootCauseCategory,
        Severity,
    )

    title = (title or "").strip()
    if not title and collected_data_path:
        try:
            data = json.loads(Path(collected_data_path).read_text())
            title = (data.get("title", "") or "").strip() or title
        except Exception:
            pass

    try:
        # Parse list fields
        sig_list = parse_csv_or_json_list(error_signatures)
        table_list = parse_csv_or_json_list(affected_tables)
        endpoint_list = parse_csv_or_json_list(affected_endpoints)
        pr_list = parse_csv_or_json_list(related_prs)
        tag_list = parse_csv_or_json_list(tags)

        # Parse affected services (JSON array of objects or empty)
        aff_services = []
        if affected_services and affected_services.strip():
            try:
                parsed = json.loads(affected_services)
                if isinstance(parsed, list):
                    aff_services = parsed
            except json.JSONDecodeError:
                pass

        # Parse remediation tickets (JSON array of objects or empty)
        rem_tickets = []
        if remediation_tickets and remediation_tickets.strip():
            try:
                parsed = json.loads(remediation_tickets)
                if isinstance(parsed, list):
                    rem_tickets = parsed
            except json.JSONDecodeError:
                pass

        # Generate ID from title slug
        from arbiter.core.models import slugify

        inc_id = generate_incident_id(date, service, suffix=slugify(title))

        # Build confidence score
        from arbiter.core.confidence import build_confidence_score

        gaps_list = parse_csv_or_json_list(verification_gaps)
        infra = get_infrastructure_profile(service, GRAPH)
        confidence = build_confidence_score(
            collected_data_path=collected_data_path,
            incident_date=date,
            root_cause_confidence=root_cause_confidence or "medium",
            verification_gaps=gaps_list,
            evidence_notes=evidence_notes,
            infrastructure_profile=infra,
        )

        arbiter_root = OUTPUT_ROOT.parent

        def _to_relative(p: str) -> str:
            if not p:
                return ""
            path = Path(p)
            if path.is_absolute():
                try:
                    return str(path.relative_to(arbiter_root))
                except ValueError:
                    return p
            return p

        rel_collected = _to_relative(collected_data_path)
        rel_report = _to_relative(report_path)

        record = IncidentRecord(
            id=inc_id,
            title=title,
            date=date,
            service=service,
            severity=Severity(severity),
            status=IncidentStatus(status),
            root_cause_category=RootCauseCategory(root_cause_category),
            root_cause_detail=root_cause_detail,
            error_signatures=sig_list,
            affected_services=aff_services,
            affected_tables=table_list,
            affected_endpoints=endpoint_list,
            resolved_by=ResolutionType(resolved_by),
            mttr_minutes=mttr_minutes if mttr_minutes > 0 else None,
            related_prs=pr_list,
            remediation_tickets=rem_tickets,
            collected_data_path=rel_collected,
            report_path=rel_report,
            tags=tag_list,
            confidence=confidence,
            knowledge_source=KnowledgeSource(knowledge_source),
        )

        incidents_dir = INCIDENTS_ROOT
        store = IncidentStore(incidents_dir)
        saved_path = store.save(record)

        result = {
            "saved_to": str(saved_path),
            "incident_id": inc_id,
            "title": title,
            "service": service,
            "root_cause_category": root_cause_category,
            "confidence": {
                "overall_level": confidence.overall_level.value,
                "overall_score": confidence.overall_score,
                "data_completeness_score": confidence.data_completeness.score,
                "root_cause_confidence": confidence.root_cause_confidence.value,
            },
            "marketplace_sync_available": is_marketplace_mode(),
        }

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Sync incident record to GitHub (marketplace)
# ---------------------------------------------------------------------------
@mcp.tool()
def sync_incident_record(incident_id: str) -> str:
    """Sync the incident record to the shared knowledge base via GitHub PR.

    This will create a branch and pull request on the shared the configured sync repo
    repository containing the incident record. Only call after the user has
    confirmed they want to sync.

    Requires marketplace mode (ARBITER_MARKETPLACE=1) and gh CLI authentication.

    Args:
        incident_id: Incident ID returned by save_incident_record
            (e.g. "INC-2026-0428-flags-test")
    """
    try:
        sync = _get_incident_sync()
        if sync is None:
            return json.dumps(
                {
                    "error": "Marketplace sync not available — "
                    "this tool requires marketplace mode (ARBITER_MARKETPLACE=1)."
                }
            )

        safe_id = Path(incident_id).name
        if safe_id != incident_id or ".." in incident_id:
            return json.dumps({"error": f"Invalid incident_id: {incident_id}"})

        record_path = INCIDENTS_ROOT / f"{safe_id}.json"
        if not record_path.exists():
            return json.dumps(
                {
                    "error": f"Incident record not found: {incident_id}. "
                    "Call save_incident_record first."
                }
            )

        record_data = json.loads(record_path.read_text())
        sync_result = sync.push_incident(record_path, record_data, incident_id)

        return json.dumps(sync_result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Get confidence assessment
# ---------------------------------------------------------------------------
@mcp.tool()
def get_confidence_assessment(collected_data_path: str) -> str:
    """Assess how strong the evidence is for the investigation's conclusions.

    Call this after gather_incident_context to understand how well the
    investigated sources support the conclusion. Returns per-source
    status, an evidence score, and a list of sources not investigated.

    Args:
        collected_data_path: Path to the collected-data JSON file
    """
    from arbiter.core.confidence import (
        _FIELD_LABELS,
        compute_data_completeness,
        format_confidence_markdown,
    )
    from arbiter.core.models import ConfidenceLevel, ConfidenceScore, DataSourceStatus

    try:
        path = Path(collected_data_path)
        if not path.exists():
            return json.dumps({"error": f"File not found: {collected_data_path}"})

        collected_data = json.loads(path.read_text())

        # Infer incident date and infrastructure profile
        time_range = collected_data.get("time_range", {})
        incident_date = time_range.get("from", "")
        infra = collected_data.get("infrastructure_profile")

        dc = compute_data_completeness(collected_data, incident_date, infrastructure_profile=infra)

        # Build a partial confidence score for display
        partial = ConfidenceScore(
            overall_level=ConfidenceLevel.MEDIUM,
            overall_score=dc.score,
            data_completeness=dc,
            root_cause_confidence=ConfidenceLevel.MEDIUM,
        )

        markdown = format_confidence_markdown(partial)

        # Build not-investigated list for the reader
        not_investigated = [
            {"source": field, "label": label}
            for field, label in _FIELD_LABELS.items()
            if getattr(dc, field) == DataSourceStatus.NOT_CHECKED
        ]

        return json.dumps(
            {
                "evidence_score": dc.score,
                "data_completeness_score": dc.score,  # backward-compat alias
                "sources": {field: getattr(dc, field).value for field in _FIELD_LABELS},
                "not_investigated": not_investigated,
                "markdown_preview": markdown,
                "guidance": "Use this evidence score along with your "
                "root_cause_confidence (high/medium/low) when calling "
                "save_incident_record. The 'not_investigated' list shows "
                "sources that were not checked — include these as "
                "verification gaps in the report.",
            },
            indent=2,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Search past incidents
# ---------------------------------------------------------------------------
@mcp.tool()
def search_past_incidents(
    service: str = "",
    error_signatures: str = "",
    root_cause_category: str = "",
    date_from: str = "",
    date_to: str = "",
    tags: str = "",
    max_results: int = 5,
) -> str:
    """Search for similar past incidents in the knowledge base.

    Use this when investigating a new incident to find historical precedent.
    Returns matches scored by similarity with explanations of why they matched.

    Args:
        service: Filter/match by primary service name
        error_signatures: Error patterns to match (JSON array or comma-separated)
        root_cause_category: Filter by root cause type
        date_from: Start date filter (ISO 8601)
        date_to: End date filter (ISO 8601)
        tags: Filter by tags (comma-separated)
        max_results: Maximum results to return (default: 5)
    """
    from arbiter.core.incident_store import IncidentStore, parse_csv_or_json_list

    try:
        sync = _get_incident_sync()
        if sync is not None:
            sync.pull_index()
    except Exception as e:
        logger.warning("Marketplace index sync failed: %s", e)

    try:
        incidents_dir = INCIDENTS_ROOT
        store = IncidentStore(incidents_dir)

        sig_list = parse_csv_or_json_list(error_signatures)
        tag_list = parse_csv_or_json_list(tags)

        # If signatures provided, use similarity search
        if sig_list:
            results = store.find_similar(
                signatures=sig_list,
                service=service,
                max_results=max_results,
            )
            return json.dumps(
                {"mode": "similarity", "total": len(results), "results": results},
                indent=2,
                default=str,
            )

        # Otherwise use filtered search
        results = store.search(
            service=service,
            root_cause_category=root_cause_category,
            date_from=date_from,
            date_to=date_to,
            tags=tag_list if tag_list else None,
        )
        return json.dumps(
            {"mode": "filter", "total": len(results), "results": results[:max_results]},
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: List incidents
# ---------------------------------------------------------------------------
@mcp.tool()
def list_incidents(
    service: str = "",
    status: str = "",
    severity: str = "",
    limit: int = 20,
) -> str:
    """List incidents in the knowledge base.

    Args:
        service: Filter by primary service
        status: Filter by status (investigating/resolved/closed)
        severity: Filter by severity (P1/P2/P3/P4)
        limit: Maximum results (default: 20)
    """
    from arbiter.core.incident_store import IncidentStore

    try:
        sync = _get_incident_sync()
        if sync is not None:
            sync.pull_index()
    except Exception as e:
        logger.warning("Marketplace index sync failed: %s", e)
        sync = None

    try:
        incidents_dir = INCIDENTS_ROOT
        store = IncidentStore(incidents_dir)

        # In marketplace mode, individual INC-*.json files may not exist —
        # list from the synced index instead.
        if sync is not None:
            index = store._load_index()
            if index and index.get("incidents"):
                results = []
                for inc_id, entry in index["incidents"].items():
                    if service and entry.get("service") != service:
                        continue
                    if status and entry.get("status") != status:
                        continue
                    if severity and entry.get("severity") != severity:
                        continue
                    entry_with_id = {"id": inc_id, **entry}
                    results.append(entry_with_id)
                results = results[:limit]
                return json.dumps(
                    {"total": len(results), "incidents": results, "source": "synced_index"},
                    indent=2,
                    default=str,
                )

        filters: dict = {}
        if service:
            filters["service"] = service
        if status:
            filters["status"] = status
        if severity:
            filters["severity"] = severity

        records = store.list_all(filters=filters if filters else None)
        records = records[:limit]

        incidents = [
            {
                "id": r.id,
                "title": r.title,
                "date": r.date,
                "service": r.service,
                "severity": r.severity.value,
                "status": r.status.value,
                "root_cause_category": r.root_cause_category.value,
                "resolved_by": r.resolved_by.value,
                "knowledge_source": r.knowledge_source.value,
                "report_path": r.report_path,
            }
            for r in records
        ]

        return json.dumps(
            {"total": len(incidents), "incidents": incidents},
            indent=2,
            default=str,
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Incident metrics
# ---------------------------------------------------------------------------
@mcp.tool()
def get_incident_metrics() -> str:
    """Get incident statistics — resolution times, root cause patterns, and trends.

    Returns: MTTR by service, root cause distribution, repeat incident rate,
    severity breakdown, resolution types, and timeline.
    """
    from arbiter.core.metrics import compute_metrics

    try:
        incidents_dir = INCIDENTS_ROOT
        metrics = compute_metrics(incidents_dir)
        return json.dumps(metrics, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Analyze causal chain
# ---------------------------------------------------------------------------
@mcp.tool()
def analyze_causal_chain(
    collected_data_path: str = "",
    service: str = "",
) -> str:
    """Map how the incident spread — from the initial trigger to the alert.

    Analyzes temporal correlations between deploys, DB errors, HTTP 500s,
    and alerts to build a cause-effect chain showing how an incident propagated.

    Args:
        collected_data_path: Path to a collected-data JSON file
        service: Service name (loads latest collected data if no path given)
    """
    from arbiter.core.causal_chain import chain_to_dict, detect_causal_chain

    try:
        # Load collected data
        if collected_data_path:
            data_path = Path(collected_data_path)
        elif service:
            data_dir = OUTPUT_ROOT / "collected-data"
            candidates = sorted(data_dir.glob(f"*-{service}*.json"), reverse=True)
            if not candidates:
                return json.dumps({"error": f"No collected data found for {service}"})
            data_path = candidates[0]
        else:
            return json.dumps({"error": "Provide collected_data_path or service name"})

        if not data_path.exists():
            return json.dumps({"error": f"File not found: {data_path}"})

        data = json.loads(data_path.read_text())
        chain = detect_causal_chain(data, GRAPH)

        result = chain_to_dict(chain)
        result["data_source"] = str(data_path)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Get service enrichment data
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def get_service_enrichment_data(
    service_name: str,
    sections: str = "",
    provider: str = "",
    detail_level: str = "summary",
) -> str:
    """Fetch architecture documentation and known failure patterns for the service.

    Call this when enrichment_hints in gather output shows available sections.
    Returns architecture docs, known bug patterns, data flows, and infrastructure
    details that help understand WHY errors happen.

    Args:
        service_name: Service name (e.g. "flags", "change-history")
        sections: Comma-separated section names to fetch (default: all available).
                  Common sections: overview, architecture, bug_categories, data_stores,
                  infrastructure, data_flows, low_level
        provider: Filter by provider name (default: all providers)
        detail_level: "summary" (default) or "full"
    """
    try:
        if not ENRICHMENT_PROVIDERS:
            return json.dumps({"message": "No enrichment providers available"})

        section_list = [s.strip() for s in sections.split(",") if s.strip()] or None
        max_chars = 2000 if detail_level == "summary" else None
        results = collect_enrichment(
            service_name,
            ENRICHMENT_PROVIDERS,
            sections=section_list,
            provider_name=provider or None,
            max_section_chars=max_chars,
        )

        if not results:
            return json.dumps(
                {
                    "message": f"No enrichment data available for '{service_name}'",
                    "available_providers": [
                        p.name for p in ENRICHMENT_PROVIDERS if p.is_available()
                    ],
                }
            )

        for r in results:
            r["detail_level"] = detail_level
        return json.dumps(results, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Get platform context
# ---------------------------------------------------------------------------
@mcp.tool()
@_track_tool_calls
def get_platform_context(topic: str, detail_level: str = "summary") -> str:
    """Get platform-wide context — how failures spread between services.

    Use this to understand how failures propagate across services and to validate
    cross-service hypotheses during investigation.

    Args:
        topic: Topic to retrieve. Available: failure-modes, communication,
               communication-low-level, overview, environments
        detail_level: "summary" (default) or "full"
    """
    try:
        if not ENRICHMENT_PROVIDERS:
            return json.dumps({"message": "No enrichment providers available"})

        for provider in ENRICHMENT_PROVIDERS:
            try:
                result = provider.get_platform_context(topic)
                if result:
                    if detail_level == "summary" and len(result) > 2000:
                        result = result[:2000].rsplit("\n\n", 1)[0]
                    return result
            except Exception as e:
                logger.warning("Platform context failed for %s: %s", provider.name, e)

        return json.dumps({"message": f"No platform context available for topic '{topic}'"})
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Tool: Validate investigation completeness
# ---------------------------------------------------------------------------
_EXCEPTION_RE = re.compile(
    r"(?i)"
    r"(?:[A-Z]\w*(?:Error|Exception|Fault|Timeout|Overflow|Panic))"  # PascalCase: TypeError, ConnectionError, etc.
    r"|(?:ABORTED|DEADLINE_EXCEEDED|UNAVAILABLE|PERMISSION_DENIED)"  # gRPC codes
    r"|(?:OOM|SIGKILL|SIGSEGV|segfault)"  # system-level
    r"|(?:connection refused|broken pipe)"  # network errors
)

_TEMPORAL_PHRASES = (
    "at the same time",
    "coincided with",
    "during the same",
    "simultaneously",
    "around the same",
)

_CAUSAL_PHRASES = (
    "caused by",
    "caused",
    "resulted in",
    "triggered",
    "led to",
    "because",
    "due to",
    "resulting from",
    "as a result",
    "causes",
    "leads to",
    "stems from",
)


@mcp.tool()
def validate_investigation(
    collected_data_path: str,
    root_cause_description: str,
) -> str:
    """Verify the investigation is complete before writing the report.

    Call this before save_incident_report to catch common investigation gaps:
    mechanism-only conclusions, pattern mismatches, wrong-service investigations,
    and observation-as-conclusion errors.

    Args:
        collected_data_path: Path to the collected-data JSON file
        root_cause_description: Your proposed root cause explanation
    """
    try:
        data = json.loads(Path(collected_data_path).read_text())
    except Exception as e:
        return json.dumps({"error": f"Cannot read collected data: {e}"})

    hints = data.get("analysis_hints", {})
    actions = data.get("investigation_actions", [])
    checks: list[dict] = []

    # Check 1: Did you find the actual error?
    traces = data.get("datadog_traces", [])
    error_traces = [
        t
        for t in traces
        if str(t.get("status_code", "")).startswith(("4", "5")) or t.get("error_type")
    ]
    opaque = [t for t in error_traces if not t.get("error_type") and not t.get("error_message")]
    span_actions = [
        a
        for a in actions
        if a.get("action") in ("child_spans_inspected", "child_spans_auto_prefetched")
    ]
    inspection_found_details = any(
        (a.get("error_spans") or 0) > 0 or (a.get("errors_with_details") or 0) > 0
        for a in span_actions
    )
    has_auto_prefetch = any("child_span_errors" in t for t in traces)
    has_exception_in_rc = bool(_EXCEPTION_RE.search(root_cause_description))

    spans_useful = (span_actions and inspection_found_details) or has_auto_prefetch
    if opaque and not spans_useful and not has_exception_in_rc:
        checks.append(
            {
                "name": "actual_error_found",
                "status": "fail",
                "message": (
                    f"{len(opaque)} error traces have no error details and child spans "
                    "were not inspected. The root cause description doesn't mention a "
                    "specific exception. You may be reporting the mechanism, not the cause."
                ),
            }
        )
    else:
        checks.append({"name": "actual_error_found", "status": "pass", "message": "OK"})

    # Check 2: Does the failure pattern match the root cause?
    det_eps = hints.get("deterministic_failure_endpoints", [])
    transient_words = ("contention", "intermittent", "timeout", "resource exhaustion", "pool")
    rc_lower = root_cause_description.lower()
    if det_eps and any(w in rc_lower for w in transient_words):
        checks.append(
            {
                "name": "pattern_match",
                "status": "warn",
                "message": (
                    f"Deterministic failure on {', '.join(det_eps[:3])} but root cause "
                    f"mentions transient-pattern language. Deterministic failures point to "
                    "code bugs or data corruption, not transient infrastructure."
                ),
            }
        )
    else:
        checks.append({"name": "pattern_match", "status": "pass", "message": "OK"})

    # Check 3: Did you investigate the right service?
    warnings = data.get("investigation_warnings", [])
    wrong_svc_warned = any(w.get("warning") == "service_may_not_handle_workload" for w in warnings)
    gather_actions = [a for a in actions if a.get("action") == "gather"]
    services_gathered = {a.get("service", "") for a in gather_actions}
    if wrong_svc_warned and len(services_gathered) <= 1:
        checks.append(
            {
                "name": "right_service",
                "status": "warn",
                "message": (
                    "Warning indicated this service may not handle the failing workload, "
                    "but only one service was investigated. Consider gathering context "
                    "for the upstream service."
                ),
            }
        )
    else:
        checks.append({"name": "right_service", "status": "pass", "message": "OK"})

    # Check 4: Did you separate observations from conclusions?
    has_temporal = any(p in rc_lower for p in _TEMPORAL_PHRASES)
    has_causal = any(p in rc_lower for p in _CAUSAL_PHRASES)
    if has_temporal and not has_causal:
        checks.append(
            {
                "name": "observation_vs_conclusion",
                "status": "warn",
                "message": (
                    "Root cause uses temporal correlation language without a causal mechanism. "
                    "Temporal overlap alone is not causation — explain HOW the observation "
                    "caused the failure, or state it as an observation rather than a cause."
                ),
            }
        )
    else:
        checks.append({"name": "observation_vs_conclusion", "status": "pass", "message": "OK"})

    # Check 5: Were configured inputs verified?
    infra = data.get("infrastructure_profile", {})
    queues = infra.get("message_queues", [])

    if queues and hints.get("error_rate", 0) == 0:
        vol = data.get("volume_metrics", {})
        queue_data = vol.get("queue")
        queue_checked = (
            isinstance(queue_data, dict) and queue_data.get("current_backlog") is not None
        )
        if not queue_checked:
            checks.append(
                {
                    "name": "configured_inputs_checked",
                    "status": "warn",
                    "message": (
                        "Service has message queue inputs but queue metrics were not "
                        "checked. With 0% HTTP errors, the failure may be in the "
                        "message processing path."
                    ),
                }
            )
        else:
            checks.append({"name": "configured_inputs_checked", "status": "pass", "message": "OK"})

    # Check 6: Was client-side considered for UI symptoms?
    infra = data.get("infrastructure_profile", {})
    frontend = infra.get("frontend", {})
    alert_text = (
        data.get("alert", "") or data.get("conversation", "") or data.get("alert_text", "") or ""
    )
    ui_keywords = (
        "not loading",
        "blank",
        "not displaying",
        "ui",
        "page",
        "frontend",
        "not showing",
    )
    has_ui_symptom = any(kw in alert_text.lower() for kw in ui_keywords)
    if has_ui_symptom and frontend:
        client_tools = {"fetch_rum_errors", "fetch_rum_performance"}
        session_tools = {tc.get("tool", "") for tc in _tool_calls}
        action_tools = {a.get("tool", "") for a in actions if a.get("tool")}
        all_tools_used = session_tools | action_tools
        client_tools_used = all_tools_used & client_tools
        if not client_tools_used:
            checks.append(
                {
                    "name": "client_side_considered",
                    "status": "warn",
                    "message": (
                        "Alert describes a UI symptom and service has frontend config, "
                        "but no client-side tools were used (RUM, CDN). Consider whether "
                        "the failure is client-side."
                    ),
                }
            )
        else:
            checks.append({"name": "client_side_considered", "status": "pass", "message": "OK"})

    # Check 7: Was signal provenance verified?
    noise_filters = data.get("noise_filters", [])
    if not noise_filters:
        svc_name = data.get("service_name", "")
        if svc_name:
            from arbiter.context.service_map import get_noise_filters as _get_nf

            noise_filters = _get_nf(svc_name)
    if noise_filters and traces:
        action_filtered = any(
            a.get("action") == "noise_filtered" or a.get("tag_filter") for a in actions
        )
        session_filtered = any(tc.get("tag_filter") for tc in _tool_calls)
        noise_filtered = action_filtered or session_filtered
        if not noise_filtered:
            labels = ", ".join(f.get("label", f.get("pattern", "")) for f in noise_filters[:2])
            checks.append(
                {
                    "name": "signal_provenance",
                    "status": "warn",
                    "message": (
                        f"Service has known noise sources ({labels}) but traces were not "
                        "filtered. Verify the error traces are from affected customers, "
                        "not background noise. Use tag_filter on fetch_datadog_traces to exclude."
                    ),
                }
            )
        else:
            checks.append({"name": "signal_provenance", "status": "pass", "message": "OK"})

    passed = all(c["status"] == "pass" for c in checks)
    return json.dumps({"passed": passed, "checks": checks}, indent=2)


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------


@mcp.tool()
def get_version() -> str:
    """Get current Arbiter version and check for updates.

    Returns current version, latest available version, and whether an update
    is available. Use /update skill to apply updates.
    """
    from arbiter.core.version_check import check_latest_version, get_local_version, get_update_state

    current = get_local_version()
    result: dict = {"current_version": current}
    state = get_update_state()
    if state is not None and state.current_version != current:
        state = None
    if state is None:
        state = check_latest_version()
    if state:
        result["latest_version"] = state.latest_version
        result["update_available"] = state.update_available
        if state.release_url:
            result["release_url"] = state.release_url
    else:
        result["latest_version"] = "unknown (offline)"
        result["update_available"] = False
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
def run_server():
    mcp.run()


if __name__ == "__main__":
    run_server()
