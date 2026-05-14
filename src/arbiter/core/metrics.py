"""Incident metrics — computed from the knowledge base."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from arbiter.core.incident_store import IncidentStore


def compute_metrics(incidents_dir: Path) -> dict:
    """Compute incident metrics from the knowledge base.

    Returns a dict with:
    - overview: total counts, date range
    - by_service: incidents, MTTR per service
    - by_root_cause: distribution of root cause categories
    - by_resolution: how incidents were resolved
    - by_severity: P1/P2/P3/P4 breakdown
    - repeat_incidents: services with multiple incidents
    - mttr: overall and per-service mean time to resolve
    - timeline: incidents per month
    """
    store = IncidentStore(incidents_dir)
    records = store.list_all()

    if not records:
        return {"overview": {"total_incidents": 0}, "message": "No incidents in knowledge base"}

    # --- Overview ---
    dates = sorted(r.date for r in records if r.date)
    overview = {
        "total_incidents": len(records),
        "date_range": f"{dates[0]} to {dates[-1]}" if dates else "",
        "services_affected": len(set(r.service for r in records)),
        "resolved": sum(1 for r in records if r.status.value == "resolved"),
        "investigating": sum(1 for r in records if r.status.value == "investigating"),
    }

    # --- By service ---
    service_counter: Counter = Counter()
    service_mttr: dict[str, list[int]] = {}
    for r in records:
        service_counter[r.service] += 1
        if r.mttr_minutes and r.mttr_minutes > 0:
            service_mttr.setdefault(r.service, []).append(r.mttr_minutes)

    by_service = []
    for svc, count in service_counter.most_common():
        mttr_values = service_mttr.get(svc, [])
        avg_mttr = round(sum(mttr_values) / len(mttr_values)) if mttr_values else None
        by_service.append(
            {
                "service": svc,
                "incident_count": count,
                "avg_mttr_minutes": avg_mttr,
                "avg_mttr_hours": round(avg_mttr / 60, 1) if avg_mttr else None,
            }
        )

    # --- By root cause ---
    root_cause_counter: Counter = Counter()
    for r in records:
        root_cause_counter[r.root_cause_category.value] += 1

    by_root_cause = [
        {
            "category": cat,
            "count": count,
            "percentage": round(count / len(records) * 100),
        }
        for cat, count in root_cause_counter.most_common()
    ]

    # --- By resolution ---
    resolution_counter: Counter = Counter()
    for r in records:
        resolution_counter[r.resolved_by.value] += 1

    by_resolution = [
        {
            "type": res_type,
            "count": count,
            "percentage": round(count / len(records) * 100),
        }
        for res_type, count in resolution_counter.most_common()
    ]

    # --- By severity ---
    severity_counter: Counter = Counter()
    for r in records:
        severity_counter[r.severity.value] += 1

    by_severity = {sev: severity_counter.get(sev, 0) for sev in ["P1", "P2", "P3", "P4"]}

    # --- Repeat incidents ---
    repeat_incidents = []
    for svc, count in service_counter.items():
        if count > 1:
            svc_records = [r for r in records if r.service == svc]
            root_causes = [r.root_cause_category.value for r in svc_records]
            repeat_incidents.append(
                {
                    "service": svc,
                    "incident_count": count,
                    "root_causes": root_causes,
                    "same_root_cause": len(set(root_causes)) == 1,
                }
            )

    repeat_rate = (
        round(sum(r["incident_count"] for r in repeat_incidents) / len(records) * 100)
        if repeat_incidents
        else 0
    )

    # --- MTTR ---
    all_mttr = [r.mttr_minutes for r in records if r.mttr_minutes and r.mttr_minutes > 0]
    mttr = {
        "overall_avg_minutes": round(sum(all_mttr) / len(all_mttr)) if all_mttr else None,
        "overall_avg_hours": round(sum(all_mttr) / len(all_mttr) / 60, 1) if all_mttr else None,
        "min_minutes": min(all_mttr) if all_mttr else None,
        "max_minutes": max(all_mttr) if all_mttr else None,
        "incidents_with_mttr": len(all_mttr),
    }

    # --- Timeline (incidents per month) ---
    month_counter: Counter = Counter()
    for r in records:
        if r.date and len(r.date) >= 7:
            month_counter[r.date[:7]] += 1

    timeline = [{"month": month, "count": count} for month, count in sorted(month_counter.items())]

    # --- By confidence ---
    confidence_counter: Counter = Counter()
    confidence_scores: list[int] = []
    for r in records:
        if r.confidence:
            confidence_counter[r.confidence.overall_level.value] += 1
            confidence_scores.append(r.confidence.overall_score)
        else:
            confidence_counter["unscored"] += 1

    by_confidence = [
        {
            "level": level,
            "count": count,
            "percentage": round(count / len(records) * 100),
        }
        for level, count in confidence_counter.most_common()
    ]
    avg_confidence = (
        round(sum(confidence_scores) / len(confidence_scores)) if confidence_scores else None
    )

    # --- By knowledge source ---
    from arbiter.core.models import KnowledgeSource

    ks_counter: Counter = Counter()
    for r in records:
        ks = getattr(r, "knowledge_source", KnowledgeSource.ARBITER)
        ks_counter[ks.value] += 1

    by_knowledge_source = [
        {
            "source": source,
            "count": count,
            "percentage": round(count / len(records) * 100),
        }
        for source, count in ks_counter.most_common()
    ]

    return {
        "overview": overview,
        "by_service": by_service,
        "by_root_cause": by_root_cause,
        "by_resolution": by_resolution,
        "by_severity": by_severity,
        "by_confidence": {
            "distribution": by_confidence,
            "avg_score": avg_confidence,
            "scored_count": len(confidence_scores),
        },
        "repeat_incidents": {
            "services": repeat_incidents,
            "repeat_rate_pct": repeat_rate,
        },
        "by_knowledge_source": by_knowledge_source,
        "mttr": mttr,
        "timeline": timeline,
    }


def format_metrics_text(metrics: dict) -> str:
    """Format metrics as human-readable text for CLI output."""
    if metrics.get("message"):
        return f"  {metrics['message']}"

    lines = []
    ov = metrics["overview"]
    lines.append(f"  Incident Knowledge Base — {ov['total_incidents']} incidents")
    lines.append(f"  Period: {ov['date_range']}")
    lines.append(f"  Services affected: {ov['services_affected']}")
    lines.append(f"  Resolved: {ov['resolved']}  |  Investigating: {ov['investigating']}")
    lines.append("")

    mttr = metrics["mttr"]
    if mttr["overall_avg_minutes"]:
        lines.append("  MTTR (mean time to resolve)")
        lines.append(f"  {'─' * 40}")
        lines.append(f"  Average: {mttr['overall_avg_hours']}h ({mttr['overall_avg_minutes']} min)")
        lines.append(f"  Min: {mttr['min_minutes']} min  |  Max: {mttr['max_minutes']} min")
        lines.append(f"  Tracked: {mttr['incidents_with_mttr']}/{ov['total_incidents']} incidents")
        lines.append("")

    lines.append("  Incidents by service")
    lines.append(f"  {'─' * 40}")
    for svc in metrics["by_service"]:
        mttr_str = f"  avg MTTR: {svc['avg_mttr_hours']}h" if svc["avg_mttr_hours"] else ""
        lines.append(f"  {svc['incident_count']:>3}x  {svc['service']}{mttr_str}")
    lines.append("")

    lines.append("  Root cause distribution")
    lines.append(f"  {'─' * 40}")
    for rc in metrics["by_root_cause"]:
        lines.append(f"  {rc['percentage']:>3}%  {rc['category']} ({rc['count']}x)")
    lines.append("")

    lines.append("  Resolution types")
    lines.append(f"  {'─' * 40}")
    for res in metrics["by_resolution"]:
        lines.append(f"  {res['percentage']:>3}%  {res['type']} ({res['count']}x)")
    lines.append("")

    lines.append("  Severity breakdown")
    lines.append(f"  {'─' * 40}")
    for sev in ["P1", "P2", "P3", "P4"]:
        count = metrics["by_severity"].get(sev, 0)
        if count:
            lines.append(f"  {sev}: {count}")
    lines.append("")

    ri = metrics["repeat_incidents"]
    if ri["services"]:
        lines.append(f"  Repeat incidents ({ri['repeat_rate_pct']}% of total)")
        lines.append(f"  {'─' * 40}")
        for s in ri["services"]:
            same = "SAME root cause" if s["same_root_cause"] else "different root causes"
            lines.append(f"  {s['service']}: {s['incident_count']}x — {same}")
        lines.append("")

    conf = metrics.get("by_confidence", {})
    if conf.get("distribution"):
        avg_str = f"  avg score: {conf['avg_score']}/100" if conf["avg_score"] else ""
        lines.append(f"  Analysis confidence ({conf['scored_count']} scored){avg_str}")
        lines.append(f"  {'─' * 40}")
        for c in conf["distribution"]:
            lines.append(f"  {c['percentage']:>3}%  {c['level']} ({c['count']}x)")
        lines.append("")

    return "\n".join(lines)
