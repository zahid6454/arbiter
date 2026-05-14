"""Incident analyzer — trace aggregation."""

from __future__ import annotations


def aggregate_traces(traces: list[dict], group_by: str = "pod_name") -> list[dict]:
    """Group traces by any key and compute per-group error stats.

    Returns a list sorted by error count descending:
    [{"key": "pod-abc", "total": 119, "errors": 53, "successes": 66, "error_rate": 0.445}]
    """
    groups: dict[str, dict] = {}
    for trace in traces:
        key = str(trace.get(group_by, "") or "<missing>")
        if key not in groups:
            groups[key] = {"total": 0, "errors": 0}
        groups[key]["total"] += 1

        status = str(trace.get("status_code", ""))
        if status.startswith(("4", "5")) or trace.get("error_type"):
            groups[key]["errors"] += 1

    result = []
    for key, stats in groups.items():
        total = stats["total"]
        errors = stats["errors"]
        successes = total - errors
        result.append(
            {
                "key": key,
                "total": total,
                "errors": errors,
                "successes": successes,
                "error_rate": round(errors / total, 3) if total > 0 else 0.0,
            }
        )

    return sorted(result, key=lambda g: -g["errors"])
