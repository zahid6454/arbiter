"""Incident knowledge base — stores structured incident records and finds similar past incidents."""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from arbiter.core.models import (
    IncidentRecord,
    IncidentStatus,
    KnowledgeSource,
    ResolutionType,
    RootCauseCategory,
    Severity,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Error signature extraction
# ---------------------------------------------------------------------------


def extract_error_signatures(collected_data: dict) -> list[str]:
    """Extract normalized error signatures from collected incident data.

    Scans DB errors, APM traces, and log messages. Returns a deduplicated,
    sorted list of fingerprint strings.
    """
    signatures: set[str] = set()

    # From DB errors (primary + upstream)
    for entry in collected_data.get("datadog_db_errors", []):
        sig = normalize_error_message(entry.get("message", ""))
        if sig:
            signatures.add(sig)
    for svc_errors in collected_data.get("upstream_db_errors", {}).values():
        for entry in (svc_errors if isinstance(svc_errors, list) else []):
            sig = normalize_error_message(entry.get("message", ""))
            if sig:
                signatures.add(sig)

    # From APM traces (primary + upstream)
    for trace in collected_data.get("datadog_traces", []):
        sig = _signature_from_trace(trace)
        if sig:
            signatures.add(sig)
    for svc_traces in collected_data.get("upstream_traces", {}).values():
        for trace in (svc_traces if isinstance(svc_traces, list) else []):
            sig = _signature_from_trace(trace)
            if sig:
                signatures.add(sig)

    # From log messages (ERROR/CRITICAL only)
    for log in collected_data.get("datadog_logs", []):
        if log.get("level") in ("ERROR", "CRITICAL"):
            sig = normalize_error_message(log.get("message", ""))
            if sig:
                signatures.add(sig)

    return sorted(signatures)


def normalize_error_message(msg: str) -> str:
    """Normalize an error message into a fingerprint."""
    if not msg:
        return ""
    first_line = msg.split("\n")[0].strip()
    if not first_line:
        return ""
    # UUID normalization
    normalized = re.sub(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "<UUID>",
        first_line,
    )
    # Large numeric IDs
    normalized = re.sub(r"\d{10,}", "<ID>", normalized)
    # Constraint key values: (flag_id, key)=(538498, off) → (flag_id, key)=(<VALUES>)
    normalized = re.sub(r"\((\w+(?:,\s*\w+)*)\)=\([^)]+\)", r"(\1)=(<VALUES>)", normalized)
    # Pod names: service-abc12345de-xyz12 → <POD>
    normalized = re.sub(r"[a-z]+-[a-f0-9]{8,10}-[a-z0-9]{5}", "<POD>", normalized)
    return normalized[:200]


def _signature_from_trace(trace: dict) -> str:
    """Extract a signature from an APM trace dict (error traces only)."""
    error_type = trace.get("error_type", "")
    http_path = trace.get("http_path", "")
    status = str(trace.get("status_code", ""))

    if not status.startswith(("4", "5")) and not error_type:
        return ""

    if error_type and error_type != "server_error" and http_path:
        return f"{error_type} on {http_path}"
    elif http_path and status:
        return f"{status} on {http_path}"
    return ""


# ---------------------------------------------------------------------------
# ID generation
# ---------------------------------------------------------------------------


def generate_incident_id(date: str, service: str, suffix: str = "") -> str:
    """Generate a deterministic incident ID.

    Format: INC-{date}-{service}[-{suffix}]
    Example: INC-2026-0409-catalog-api-high-db-conn
    """
    date_part = date.replace("-", "")[:8]
    if len(date_part) == 8:
        date_part = f"{date_part[:4]}-{date_part[4:]}"

    from arbiter.core.models import slugify

    svc_part = slugify(service)

    parts = ["INC", date_part, svc_part]
    if suffix:
        slug = slugify(suffix)
        svc_prefix = svc_part + "-"
        if slug.startswith(svc_prefix):
            slug = slug[len(svc_prefix):]
        elif slug.startswith(svc_part):
            slug = slug[len(svc_part):].lstrip("-")
        else:
            svc_segments = svc_part.split("-")
            for n in range(len(svc_segments) - 1, 0, -1):
                partial = "-".join(svc_segments[:n]) + "-"
                if slug.startswith(partial):
                    slug = slug[len(partial):]
                    break
        if slug:
            parts.append(slug)

    return "-".join(parts)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def parse_csv_or_json_list(value: str) -> list[str]:
    """Parse a string that may be a JSON array or comma-separated values."""
    if not value or not value.strip():
        return []

    value = value.strip()

    if value.startswith("["):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except json.JSONDecodeError:
            pass

    return [item.strip() for item in value.split(",") if item.strip()]


# ---------------------------------------------------------------------------
# Incident Store
# ---------------------------------------------------------------------------


class IncidentStore:
    """File-based incident knowledge base.

    Stores individual incident records as JSON files in a directory,
    with an index for fast search and similarity matching.
    """

    def __init__(self, incidents_dir: Path):
        self.incidents_dir = incidents_dir
        self.index_path = incidents_dir / "index.json"

    def save(self, record: IncidentRecord) -> Path:
        """Save an incident record to disk and rebuild the index."""
        self.incidents_dir.mkdir(parents=True, exist_ok=True)

        now = datetime.now(UTC).isoformat()
        if not record.created_at:
            record.created_at = now
        record.updated_at = now

        data = asdict(record)
        for key in ("severity", "status", "root_cause_category", "resolved_by", "knowledge_source"):
            if hasattr(data.get(key), "value"):
                data[key] = data[key].value
            elif isinstance(data.get(key), str):
                pass

        if record.confidence is not None:
            from arbiter.core.confidence import confidence_to_dict

            data["confidence"] = confidence_to_dict(record.confidence)
        else:
            data["confidence"] = None

        file_path = self.incidents_dir / f"{record.id}.json"
        tmp_path = file_path.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps(data, indent=2, default=str))
        os.replace(str(tmp_path), str(file_path))

        self.rebuild_index()

        return file_path

    def load(self, incident_id: str) -> IncidentRecord | None:
        """Load a single incident record by ID."""
        file_path = self.incidents_dir / f"{incident_id}.json"
        if not file_path.exists():
            return None

        data = json.loads(file_path.read_text())
        return _dict_to_record(data)

    def list_all(self, filters: dict | None = None) -> list[IncidentRecord]:
        """List all incident records, optionally filtered."""
        if not self.incidents_dir.exists():
            return []

        records = []
        for path in sorted(self.incidents_dir.glob("INC-*.json")):
            try:
                data = json.loads(path.read_text())
                record = _dict_to_record(data)

                if filters:
                    if filters.get("service") and record.service != filters["service"]:
                        continue
                    if filters.get("severity") and record.severity.value != filters["severity"]:
                        continue
                    if filters.get("status") and record.status.value != filters["status"]:
                        continue

                records.append(record)
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("Failed to load incident %s: %s", path.name, e)

        return records

    def delete(self, incident_id: str) -> bool:
        """Delete an incident record and rebuild the index."""
        file_path = self.incidents_dir / f"{incident_id}.json"
        if not file_path.exists():
            return False

        file_path.unlink()
        self.rebuild_index()
        return True

    def rebuild_index(self) -> None:
        """Rebuild index.json from individual incident files."""
        index = {
            "version": 1,
            "rebuilt_at": datetime.now(UTC).isoformat(),
            "incidents": {},
        }

        if self.incidents_dir.exists():
            for path in sorted(self.incidents_dir.glob("INC-*.json")):
                try:
                    data = json.loads(path.read_text())
                    inc_id = data["id"]
                    index["incidents"][inc_id] = {
                        "title": data.get("title", ""),
                        "date": data.get("date", ""),
                        "service": data.get("service", ""),
                        "severity": data.get("severity", ""),
                        "status": data.get("status", ""),
                        "root_cause_category": data.get("root_cause_category", ""),
                        "root_cause_detail": data.get("root_cause_detail", ""),
                        "resolved_by": data.get("resolved_by", ""),
                        "error_signatures": data.get("error_signatures", []),
                        "affected_service_names": [
                            s.get("service", "") if isinstance(s, dict) else str(s)
                            for s in data.get("affected_services", [])
                        ],
                        "affected_tables": data.get("affected_tables", []),
                        "affected_endpoints": data.get("affected_endpoints", []),
                        "tags": data.get("tags", []),
                        "report_path": data.get("report_path", ""),
                        "confidence_level": (
                            data.get("confidence", {}).get("overall_level")
                            if data.get("confidence")
                            else None
                        ),
                        "confidence_score": (
                            data.get("confidence", {}).get("overall_score")
                            if data.get("confidence")
                            else None
                        ),
                        "knowledge_source": data.get("knowledge_source", "arbiter"),
                        "remediation_tickets": data.get("remediation_tickets", []),
                    }
                except (json.JSONDecodeError, KeyError) as e:
                    logger.warning("Failed to index %s: %s", path.name, e)

        index["incident_count"] = len(index["incidents"])
        self._save_index(index)

    def find_similar(
        self,
        signatures: list[str],
        service: str = "",
        tables: list[str] | None = None,
        endpoints: list[str] | None = None,
        max_results: int = 5,
        min_score: float = 0.1,
    ) -> list[dict]:
        """Find similar past incidents using error signature matching."""
        index = self._load_index()
        if not index.get("incidents"):
            return []

        query_sig_set = set(signatures)
        query_resource_set = set((tables or []) + (endpoints or []))
        results = []

        for inc_id, inc_data in index["incidents"].items():
            score = 0.0
            matches: dict = {}

            past_sigs = set(inc_data.get("error_signatures", []))
            if query_sig_set and past_sigs:
                intersection = query_sig_set & past_sigs
                union = query_sig_set | past_sigs
                jaccard = len(intersection) / len(union) if union else 0
                score += jaccard * 0.5
                if intersection:
                    matches["signatures"] = sorted(intersection)

            past_service = inc_data.get("service", "")
            past_affected = set(inc_data.get("affected_service_names", []))
            if service and service == past_service:
                score += 0.3
                matches["service"] = "exact_match"
            elif service and service in past_affected:
                score += 0.15
                matches["service"] = "in_affected"

            past_resources = set(
                inc_data.get("affected_tables", []) + inc_data.get("affected_endpoints", [])
            )
            if query_resource_set and past_resources:
                res_intersection = query_resource_set & past_resources
                res_union = query_resource_set | past_resources
                res_jaccard = len(res_intersection) / len(res_union) if res_union else 0
                score += res_jaccard * 0.2
                if res_intersection:
                    matches["tables_endpoints"] = sorted(res_intersection)

            if score >= min_score and matches:
                result = {
                    "incident_id": inc_id,
                    "score": round(score, 3),
                    "title": inc_data.get("title", ""),
                    "date": inc_data.get("date", ""),
                    "status": inc_data.get("status", ""),
                    "root_cause_category": inc_data.get("root_cause_category", ""),
                    "root_cause_detail": inc_data.get("root_cause_detail", ""),
                    "resolved_by": inc_data.get("resolved_by", ""),
                    "report_path": inc_data.get("report_path", ""),
                    "confidence_level": inc_data.get("confidence_level"),
                    "confidence_score": inc_data.get("confidence_score"),
                    "knowledge_source": inc_data.get("knowledge_source", "arbiter"),
                    "matches": matches,
                }
                results.append(result)

        results.sort(key=lambda r: -r["score"])
        return results[:max_results]

    def search(
        self,
        service: str = "",
        root_cause_category: str = "",
        date_from: str = "",
        date_to: str = "",
        tags: list[str] | None = None,
    ) -> list[dict]:
        """Search incidents by filters. All filters are AND-combined."""
        index = self._load_index()
        results = []

        for inc_id, inc_data in index.get("incidents", {}).items():
            if service and inc_data.get("service") != service:
                continue
            if root_cause_category and inc_data.get("root_cause_category") != root_cause_category:
                continue
            inc_date = inc_data.get("date", "")
            if date_from and inc_date < date_from:
                continue
            if date_to and inc_date > date_to:
                continue
            if tags:
                inc_tags = set(inc_data.get("tags", []))
                if not inc_tags & set(tags):
                    continue

            results.append(
                {
                    "incident_id": inc_id,
                    "title": inc_data.get("title", ""),
                    "date": inc_data.get("date", ""),
                    "service": inc_data.get("service", ""),
                    "severity": inc_data.get("severity", ""),
                    "root_cause_category": inc_data.get("root_cause_category", ""),
                    "root_cause_detail": inc_data.get("root_cause_detail", ""),
                    "resolved_by": inc_data.get("resolved_by", ""),
                    "report_path": inc_data.get("report_path", ""),
                    "confidence_level": inc_data.get("confidence_level"),
                    "confidence_score": inc_data.get("confidence_score"),
                    "knowledge_source": inc_data.get("knowledge_source", "arbiter"),
                }
            )

        return sorted(results, key=lambda r: r.get("date", ""), reverse=True)

    def _load_index(self) -> dict:
        """Load index from disk, or return empty if not found."""
        if not self.index_path.exists():
            return {"version": 1, "incidents": {}, "incident_count": 0}
        try:
            return json.loads(self.index_path.read_text())
        except (json.JSONDecodeError, OSError):
            return {"version": 1, "incidents": {}, "incident_count": 0}

    def _save_index(self, index: dict) -> None:
        """Atomically write index to disk."""
        self.incidents_dir.mkdir(parents=True, exist_ok=True)
        tmp_path = self.index_path.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps(index, indent=2, default=str))
        os.replace(str(tmp_path), str(self.index_path))


def _dict_to_record(data: dict) -> IncidentRecord:
    """Convert a JSON dict back to an IncidentRecord."""
    confidence = None
    if data.get("confidence"):
        from arbiter.core.confidence import dict_to_confidence

        confidence = dict_to_confidence(data["confidence"])

    return IncidentRecord(
        id=data["id"],
        title=data["title"],
        date=data["date"],
        service=data["service"],
        severity=Severity(data.get("severity", "P2")),
        status=IncidentStatus(data.get("status", "investigating")),
        root_cause_category=RootCauseCategory(data.get("root_cause_category", "unknown")),
        root_cause_detail=data.get("root_cause_detail", ""),
        error_signatures=data.get("error_signatures", []),
        affected_services=data.get("affected_services", []),
        affected_tables=data.get("affected_tables", []),
        affected_endpoints=data.get("affected_endpoints", []),
        resolved_by=ResolutionType(data.get("resolved_by", "unresolved")),
        mttr_minutes=data.get("mttr_minutes"),
        related_prs=data.get("related_prs", []),
        remediation_tickets=data.get("remediation_tickets", []),
        collected_data_path=data.get("collected_data_path", ""),
        report_path=data.get("report_path", ""),
        tags=data.get("tags", []),
        created_at=data.get("created_at", ""),
        updated_at=data.get("updated_at", ""),
        confidence=confidence,
        knowledge_source=_parse_knowledge_source(data.get("knowledge_source", "arbiter")),
    )


def _parse_knowledge_source(raw: str) -> KnowledgeSource:
    try:
        return KnowledgeSource(raw)
    except ValueError:
        return KnowledgeSource.ARBITER
