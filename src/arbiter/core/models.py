"""Core data models shared across all collectors and analyzers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


def slugify(text: str, max_len: int = 60, *, strip_leading_date: bool = False) -> str:
    """Convert text to a URL/filename-safe slug, truncating at word boundaries."""
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    if strip_leading_date:
        slug = re.sub(r"^(\d{4}-\d{2}-\d{2})-?", "", slug).strip("-")
    if len(slug) > max_len:
        slug = slug[:max_len].rsplit("-", 1)[0]
    return slug


class Severity(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class EventSource(str, Enum):
    DATADOG = "datadog"
    SENTRY = "sentry"
    GCP = "gcp"
    OPSGENIE = "opsgenie"
    GIT = "git"
    GITHUB = "github"
    MANUAL = "manual"


class LogLevel(str, Enum):
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    DEBUG = "DEBUG"


class RootCauseCategory(str, Enum):
    DATABASE_CONTENTION = "database_contention"
    DEPLOY_REGRESSION = "deploy_regression"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    THIRD_PARTY = "third_party"
    CONFIG_CHANGE = "config_change"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    CODE_BUG = "code_bug"
    EXTERNAL_CLIENT_MISCONFIGURATION = "external_client_misconfiguration"
    UNKNOWN = "unknown"


class ResolutionType(str, Enum):
    CODE_FIX = "code_fix"
    ROLLBACK = "rollback"
    CONFIG_CHANGE = "config_change"
    RESTART = "restart"
    SELF_HEALED = "self_healed"
    MANUAL_INTERVENTION = "manual_intervention"
    UNRESOLVED = "unresolved"


class IncidentStatus(str, Enum):
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class ConfidenceLevel(str, Enum):
    HIGH = "high"  # Root cause confirmed via code trace + direct evidence
    MEDIUM = "medium"  # Strong evidence but not fully verified
    LOW = "low"  # Speculative, significant data gaps


class KnowledgeSource(str, Enum):
    ARBITER = "arbiter"
    HUMAN = "human"
    ARBITER_AND_HUMAN = "arbiter & human"


class DataSourceStatus(str, Enum):
    AVAILABLE = "available"  # Data returned
    EMPTY = "empty"  # Queried, nothing found (within retention)
    EXPIRED = "expired"  # Retention window exceeded
    UNAVAILABLE = "unavailable"  # Collector errored or not run
    NOT_CHECKED = "not_checked"  # Source not queried
    NOT_RELEVANT = "not_relevant"  # Service infrastructure doesn't use this source


class EventType(str, Enum):
    DEPLOY = "deploy"
    DB_ERROR = "db_error"
    HTTP_ERROR = "http_error"
    SERVICE_ERROR = "service_error"
    ALERT = "alert"
    INFRASTRUCTURE_CHANGE = "infrastructure_change"
    WORKLOAD_BURST = "workload_burst"


@dataclass
class TimelineEvent:
    """A single event in the incident timeline.

    All collectors produce these. The timeline builder merges and
    correlates them across sources.
    """

    timestamp: str
    message: str
    source: EventSource
    service: str = ""
    level: LogLevel | None = None
    metadata: dict = field(default_factory=dict)

    def sort_key(self) -> str:
        return self.timestamp or ""


@dataclass
class LogEntry:
    """A structured log entry from any observability platform."""

    timestamp: str
    level: LogLevel
    message: str
    service: str
    source: EventSource
    environment: str = ""
    host: str = ""
    container: str = ""
    pod: str = ""
    trace_id: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class AlertInfo:
    """An alert from OpsGenie, Datadog monitors, or similar."""

    id: str
    title: str
    severity: Severity
    status: str  # triggered, acknowledged, resolved
    source: EventSource
    created_at: str = ""
    acknowledged_at: str = ""
    resolved_at: str = ""
    responders: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    message: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass
class ErrorGroup:
    """A group of similar errors, deduplicated by pattern."""

    pattern: str
    count: int
    level: LogLevel
    first_seen: str
    last_seen: str
    services: list[str] = field(default_factory=list)
    sample_message: str = ""


@dataclass
class Traceback:
    """A reconstructed traceback/stack trace."""

    timestamp: str
    service: str
    exception_type: str
    exception_detail: str
    full_traceback: str
    pod: str = ""
    source: EventSource = EventSource.DATADOG


@dataclass
class ServiceInfo:
    """Service metadata from the dependency graph."""

    name: str
    depends_on: list[str] = field(default_factory=list)
    depended_on_by: list[str] = field(default_factory=list)
    stack: str = ""
    description: str = ""


@dataclass
class BlastRadiusEntry:
    """A service affected by an incident."""

    service: str
    role: str  # primary, upstream, downstream
    impact: str
    error_count: int = 0
    warning_count: int = 0


@dataclass
class IncidentContext:
    """Complete incident context assembled from all sources.

    This is what gets passed to the report renderer.
    """

    title: str
    severity: Severity
    primary_service: str
    time_range_start: str
    time_range_end: str
    date: str = ""

    # Collected data
    timeline: list[TimelineEvent] = field(default_factory=list)
    logs: list[LogEntry] = field(default_factory=list)
    alerts: list[AlertInfo] = field(default_factory=list)
    error_groups: list[ErrorGroup] = field(default_factory=list)
    tracebacks: list[Traceback] = field(default_factory=list)
    blast_radius: list[BlastRadiusEntry] = field(default_factory=list)

    # Cross-service data
    cross_service_logs: dict[str, list[LogEntry]] = field(default_factory=dict)

    # Git context
    git_context: dict = field(default_factory=dict)

    # Conversation/thread
    conversation: list[dict] = field(default_factory=list)

    # Service info
    service_info: ServiceInfo | None = None

    # Raw context for Claude analysis
    summary: str = ""
    root_cause: str = ""
    action_items: list[dict] = field(default_factory=list)
    preventive_measures: list[str] = field(default_factory=list)


@dataclass
class IncidentRecord:
    """A structured incident record for the knowledge base."""

    id: str  # e.g., "INC-2026-0409-catalog-api"
    title: str
    date: str  # ISO 8601 date, e.g., "2026-04-09"
    service: str  # primary service canonical name
    severity: Severity
    status: IncidentStatus

    # Root cause
    root_cause_category: RootCauseCategory
    root_cause_detail: str = ""

    # Error fingerprints (normalized patterns)
    error_signatures: list[str] = field(default_factory=list)

    # Affected services with roles
    affected_services: list[dict] = field(default_factory=list)

    # Specific resources
    affected_tables: list[str] = field(default_factory=list)
    affected_endpoints: list[str] = field(default_factory=list)

    # Resolution
    resolved_by: ResolutionType = ResolutionType.UNRESOLVED
    mttr_minutes: int | None = None

    # References
    related_prs: list[str] = field(default_factory=list)
    remediation_tickets: list[dict] = field(default_factory=list)
    collected_data_path: str = ""
    report_path: str = ""

    # Metadata
    tags: list[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    # Confidence assessment
    confidence: ConfidenceScore | None = None

    # Knowledge attribution
    knowledge_source: KnowledgeSource = KnowledgeSource.ARBITER


@dataclass
class ChainLink:
    """A single event in a causal chain."""

    timestamp: str
    event_type: EventType
    service: str
    description: str
    evidence: list[str] = field(default_factory=list)
    delta_seconds: float | None = None
    delta_human: str = ""
    confidence: float = 1.0
    metadata: dict = field(default_factory=dict)


@dataclass
class CausalChain:
    """An ordered sequence of causally linked events."""

    links: list[ChainLink] = field(default_factory=list)
    root_cause_index: int | None = None
    detection_delay_seconds: float | None = None
    potential_triggers: list[ChainLink] = field(default_factory=list)
    summary: str = ""


@dataclass
class DataCompleteness:
    """Auto-computed data availability from collected incident data."""

    logs: DataSourceStatus = DataSourceStatus.NOT_CHECKED
    traces: DataSourceStatus = DataSourceStatus.NOT_CHECKED
    db_errors: DataSourceStatus = DataSourceStatus.NOT_CHECKED
    upstream_traces: DataSourceStatus = DataSourceStatus.NOT_CHECKED
    upstream_db_errors: DataSourceStatus = DataSourceStatus.NOT_CHECKED
    cross_service_logs: DataSourceStatus = DataSourceStatus.NOT_CHECKED
    alerts: DataSourceStatus = DataSourceStatus.NOT_CHECKED
    github_deploys: DataSourceStatus = DataSourceStatus.NOT_CHECKED
    github_workflow_deploys: DataSourceStatus = DataSourceStatus.NOT_CHECKED
    git_context: DataSourceStatus = DataSourceStatus.NOT_CHECKED
    source_code: DataSourceStatus = DataSourceStatus.NOT_CHECKED
    causal_chain: DataSourceStatus = DataSourceStatus.NOT_CHECKED
    gke_operations: DataSourceStatus = DataSourceStatus.NOT_CHECKED
    cloudsql_operations: DataSourceStatus = DataSourceStatus.NOT_CHECKED
    queue_metrics: DataSourceStatus = DataSourceStatus.NOT_CHECKED
    score: int = 0  # 0-100


@dataclass
class ConfidenceScore:
    """Combined confidence assessment for an incident analysis."""

    overall_level: ConfidenceLevel = ConfidenceLevel.MEDIUM
    overall_score: int = 50  # 0-100
    data_completeness: DataCompleteness = field(default_factory=DataCompleteness)
    root_cause_confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    verification_gaps: list[str] = field(default_factory=list)
    evidence_notes: str = ""


@dataclass
class CausalChainConfig:
    """Configurable thresholds for causal chain detection."""

    deploy_to_error_hours: float = 6.0
    db_to_http_seconds: float = 30.0
    cross_service_seconds: float = 60.0
    same_service_seconds: float = 10.0
    infra_change_to_error_seconds: float = 120.0
