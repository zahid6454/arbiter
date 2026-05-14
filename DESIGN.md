# Arbiter — Design Plan

## What is Arbiter

An open-source, MCP-powered AI reasoning engine for production incident investigation. Arbiter teaches AI agents **how to think** about incidents — hypothesis-driven, not checklist-driven. Users bring their own service configurations, observability sources, and domain knowledge. Arbiter provides the investigation methodology, the MCP tool interface, pluggable collectors, and core reasoning primitives.

## What Arbiter is NOT

- Not a monitoring tool or dashboard
- Not a data collector that dumps raw logs
- Not tied to any specific company, platform, or infrastructure
- Not a replacement for observability tools — it sits on top of them

## Who is it for

- **On-call engineers** — investigate incidents faster with hypothesis-driven reasoning instead of ad-hoc log grepping
- **Platform/SRE teams** — build an incident knowledge base with root cause patterns, MTTR tracking, and repeat incident detection
- **Engineering leadership** — get structured executive summaries, confidence assessments, and trend analytics across incidents
- **Customer support** — every report includes a CS brief with affected functionality, visible symptoms, and suggested customer response text
- **Anyone using Claude Code** (or any MCP-compatible AI client) who wants their AI agent to reason about production issues, not just collect data

## Core Value Proposition

Most incident investigation today is: alert fires → engineer greps logs → finds something that looks wrong → writes a report. Arbiter replaces this with a disciplined reasoning cycle:

```
ORIENT → HYPOTHESIZE → TEST → CHALLENGE → ITERATE → REPORT
```

The AI agent doesn't just collect data — it forms hypotheses, tests them against evidence, challenges its own conclusions, and produces reports that show the reasoning chain.

---

## Capabilities

Everything the system does, organized by category.

### Investigation Engine

- **Phased collection** — preflight → primary signals → dependency signals → auxiliary signals. Each phase returns progress so the user sees what's happening. Falls back to single-pass collection if a phase fails.
- **Investigation sessions** — `session_id` tracks state across phases. Service profile, dependency graph, source inventory, and duration estimate computed at preflight.
- **Investigation brief** — after collection, produces a compact brief with: `analysis_hints` (error rate, deploy correlation, volume anomaly, persistent failure detection), `top_errors` and `top_traces` (deduplicated, max 5 each), `infrastructure_profile`, `similar_past_incidents` (with caveats), `enrichment_hints`, `recommended_next_tools` (prioritized), and `investigation_warnings`.
- **Investigation warnings** — machine-computed alerts that flag critical patterns:
  - `opaque_errors` — error traces with no error details; child spans must be inspected
  - `deterministic_failure` — 100% error rate on specific endpoints; rules out transient causes
  - `zero_errors_alert_fired` — 0% errors but alert triggered; failure is outside the request-response path
  - `expected_input_not_checked` — service has configured inputs (e.g., message queues) that weren't measured
  - `known_noise_present` — service has known noise sources that inflate error rates
  - `service_may_not_handle_workload` — service may proxy to an upstream; re-investigate there
- **Severity-calibrated depth** — P1-P2 gets the full challenge gauntlet. P3-P4 can skip lower-priority infrastructure checks unless evidence points there.
- **Title derivation** — automatically derives incident title from alert text or conversation for consistent artifact naming across collected data, report, and incident record.

### Reasoning Protocol

- **Hypothesis-driven cycle** — ORIENT → HYPOTHESIZE → TEST → CHALLENGE → ITERATE → REPORT. The AI forms hypotheses, tests them against evidence, challenges its own conclusions.
- **Competing explanations** — before testing any single hypothesis, enumerate top 2-3 plausible causes. Prevents anchoring on the first visible signal.
- **IS NOT test** — "If this hypothesis is correct, what else should be failing that isn't?" Eliminates over-broad hypotheses before spending tokens.
- **Observation vs. conclusion separation** — observations are what data shows; conclusions require a causal mechanism. Temporal correlation alone is not causation.
- **Evidence quality tiers** — Tier 1 (Deterministic: stack trace to exact line), Tier 2 (Strong correlational: temporal + explained mechanism), Tier 3 (Circumstantial: temporal without mechanism), Tier 4 (Eliminative: process of elimination). Conclusions are rated by the highest tier supporting them.
- **Challenge gauntlet** — 16 structured challenges every conclusion must survive before acceptance:
  - What changed to trigger this?
  - Does it explain ALL the evidence?
  - What would disprove it?
  - Is there a simpler explanation?
  - Have I found the cause, or just the mechanism?
  - Is this deterministic or transient — does the pattern match?
  - Have I checked infrastructure (GKE operations, CloudSQL maintenance, status pages)?
  - Have I checked all configured inputs, not just HTTP?
  - Have I consulted enrichment providers?
  - Should the service have survived this trigger (pre-existing vulnerability)?
  - What is the quality of my evidence?
  - Are traces from affected users or background noise?
- **Multi-factor exception** — a failed hypothesis stays dead, but independently confirmed factors can be legitimate contributing causes if each has its own causal mechanism.
- **External input protocol** — when someone provides a theory (user, engineer, pasted Slack message), treat it as a hypothesis, not a conclusion. Queue it, test it with the same rigor, report honestly.
- **Past incident anchoring defense** — analyze current data FIRST, then check if past patterns apply. A 90% signature match does not mean the same root cause.
- **"Unknown" is valid** — if the specific error cannot be identified, the report states what could and could not be determined. No gap-filling with the loudest concurrent signal.

### Narration System

- **Narration contract** — between every tool call, the AI narrates what happened and what's next. The user follows the reasoning in real time.
- **Template-based narration** — structured templates for after preflight, after each collection phase, on phase failure. Adapted to what the data shows.

### Token Efficiency

- **Detail level system** — all variable-length tools default to `detail_level="summary"`. Summary returns counts, top patterns, and representative examples. Escalate to `detail_level="full"` only when summary raises a specific question needing raw data.
- **Investigation effort tracking** — tracks which tools were called, their data collection depth (Summary/Full), and estimated token usage. Included in the report.

### Data Collection

- **Datadog** — logs, APM traces, monitors, SLOs, metrics (timeseries), error tracking, Watchdog insights, RUM errors, RUM performance, trace span inspection
- **GCP** — Cloud Logging, admin activity audit logs, CloudSQL operations (maintenance/failover), CloudSQL server logs, GKE cluster operations (upgrades/repairs), load balancer logs
- **Sentry** — unresolved issues with stack traces
- **OpsGenie** — alerts, alert activity timeline
- **GitHub** — PRs with diffs and reviews, deploy correlation (PR-based and tag/workflow-based), code search, source file reading, releases
- **Kubernetes** — pod events, PodDisruptionBudgets, node ages (via kubectl)
- **Status pages** — GCP and Cloudflare public status (no auth needed)
- **Manual input** — parse pasted Slack/Teams threads, raw error logs
- **Child span prefetch** — when parent spans have empty error details, automatically inspects child spans for the actual error
- **Volume anomaly detection** — checks if request rate shifted significantly before/during the incident
- **Deploy correlation** — splits deploys into pre-incident and during-incident with hours-before-incident for each PR
- **Noise filtering** — services declare known noise sources in config; traces can be filtered to exclude noise before interpreting error rates
- **UUID correlation** — trace a specific request ID across all services to find where it failed
- **Baseline comparison** — compare incident traces against a 24h-ago healthy baseline to spot regressions
- **Log aggregation** — break down errors by endpoint, pod, status code, or version using pre-built templates or custom facets

### Remediation

- **Code fix eligibility gate** — only propose a fix when: root cause confidence is HIGH/MEDIUM, failing code path identified, root cause is actionable (code_bug or deploy_regression), and fix is scoped
- **Remediation spec** — for each fix: file, function, current behavior, required change, why, verification steps
- **Jira ticket creation** — creates tickets with full remediation spec via Atlassian MCP tools. Title format: `[Arbiter] {description}`. Priority mapped from severity.
- **Bidirectional linking** — report references ticket, ticket comment links back to report

### Reports

- **Multi-audience structure** — every report includes:
  - **Executive Summary** — 5 lines max, no jargon, for leadership
  - **Customer Support Brief** — affected functionality, symptoms, suggested response text, escalation guidance
  - **On-Call Summary** — what broke, what triggered it, what to watch, when to escalate
- **Investigation chain** — shows the full hypothesis → test → challenge reasoning, including what was ruled out and what remains unknown
- **Causal chain diagram** — text-based tree diagram showing how the incident propagated (deploy → DB error → HTTP 500 → alert)
- **Confidence assessment** — overall score, evidence strength, evidence quality tier, verification gaps
- **Defensive layer review** — before writing action items, asks "which defense should have caught this and why didn't it?" (code review, testing, monitoring, connection pools, retry logic, circuit breakers, PDBs)
- **Pre-report validation** — checks 7 dimensions before writing: actual error found, failure pattern matches root cause, right service investigated, observations separated from conclusions, configured inputs verified, client-side considered (UI symptoms), signal provenance (noise filtering)
- **Markdown + PDF** — reports saved as markdown, optionally rendered to PDF for sharing

### Knowledge Base

- **Incident records** — structured JSON with: root cause category, error signatures, affected services/tables/endpoints, resolved_by, MTTR, related PRs, remediation tickets, confidence level, verification gaps, evidence notes
- **Error signature fingerprinting** — normalized error patterns for matching across incidents
- **Similarity search** — find past incidents by service, error signatures, root cause category, date range, tags. Returns matches scored by similarity with explanations.
- **Repeat incident detection** — identifies when a prior incident was never fully resolved
- **Incident metrics** — MTTR by service, root cause distribution, repeat incident rate, severity breakdown, resolution types, confidence distribution
- **Knowledge base sync** — optionally sync records to a configurable Git repo for team sharing via PR

### Integration

- **Claude Code skills** — `/investigate`, `/quick-check`, `/setup` as thin skill launchers
- **MCP resource** — investigation protocol loaded as MCP resource so any MCP client can read it
- **Jira integration** — ticket creation, commenting via Atlassian MCP tools. Cloud ID and project configurable in services.yaml.
- **CLI** — `arbiter-mcp` (start MCP server), `arbiter setup` (credential wizard), `arbiter version`

---

## Architecture

### High-Level Structure

```
arbiter/
├── src/arbiter/
│   ├── __init__.py
│   ├── mcp_server.py              # MCP server — tools exposed to AI agents
│   ├── cli.py                     # CLI entry point
│   ├── credentials.py             # Credential resolution (env → file → .env)
│   ├── core/                      # Reasoning engine (zero external dependencies)
│   │   ├── models.py              # Data models — traces, logs, incidents, evidence
│   │   ├── analyzer.py            # Error grouping, pattern detection, trace aggregation
│   │   ├── causal_chain.py        # Cause-effect propagation detection
│   │   ├── confidence.py          # Evidence strength scoring
│   │   ├── incident_store.py      # File-based incident knowledge base + similarity search
│   │   ├── metrics.py             # MTTR, root cause distribution, repeat rate
│   │   └── timeline.py            # Cross-source timeline builder
│   ├── collectors/                # Data source adapters (pluggable)
│   │   ├── base.py                # Collector ABC — all sources implement this
│   │   ├── datadog.py             # Datadog logs, traces, monitors, metrics, RUM
│   │   ├── gcp.py                 # GCP Cloud Logging, audit logs, CloudSQL, GKE, LB
│   │   ├── sentry.py              # Sentry issues and stack traces
│   │   ├── opsgenie.py            # OpsGenie alerts and timeline
│   │   ├── github.py              # PRs, deploys, code search, releases, source files
│   │   ├── git.py                 # Local git repo reader
│   │   ├── kubernetes.py          # kubectl-based pod enrichment
│   │   ├── status_pages.py        # Public status page checks (GCP, Cloudflare)
│   │   ├── manual.py              # Parse pasted logs and chat threads
│   │   └── source_code.py         # Stack trace → source file mapping
│   ├── enrichment/                # Domain knowledge providers (pluggable)
│   │   ├── base.py                # Enrichment provider ABC
│   │   └── registry.py            # Dynamic provider discovery and registration
│   ├── context/                   # Service graph and workspace
│   │   ├── service_map.py         # services.yaml reader, dependency graph, BFS traversal
│   │   └── workspace.py           # Path resolution, output directories
│   └── output/                    # Report generation
│       ├── renderer.py            # Jinja2 → markdown
│       └── pdf_renderer.py        # Markdown → HTML → PDF
├── config/
│   ├── services.example.yaml      # Example service configuration (documented schema)
│   └── templates/
│       ├── report.md.j2           # Report template
│       └── report.css             # PDF stylesheet
├── skills/                        # Claude Code skills
│   ├── investigate/SKILL.md
│   ├── quick-check/SKILL.md
│   └── setup/SKILL.md
├── pyproject.toml
├── README.md
├── LICENSE                        # MIT or Apache 2.0
└── CLAUDE.md                      # Investigation protocol (generic)
```

### Key Design Decisions

#### 1. Service Configuration — User-Provided `services.yaml`

Arbiter ships with NO service definitions. Users create their own `services.yaml` that maps their services to observability sources:

```yaml
# arbiter configuration
organization:
  name: "acme"
  github_org: "acme-platform"
  sentry_org: "acmeplatform"

jira:
  cloud_id: "acme-eng.atlassian.net"
  default_project: "PLATFORM"

environments:
  production:
    aliases: ["prod"]
    datadog_env: "production"
  integration:
    aliases: ["dev"]
    datadog_env: "integration"
  preproduction:
    aliases: ["stag"]
    datadog_env: "staging"

services:
  # --- Flask + React + PostgreSQL service with frontend RUM ---
  catalog:
    description: "Product catalog — CRUD, categories, inventory, search"
    datadog_service: "catalog-api"
    gcp_project: "catalog-prod-7ccf"
    github_repo: "acme-platform/catalog"
    sentry_project: "catalog"
    jira_project: "CATALOG"
    database:
      type: "postgresql"
      cloudsql_instance: "catalog-prod-primary"
    dependencies:
      - platform-core
      - audit-log
      - asset-pipeline
    infrastructure:
      platform: "gke"
      cluster: "prod-cluster-us-east1"
      namespace: "catalog"
    frontend:
      has_ui: true
      rum: true
      cdn: "cloudflare"
    noise_filters:
      - tag_filter: "-@http.useragent:libcurl*"
        description: "Internal health check bot traffic"

  # --- Large monolith with Spanner ---
  platform-core:
    description: "Core platform monolith — 900+ routes, auth, projects, accounts"
    datadog_service: "platform-core"
    gcp_project: "platform-core-prod-87l6"
    github_repo: "acme-platform/platform-core"
    sentry_project: "platform-core"
    database:
      type: "spanner"
      instance: "platform-core-prod"
    dependencies: []
    infrastructure:
      platform: "gke"
      cluster: "prod-cluster-us-east1"
      namespace: "platform-core"
    frontend:
      has_ui: true
      rum: true

  # --- Change tracking service (Flask + PostgreSQL + webhooks) ---
  audit-log:
    description: "Tracks entity revisions, computes diffs, fires webhooks"
    datadog_service: "audit-log"
    gcp_project: "audit-log-prod-0mrq"
    github_repo: "acme-platform/audit-log"
    sentry_project: "audit-log"
    database:
      type: "postgresql"
      cloudsql_instance: "audit-log-prod-primary"
    dependencies:
      - platform-core
    infrastructure:
      platform: "gke"
      cluster: "prod-cluster-us-east1"
      namespace: "audit-log"

  # --- Pub/Sub worker with NO HTTP endpoints ---
  asset-pipeline:
    description: "Builds and publishes static assets to CDN on entity changes"
    datadog_service: "asset-pipeline"
    gcp_project: "asset-pipeline-prod-2101"
    github_repo: "acme-platform/asset-pipeline"
    sentry_project: "asset-pipeline"
    database:
      type: "postgresql"
      cloudsql_instance: "asset-pipeline-prod-primary"
    dependencies:
      - platform-core
    infrastructure:
      platform: "gke"
      cluster: "prod-cluster-us-east1"
      namespace: "asset-pipeline"
    message_queues:
      - type: "pubsub"
        subscription: "asset-ingress-sub"
        topic: "entity-changes"
    deploy_method: "tag"  # tag-based deploys via GitHub Actions, not PR merges

  # --- API gateway (NGINX + Go + Python) ---
  api-gateway:
    description: "Public API gateway — routing, rate limiting, auth validation"
    datadog_service: "api-gateway"
    gcp_project: "infra-prod-889d"
    github_repo: "acme-platform/api-gateway"
    database:
      type: "none"
    dependencies:
      - platform-core
      - catalog
      - auth-service
    infrastructure:
      platform: "gke"
      cluster: "prod-cluster-us-east1"
      namespace: "api-gateway"

  # --- Auth/token service (Go, App Engine, Datastore) ---
  auth-service:
    description: "OAuth token issuance and JWT validation"
    datadog_service: "auth-service"
    gcp_project: "auth-prod-hrd"
    github_repo: "acme-platform/auth-service"
    database:
      type: "datastore"
    dependencies: []
    infrastructure:
      platform: "app-engine"

  # --- Scheduled task service (FastAPI + PostgreSQL + Pub/Sub) ---
  task-scheduler:
    description: "Scheduled operations — campaign activation, timed releases"
    datadog_service: "task-scheduler"
    gcp_project: "task-scheduler-prod-31jy"
    github_repo: "acme-platform/task-scheduler"
    sentry_project: "task-scheduler"
    database:
      type: "postgresql"
      cloudsql_instance: "task-scheduler-prod-primary"
    dependencies:
      - catalog
      - platform-core
    infrastructure:
      platform: "gke"
      cluster: "prod-cluster-us-east1"
      namespace: "task-scheduler"
    message_queues:
      - type: "pubsub"
        subscription: "scheduled-tasks-sub"
        topic: "scheduled-tasks"
```

**Schema validation** — Arbiter validates the config on startup and gives clear errors for missing/malformed fields. A `services.example.yaml` ships with comprehensive comments explaining every field.

#### 2. Enrichment Provider System — Fully Pluggable

Enrichment providers supply domain knowledge that observability tools can't — architecture docs, known bug patterns, failure modes, data flow diagrams. Arbiter ships with NO built-in providers but defines a clean interface:

```python
class EnrichmentProvider(ABC):
    """Supplies domain knowledge about services."""

    @property
    @abstractmethod
    def provider_id(self) -> str:
        """Unique identifier (e.g., 'wiki', 'runbook-agent')."""

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Human-readable name."""

    @abstractmethod
    def get_available_sections(self, service_name: str) -> list[str]:
        """What knowledge sections are available for this service."""

    @abstractmethod
    def get_enrichment_data(
        self, service_name: str, sections: list[str]
    ) -> dict:
        """Return enrichment data for requested sections."""
```

Providers are registered via:
- **Python entry points** — install a package, it auto-registers
- **Config file** — point to a local directory of markdown docs
- **API** — implement the ABC and register programmatically

Example third-party providers someone might build:
- A Confluence wiki scraper that pulls architecture docs
- A runbook provider that reads from PagerDuty
- A static docs provider that reads markdown files from a repo
- An AI-powered code analysis provider that maps errors to known bug patterns

#### 3. Collectors — Built-in but Configurable

The collectors (Datadog, GCP, Sentry, etc.) are generic — they talk to APIs using credentials the user provides. They ship with Arbiter because they contain no company-specific logic. Each collector only activates if the relevant credentials are configured.

```
Credential resolution order:
1. Shell environment variables (DD_API_KEY, etc.)
2. $ARBITER_HOME/credentials.env
3. .env file in working directory
```

Required: None (Arbiter works with whatever sources you configure)
Common: `DD_API_KEY`, `DD_APP_KEY`, `DD_SITE`
Optional: `SENTRY_AUTH_TOKEN`, `OPSGENIE_API_KEY`, `GCLOUD_CONFIGURATION`

#### 4. Investigation Protocol — Generic CLAUDE.md

The investigation protocol (ORIENT → HYPOTHESIZE → TEST → CHALLENGE → ITERATE → REPORT) is the heart of Arbiter. It ships as a generic `CLAUDE.md` that:

- Teaches the AI agent the hypothesis-driven methodology
- References tools by their generic names (no company-specific examples)
- Uses placeholder service names in examples ("service-a", "upstream-db")
- Documents all MCP tools and when to use them
- Includes the anti-pattern catalog (anchoring, premature closure, mechanism-vs-cause)

The protocol is loaded as an MCP resource so any MCP client can read it.

#### 5. MCP Server — The AI Interface

The MCP server exposes ~60 tools that an AI agent uses during investigation:

**Investigation flow tools:**
- `preflight_investigation` — service lookup, dependency count, source estimate
- `collect_primary_signals` — traces + logs + DB errors for the service
- `collect_dependency_signals` — check upstream services
- `collect_auxiliary_signals` — Sentry + GCP + GitHub + OpsGenie
- `gather_incident_context` — single-pass fallback

**Data source tools:**
- `fetch_datadog_traces`, `fetch_datadog_logs`, `fetch_datadog_metrics`
- `fetch_gcp_logs`, `fetch_gcp_audit_logs`
- `fetch_sentry_issues`
- `fetch_github_deploys`, `fetch_github_pr`, `search_github_code`, `read_github_file`
- `fetch_opsgenie_alerts`
- etc.

**Reasoning tools:**
- `analyze_causal_chain` — detect cause-effect propagation
- `get_confidence_assessment` — evidence strength scoring
- `validate_investigation` — pre-report completeness check
- `aggregate_trace_data` — group traces by dimensions
- `compare_datadog_traces` — baseline comparison

**Knowledge base tools:**
- `save_incident_record`, `search_past_incidents`, `list_incidents`
- `get_incident_metrics`

**Report tools:**
- `save_incident_report`, `generate_pdf_report`

#### 6. Knowledge Base — Local-First

Incident records are stored as JSON files locally. No cloud dependency. Users can optionally sync to a Git repo for team sharing (the sync target is configurable, not hardcoded).

```yaml
# In services.yaml or arbiter config
knowledge_base:
  sync_repo: "mycompany/incident-knowledge"  # optional
```

---

## Implementation Approach

**Copy and clean.** The generic framework code is copied from the production-tested codebase, then cleaned of all company-specific references. This preserves battle-tested logic and existing test coverage. The domain-specific pieces (service definitions, enrichment provider implementations, incident history) do not ship.

### Per-component approach

| Arbiter Component | Action | What changes |
|-------------------|--------|--------------|
| `core/*` (models, analyzer, causal_chain, confidence, metrics, timeline, incident_store) | Copy | Rename imports `replix` → `arbiter`. Zero logic changes — already fully generic. |
| `collectors/base.py` | Copy | Rename imports only. |
| `collectors/datadog.py` | Copy | Rename imports. Already generic — pure Datadog API client. |
| `collectors/gcp.py` | Copy | Rename imports. Remove 1 inline comment referencing a specific company. |
| `collectors/sentry.py` | Copy | Rename imports. Already generic. |
| `collectors/github.py` | Copy | Rename imports. Replace hardcoded default org with config lookup. |
| `collectors/opsgenie.py` | Copy | Rename imports. Already generic. |
| `collectors/kubernetes.py` | Copy | Rename imports. Already generic. |
| `collectors/status_pages.py` | Copy | Rename imports. Already generic. |
| `collectors/manual.py` | Copy | Rename imports. Already generic. |
| `collectors/source_code.py` | Copy | Rename imports. Already generic. |
| `collectors/git.py` | Copy | Rename imports. Already generic. |
| `enrichment/base.py` | Copy | Rename imports. Already generic ABC. |
| `enrichment/registry.py` | Rewrite | Replace hardcoded single-provider registration with dynamic discovery via Python entry points + config. |
| `enrichment/research_agent.py` | **Do not ship** | Company-specific enrichment provider. Stays in the original codebase. |
| `context/service_map.py` | Copy | Rename imports. Replace hardcoded default org with config lookup. |
| `context/workspace.py` | Copy | Rename imports. Change paths from `replix` to `arbiter`, env vars from `REPLIX_*` to `ARBITER_*`. |
| `mcp_server.py` | Copy | Rename imports. Remove company-specific service names from docstring examples. Replace hardcoded org references with config lookups. |
| `cli.py` | Copy | Rename imports. Change CLI name to `arbiter`. |
| `credentials.py` | Copy | Rename imports. Change env var prefix from `REPLIX_*` to `ARBITER_*`. |
| `output/renderer.py` | Copy | Rename imports. Already generic. |
| `output/pdf_renderer.py` | Copy | Rename imports. Already generic. |
| `config/services.yaml` | **Do not ship** | Company-specific service catalog. Replaced by `services.example.yaml` with generic examples. |
| `config/services.example.yaml` | Write new | Documented schema with the generic acme-platform examples from this design plan. |
| `config/templates/report.md.j2` | Copy | Already generic. |
| `config/templates/report.css` | Copy | Already generic. |
| `CLAUDE.md` | Rewrite | Generic investigation protocol using generic service name examples. All methodology preserved, all company-specific references removed. |
| `core/incident_sync.py` | Copy | Replace hardcoded repo with configurable `knowledge_base.sync_repo` from services.yaml. |
| `core/version_check.py` | Copy | Point to Arbiter's GitHub repo. |
| `incidents/*` | **Do not ship** | Company-specific incident history. Arbiter ships with an empty `incidents/` directory. |
| `skills/*.md` | Copy | Remove company-specific service name examples. Replace branding. |
| `scripts/bootstrap.sh` | Copy | Replace branding, env var names, hardcoded org references. |
| `tests/` | Copy | Rename imports. Remove tests for company-specific enrichment provider. All other tests should pass after rename. |

---

## Phased Delivery

### Phase 1: Foundation
- Project scaffolding (pyproject.toml, src layout, git init)
- Core reasoning engine — data models, error grouping, causal chain detection, confidence scoring, incident store, metrics
- Credential resolution (env → file → .env)
- Service configuration schema + YAML validation + `services.example.yaml`
- Workspace and path resolution (`$ARBITER_HOME`)

### Phase 2: Collectors + MCP Server
- Collector ABC + all built-in collectors (Datadog, GCP, Sentry, OpsGenie, GitHub, git, kubernetes, status pages, manual parser)
- MCP server with all investigation tools
- CLI entry point (`arbiter-mcp`, `arbiter setup`, `arbiter version`)
- Investigation session management (preflight → phased collection → investigation brief)

### Phase 3: Protocol + Reports + Skills
- Investigation protocol CLAUDE.md — hypothesis-driven methodology with generic examples
- Claude Code skills (investigate, quick-check, setup)
- Report generation (Jinja2 markdown + PDF)
- Incident knowledge base (store, search, similarity matching, metrics)

### Phase 4: Polish + Ship
- Enrichment provider plugin system (ABC + registry + Python entry points)
- README with quickstart guide and screenshots
- Test suite
- PyPI package publication
- Public GitHub repo release

---

## Decisions

| Question | Decision |
|----------|----------|
| **License** | Apache 2.0 — patent protection, standard for infrastructure tools |
| **Project name** | Arbiter |
| **PyPI package** | `arbiter-mcp` (`pip install arbiter-mcp`) |
| **GitHub repo** | Personal account (to be created) |
| **Collectors** | Bundled in core. Split into separate packages later only if adoption demands it. |
| **CLAUDE.md delivery** | Bundled in the Python package, exposed as MCP resource. |
