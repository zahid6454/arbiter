# Arbiter

**Teach your AI agent how to investigate production incidents.**

Arbiter is an open-source MCP server that turns Claude (or any MCP-compatible AI) into a hypothesis-driven incident investigator. You point it at your observability stack — Datadog, Sentry, GCP, GitHub, OpsGenie — and it does the rest: collects evidence, forms hypotheses, tests them, challenges its own conclusions, and writes structured incident reports.

It's not a dashboard. It's not a log dumper. It's a reasoning engine that happens to know how to talk to your infrastructure.

```
pip install arbiter-mcp
```

---

## The Problem

When an alert fires at 2 AM, the engineer's workflow looks like this:

1. Open Datadog. Grep for errors.
2. Open GitHub. Check recent deploys.
3. Open Sentry. Look for stack traces.
4. Open GCP. Check audit logs.
5. Correlate timestamps manually across all four.
6. Form a theory. Maybe check one more thing. Write it up.

AI can speed up each step. But speed isn't the bottleneck — **reasoning** is. Give an LLM 200 error logs and it will summarize them beautifully. It won't tell you *why* errors started at 02:01, whether the deploy 30 minutes earlier is the cause or a coincidence, or whether the loudest signal is actually the root cause.

Arbiter solves this by giving the AI agent a structured investigation method:

```
ORIENT → HYPOTHESIZE → TEST → CHALLENGE → ITERATE → REPORT
```

The agent doesn't just collect data. It states what it thinks happened, predicts what it should see if it's right, checks, and only accepts a conclusion if it survives adversarial challenges. The full reasoning chain — including what was ruled out — goes into the report.

---

## 30-Second Demo

In Claude Code:

```
/investigate catalog — high error rate, customers can't load product pages
```

Arbiter will:
1. **Orient** — look up the service, its dependencies, its infrastructure, estimate collection time
2. **Collect** — pull traces, logs, DB errors, deploys, alerts across all relevant sources (~30s)
3. **Hypothesize** — "Error traces show connection pool exhaustion. Competing hypotheses: (1) deploy regression in connection handling, (2) CloudSQL maintenance, (3) traffic spike exceeding pool size"
4. **Test** — check deploy timing, CloudSQL operations, request volume metrics
5. **Challenge** — "If it's the deploy, errors should start right after merge. They started 2 hours later. Ruling out deploy."
6. **Report** — executive summary, CS brief, on-call summary, full investigation chain, confidence assessment

Every step is narrated. You follow the reasoning in real time.

---

## Getting Started

### 1. Install

```bash
pip install arbiter-mcp
```

### 2. Configure your services

```bash
mkdir -p ~/arbiter
```

Create `~/arbiter/services.yaml` — this tells Arbiter what your services are and where to find their data:

```yaml
organization:
  name: "mycompany"
  github_org: "mycompany"

services:
  catalog:
    description: "Product catalog API"
    datadog_service: "catalog-api"
    gcp_project: "catalog-prod-7ccf"
    github_repo: "mycompany/catalog"
    sentry_project: "catalog"
    database:
      type: "postgresql"
      cloudsql_instance: "catalog-prod-primary"
    depends_on:
      - auth-service
    infrastructure:
      platform: "gke"
      cluster: "prod-cluster"
      namespace: "catalog"

  auth-service:
    description: "OAuth and JWT validation"
    datadog_service: "auth-service"
    gcp_project: "auth-prod-hrd"
    github_repo: "mycompany/auth-service"
    database:
      type: "datastore"
    depends_on: []
    infrastructure:
      platform: "app-engine"
```

A full example with 7 services is at [src/arbiter/config/services.yaml](src/arbiter/config/services.yaml).

### 3. Add credentials

Create `~/arbiter/credentials.env`:

```bash
# Required
DD_API_KEY=your-api-key
DD_APP_KEY=your-app-key
DD_SITE=datadoghq.com

# Optional — degrade gracefully if missing
SENTRY_AUTH_TOKEN=your-token
OPSGENIE_API_KEY=your-key
```

GCP and GitHub use their own CLIs — run `gcloud auth login` and `gh auth login` once.

### 4. Wire up to Claude Code

Add to your MCP settings (`.claude/settings.json` or global):

```json
{
  "mcpServers": {
    "arbiter": {
      "command": "uvx",
      "args": ["arbiter-mcp"]
    }
  }
}
```

That's it. Ask Claude to investigate anything.

---

## How It Works

```
Alert / Slack thread / customer report
  │
  ▼
COLLECT (phased, ~30-45s)
  ├─ Preflight: service profile, dependency graph, source inventory
  ├─ Primary: Datadog traces + logs + DB errors + volume metrics
  ├─ Dependencies: upstream errors + cross-service correlation + UUID tracing
  └─ Auxiliary: Sentry + GCP + OpsGenie + GitHub + Git
  │
  ▼
REASON (hypothesis-driven loop)
  │
  │   ORIENT ──► HYPOTHESIZE ──► TEST ──► CHALLENGE
  │     ▲                         │          │
  │     │         new signal      │          │
  │     └─────────────────────────┘          │
  │     ▲                                    │
  │     │         hypothesis fails           │
  │     └────────────────────────────────────┘
  │
  ▼
REPORT
  ├─ Executive summary (5 lines, no jargon)
  ├─ Customer support brief (symptoms, suggested response)
  ├─ On-call summary (what broke, what to watch)
  ├─ Investigation chain (hypothesis → test → challenge → result)
  ├─ Causal chain diagram (deploy → DB error → HTTP 500 → alert)
  └─ Confidence assessment (evidence tier, verification gaps)
  │
  ▼
REMEMBER
  └─ Incident record saved to knowledge base
     Next investigation surfaces this finding automatically
```

---

## What It Talks To

| Source | What Arbiter pulls | Credentials |
|--------|-------------------|-------------|
| **Datadog** | Logs, APM traces, monitors, SLOs, metrics, error tracking, Watchdog insights, RUM | `DD_API_KEY` + `DD_APP_KEY` (required) |
| **GitHub** | PRs + diffs, workflow runs, releases, code search, source files | `gh` CLI |
| **GCP** | Cloud Logging, admin audit logs, GKE cluster ops, CloudSQL maintenance, LB logs | `gcloud` CLI |
| **Sentry** | Unresolved issues with stack traces | `SENTRY_AUTH_TOKEN` |
| **OpsGenie** | Alerts, activity timeline, responders | `OPSGENIE_API_KEY` |
| **Kubernetes** | Pod events, PDBs, node ages | `kubectl` (auto-detected) |
| **Status Pages** | GCP + Cloudflare outage feeds | None (public APIs) |

Only Datadog is required. Everything else is optional and degrades gracefully.

---

## The Reasoning Method

Arbiter's investigation protocol isn't ad-hoc. Each technique maps to an established practice:

| Technique | What Arbiter does | Origin |
|-----------|-------------------|--------|
| Competing hypotheses | List 2-3 explanations before testing any | Analysis of Competing Hypotheses (Heuer, CIA, 1970s) |
| IS NOT test | "What's working that shouldn't be?" | Kepner-Tregoe Problem Analysis (1960s) |
| Evidence quality tiers | Deterministic → correlational → circumstantial → eliminative | Intelligence analysis tradecraft (Heuer) |
| Cause vs. mechanism | "Stack trace = what broke. Why did it break *now*?" | Systems safety (Leveson, Reason) |
| Anti-anchoring caveats | Past incident match ≠ same root cause | Learning from Incidents (Allspaw, Dekker, Cook) |
| Hypothesis-driven troubleshooting | Predict → observe → refine | Google SRE, hypothetico-deductive method |
| Defensive layer review | "Which defense should have caught this?" | Swiss Cheese Model (Reason) |

The full protocol is in [CLAUDE.md](CLAUDE.md), loaded as an MCP resource at runtime.

---

## CLI

Arbiter also works from the terminal, independent of Claude Code:

```bash
arbiter logs catalog                 # Datadog error logs (last 1h)
arbiter errors catalog               # Grouped error patterns
arbiter blast catalog                # Blast radius — what depends on this?
arbiter scan catalog                 # Cross-service error sweep
arbiter deploys catalog              # Recent git activity
arbiter services                     # List all configured services
arbiter metrics                      # Knowledge base stats (MTTR, root causes)
arbiter gather catalog --from ...    # Full data collection to JSON
```

---

## Enrichment Providers

Observability data shows you *what* broke. Enrichment providers tell you *why* services fail that way.

Arbiter ships with no built-in providers but defines a clean plugin interface. Build your own to pull architecture docs from Confluence, runbooks from PagerDuty, or failure patterns from code analysis:

```python
from arbiter.enrichment.base import EnrichmentProvider

class ConfluenceProvider(EnrichmentProvider):
    @property
    def name(self) -> str:
        return "confluence"

    def available_sections(self, service: str) -> list[str] | None:
        return ["architecture", "runbooks", "known_issues"]

    def get_service_enrichment_data(self, service, sections=None, **kwargs):
        # Your logic to fetch from Confluence, a wiki, a docs repo, etc.
        ...
```

Providers are auto-discovered via Python entry points when installed as packages.

---

## Knowledge Base

Every investigation is saved as a structured JSON record:

- Root cause category, error signatures, affected services/endpoints
- MTTR, resolution type, related PRs, remediation tickets
- Confidence level, verification gaps, evidence notes

The knowledge base enables:

- **Similarity search** — "Has this error pattern appeared before?" (Jaccard scoring across signatures, services, resources)
- **Repeat detection** — surfaces incidents where prior remediation was never completed
- **Metrics** — MTTR by service, root cause distribution, repeat rate, severity breakdown

Records are git-tracked JSON files. Optionally sync to a shared repo via GitHub PRs for team-wide visibility.

---

## Project Structure

```
arbiter/
├── src/arbiter/
│   ├── mcp_server.py          # ~60 MCP tools exposed to AI agents
│   ├── cli.py                 # 11 CLI commands
│   ├── credentials.py         # Credential resolution chain
│   ├── core/                  # Reasoning engine (zero external API deps)
│   ├── collectors/            # 11 data source adapters
│   ├── enrichment/            # Pluggable domain knowledge providers
│   ├── context/               # Service graph + workspace resolution
│   └── output/                # Report rendering (Markdown + PDF)
├── skills/                    # 5 Claude Code skills
├── CLAUDE.md                  # Investigation protocol
├── pyproject.toml
└── LICENSE                    # Apache 2.0
```

---

## Limitations

- **Data retention** — Datadog logs expire in ~2-3 days, traces in ~15 days. Investigate within 48 hours. The knowledge base preserves findings permanently.
- **Datadog rate limiting** — Full collection makes ~15-20 API calls with adaptive delays. Under heavy limiting, wait a few minutes and retry.
- **APM trace details** — Error details often live in child spans, not parent. Arbiter auto-inspects child spans when parent details are empty.
- **GCP Cloud Logging** — Not all services log here. Some use only Datadog.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
