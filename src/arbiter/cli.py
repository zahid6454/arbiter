"""Arbiter CLI — incident analysis and report generation from the command line."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from arbiter.context.service_map import (
    get_blast_radius,
    get_dependencies,
    get_related_services,
    list_services,
    load_service_graph,
)
from arbiter.context.workspace import resolve_incidents_root, resolve_output_root, resolve_workspace

API_RATE_LIMIT_DELAY = 3  # seconds between Datadog API calls


def _graph():
    return load_service_graph()


@click.group()
def main():
    """Arbiter — MCP-powered AI reasoning engine for production incident investigation.

    \b
    Quick start:
      arbiter logs catalog                # errors from catalog (last 1h)
      arbiter errors catalog              # grouped error summary
      arbiter blast catalog               # blast radius
      arbiter scan catalog                # cross-service error check
      arbiter services                    # list all services
      arbiter gather catalog --from ...   # full incident data
    """
    pass


# ---------------------------------------------------------------------------
# arbiter logs <service> [timerange] [env]
# ---------------------------------------------------------------------------
@main.command()
@click.argument("service")
@click.argument("time_range", default="1h")
@click.argument("env", default="production")
@click.option("-n", "--limit", default=20, help="Max log entries")
@click.option("-q", "--query", default="status:error", help="Datadog query")
def logs(service: str, time_range: str, env: str, limit: int, query: str):
    """Fetch error logs from Datadog."""
    from arbiter.collectors.datadog import DatadogCollector

    try:
        client = DatadogCollector()
        if not client.is_configured():
            click.echo("Error: Set DD_API_KEY and DD_APP_KEY", err=True)
            sys.exit(1)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    entries = client.collect_logs(
        service=service,
        time_range=time_range,
        env=env,
        limit=limit,
        query=query,
    )
    for e in entries:
        click.echo(f"  [{e.timestamp[:19]}] {e.level.value:8s} {e.service:20s} {e.message[:120]}")
    click.echo(f"\n  Total: {len(entries)} entries")


# ---------------------------------------------------------------------------
# arbiter errors <service> [timerange]
# ---------------------------------------------------------------------------
@main.command()
@click.argument("service")
@click.argument("time_range", default="1h")
@click.argument("env", default="production")
def errors(service: str, time_range: str, env: str):
    """Show grouped error summary from Datadog."""
    from arbiter.collectors.datadog import DatadogCollector

    try:
        client = DatadogCollector()
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    result = client.get_error_summary(service=service, time_range=time_range, env=env)

    click.echo(f"\n  {service} | {env} | last {time_range}")
    click.echo(
        f"  Total errors: {result['total_errors']}  |  Unique patterns: {result['unique_error_patterns']}"
    )
    click.echo(f"  {'─' * 60}")
    for err in result["top_errors"]:
        click.echo(f"  {err['count']:>4}x  {err['pattern'][:100]}")
    click.echo()


# ---------------------------------------------------------------------------
# arbiter blast <service>
# ---------------------------------------------------------------------------
@main.command()
@click.argument("service")
def blast(service: str):
    """Show blast radius for a service."""
    affected = get_blast_radius(service, _graph())

    click.echo(f"\n  Blast radius: {service}")
    click.echo(f"  {'─' * 50}")
    for entry in affected:
        icon = "●" if entry.role == "primary" else "↓" if entry.role == "downstream" else "↑"
        click.echo(f"  {icon} {entry.service:28s} {entry.role:12s} {entry.impact}")
    click.echo()


# ---------------------------------------------------------------------------
# arbiter scan <service> [timerange]
# ---------------------------------------------------------------------------
@main.command()
@click.argument("service")
@click.argument("time_range", default="1h")
@click.argument("env", default="production")
def scan(service: str, time_range: str, env: str):
    """Scan errors across a service and all dependencies."""
    from arbiter.collectors.datadog import DatadogCollector

    try:
        client = DatadogCollector()
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    graph = _graph()
    related = get_related_services(service, graph)
    all_services = [service, *related]

    click.echo(f"\n  Scanning {len(all_services)} services | {env} | last {time_range}")
    click.echo(f"  {'─' * 60}")

    results = client.collect_logs_multi(
        services=all_services,
        time_range=time_range,
        env=env,
        limit_per_service=20,
    )

    for svc in all_services:
        svc_logs = results.get(svc, [])
        count = len(svc_logs)
        marker = "●" if svc == service else "○"
        status = f"{count} errors" if count > 0 else "clean"
        click.echo(f"  {marker} {svc:30s} {status}")
        for log in svc_logs[:2]:
            click.echo(f"      └─ {log.message[:120]}")
    click.echo()


# ---------------------------------------------------------------------------
# arbiter services
# ---------------------------------------------------------------------------
@main.command()
def services():
    """List all available services."""
    graph = _graph()
    svc_list = list_services(graph)

    click.echo("\n  Available services:")
    click.echo(f"  {'─' * 50}")
    for svc in svc_list:
        deps = get_dependencies(svc, graph)
        dep_count = len(deps.get("depends_on", []))
        rev_count = len(deps.get("depended_on_by", []))
        click.echo(f"  {svc:30s}  ↑{dep_count} deps  ↓{rev_count} dependents")
    click.echo()


# ---------------------------------------------------------------------------
# arbiter deploys <service> [hours]
# ---------------------------------------------------------------------------
@main.command()
@click.argument("service")
@click.argument("hours", default=24, type=int)
def deploys(service: str, hours: int):
    """Show recent commits/deploys for a service."""
    from arbiter.collectors.git import GitCollector

    workspace = resolve_workspace()
    git = GitCollector(workspace)
    ctx = git.gather_context(service, hours_back=hours)

    if "error" in ctx:
        click.echo(f"Error: {ctx['error']}", err=True)
        sys.exit(1)

    click.echo(f"\n  {service} | last {hours}h | branch: {ctx.get('current_branch', '?')}")
    click.echo(f"  {'─' * 60}")

    commits = ctx.get("recent_commits", [])
    if not commits:
        click.echo("  No commits in this period")
    for c in commits[:15]:
        click.echo(f"  {c['hash']}  {c['author']:20s}  {c['message'][:60]}")

    tags = ctx.get("recent_tags", [])
    if tags:
        click.echo("\n  Recent tags:")
        for t in tags[:5]:
            click.echo(f"  {t['tag']:30s}  {t['date']}")
    click.echo()


# ---------------------------------------------------------------------------
# arbiter gather <service> — full context gather
# ---------------------------------------------------------------------------
@main.command()
@click.argument("service")
@click.argument("time_range", default="2h")
@click.option("--severity", default="P2", help="Incident severity (P1-P4)")
@click.option("-t", "--thread", default="", help="Chat thread text or file path")
@click.option("--from", "from_time", default="", help="Absolute start (ISO 8601)")
@click.option("--to", "to_time", default="", help="Absolute end (ISO 8601)")
def gather(service: str, time_range: str, severity: str, thread: str, from_time: str, to_time: str):
    """Gather full incident context — logs, APM traces, DB errors, UUID correlation, git.

    \b
    Collects from: Datadog (logs + traces + DB errors), Sentry, GCP, git.
    Saves raw data to output/collected-data/<date>-<service>.json

    \b
    Examples:
      arbiter gather catalog
      arbiter gather catalog --from 2026-04-09T02:00:00Z --to 2026-04-09T10:00:00Z
    """
    import re
    import subprocess
    import time as _time
    from datetime import datetime

    from arbiter.collectors.datadog import DatadogCollector
    from arbiter.collectors.git import GitCollector
    from arbiter.collectors.manual import ManualCollector
    from arbiter.context.service_map import get_datadog_service

    workspace = resolve_workspace()
    graph = _graph()

    context: dict = {
        "service": service,
        "severity": severity,
        "generated_at": datetime.now().isoformat(),
        "time_range": {"from": from_time or f"now-{time_range}", "to": to_time or "now"},
    }

    dd_service = get_datadog_service(service, graph)
    context["datadog_service_name"] = dd_service

    click.echo("  [1/10] Service map & blast radius...")
    context["blast_radius"] = [
        {"service": b.service, "role": b.role, "impact": b.impact}
        for b in get_blast_radius(service, graph)
    ]
    context["dependencies"] = get_dependencies(service, graph)

    dd_kwargs: dict = {}
    if from_time:
        dd_kwargs["from_time"] = from_time
        dd_kwargs["to_time"] = to_time or "now"

    try:
        dd = DatadogCollector()
        if dd.is_configured():
            click.echo(f"  [2/10] APM traces for {dd_service}...")
            try:
                traces = dd.search_traces(
                    service=dd_service,
                    time_range=time_range,
                    status_code="",
                    limit=50,
                    **dd_kwargs,
                )
                context["datadog_traces"] = traces
                error_count = sum(
                    1
                    for t in traces
                    if str(t.get("status_code", "")).startswith(("4", "5")) or t.get("error_type")
                )
                click.echo(f"         {len(traces)} traces ({error_count} errors)")
            except Exception as e:
                click.echo(f"         Traces: {e}")
                context["datadog_traces"] = []

            _time.sleep(API_RATE_LIMIT_DELAY)

            click.echo("  [3/10] Upstream APM traces...")
            deps = get_dependencies(service, graph)
            upstream_traces = {}
            for upstream in deps.get("depends_on", []):
                _time.sleep(API_RATE_LIMIT_DELAY)
                try:
                    dd_up = get_datadog_service(upstream, graph)
                    ut = dd.search_traces(
                        service=dd_up,
                        time_range=time_range,
                        status_code="500",
                        limit=10,
                        **dd_kwargs,
                    )
                    if ut:
                        upstream_traces[upstream] = ut
                        click.echo(f"         {upstream}: {len(ut)} error traces")
                except Exception as e:
                    click.echo(f"         {upstream}: {e}")
            if upstream_traces:
                context["upstream_traces"] = upstream_traces

            _time.sleep(API_RATE_LIMIT_DELAY)

            click.echo(f"  [4/10] Datadog logs for {dd_service}...")
            log_entries = dd.collect_logs(
                service=dd_service,
                time_range=time_range,
                limit=100,
                **dd_kwargs,
            )
            context["datadog_logs"] = [
                {
                    "timestamp": l.timestamp,
                    "level": l.level.value,
                    "message": l.message,
                    "service": l.service,
                    "pod": l.pod,
                }
                for l in log_entries
            ]
            context["datadog_log_count"] = len(log_entries)
            click.echo(f"         {len(log_entries)} entries")

            uuids = []
            for l in log_entries:
                m = re.search(r'"uuid":\s*"([^"]+)"', l.message)
                if m:
                    uuids.append({"uuid": m.group(1), "timestamp": l.timestamp})
            context["extracted_uuids"] = uuids
            if uuids:
                click.echo(f"         {len(uuids)} request UUIDs extracted from 500 responses")

            _time.sleep(API_RATE_LIMIT_DELAY)

            click.echo("  [5/10] Database errors...")
            db_errors = dd.search_database_errors(
                service=dd_service,
                time_range=time_range,
                **dd_kwargs,
            )
            context["datadog_db_errors"] = [
                {
                    "timestamp": l.timestamp,
                    "level": l.level.value,
                    "message": l.message,
                    "service": l.service,
                }
                for l in db_errors
            ]
            click.echo(f"         {len(db_errors)} on {dd_service}")

            upstream_db = {}
            for upstream in deps.get("depends_on", []):
                _time.sleep(API_RATE_LIMIT_DELAY)
                try:
                    dd_up = get_datadog_service(upstream, graph)
                    ub = dd.search_database_errors(
                        service=dd_up,
                        time_range=time_range,
                        **dd_kwargs,
                    )
                    if ub:
                        upstream_db[upstream] = [
                            {
                                "timestamp": l.timestamp,
                                "level": l.level.value,
                                "message": l.message,
                                "service": l.service,
                            }
                            for l in ub
                        ]
                        click.echo(f"         {len(ub)} on {upstream} ({dd_up})")
                except Exception as e:
                    click.echo(f"         {upstream}: {e}")
            if upstream_db:
                context["upstream_db_errors"] = upstream_db

            _time.sleep(API_RATE_LIMIT_DELAY)

            click.echo("  [6/10] Cross-service scan...")
            related = get_related_services(service, graph)
            dd_related = [get_datadog_service(s, graph) for s in related]
            cross = dd.collect_logs_multi(
                services=dd_related,
                time_range=time_range,
                **dd_kwargs,
            )
            context["cross_service_logs"] = {
                svc: [
                    {
                        "timestamp": l.timestamp,
                        "level": l.level.value,
                        "message": l.message,
                        "service": l.service,
                    }
                    for l in svc_logs
                ]
                for svc, svc_logs in cross.items()
            }
            for svc, svc_logs in cross.items():
                if svc_logs:
                    click.echo(f"         {svc}: {len(svc_logs)} errors")

            if uuids:
                click.echo(f"  [7/10] UUID correlation ({len(uuids[:5])} UUIDs)...")
                uuid_results = {}
                for u in uuids[:5]:
                    _time.sleep(API_RATE_LIMIT_DELAY)
                    try:
                        matched = dd.search_by_uuid(u["uuid"], time_range=time_range, **dd_kwargs)
                        uuid_results[u["uuid"]] = [
                            {
                                "timestamp": l.timestamp,
                                "level": l.level.value,
                                "message": l.message,
                                "service": l.service,
                            }
                            for l in matched
                        ]
                    except Exception as e:
                        click.echo(f"         UUID {u['uuid'][:8]}...: {e}")
                context["uuid_correlation"] = uuid_results
            else:
                click.echo("  [7/10] UUID correlation — no UUIDs to trace")

    except Exception as e:
        context["datadog_error"] = str(e)

    click.echo("  [8/10] Git...")

    if thread:
        thread_path = Path(thread)
        raw = thread_path.read_text() if thread_path.exists() else thread
        manual = ManualCollector()
        context["parsed_thread"] = manual.parse_thread(raw)

    git = GitCollector(workspace)
    repo_path = workspace / service
    if repo_path.is_dir():
        subprocess.run(["git", "fetch", "--all"], cwd=repo_path, capture_output=True, timeout=30)
    context["git_context"] = git.gather_context(service, hours_back=72)

    click.echo("  [9/10] Source code analysis...")
    from arbiter.collectors.source_code import SourceCodeCollector
    from arbiter.context.service_map import get_source_root

    source = SourceCodeCollector(workspace)
    source_root = get_source_root(service, graph)
    code_context = source.analyze(service, context, source_root=source_root)
    if code_context:
        context["source_code"] = code_context
        click.echo(f"         {code_context['files_analyzed']} relevant source files found")
        for snippet in code_context.get("snippets", []):
            click.echo(f"         {snippet['file']} ({snippet['match_source']})")
    else:
        click.echo("         No relevant source files found")

    click.echo("  [10/10] Causal chain detection...")
    try:
        from arbiter.core.causal_chain import chain_to_dict, detect_causal_chain, format_chain_text

        chain = detect_causal_chain(context, graph)
        if chain.links:
            context["causal_chain"] = chain_to_dict(chain)
            click.echo(f"         {len(chain.links)} links detected")
            click.echo(format_chain_text(chain))
        else:
            click.echo("         No causal chain detected")
    except Exception as e:
        click.echo(f"         Chain detection failed: {e}")

    data_dir = resolve_output_root() / "collected-data"
    data_dir.mkdir(parents=True, exist_ok=True)
    from datetime import datetime

    date_str = datetime.now().strftime("%Y-%m-%d")
    from arbiter.core.models import slugify

    slug = slugify(service)
    data_path = data_dir / f"{date_str}-{slug}.json"
    data_path.write_text(json.dumps(context, indent=2, default=str))

    click.echo(f"\n  Data saved to: {data_path}")
    click.echo(json.dumps(context, indent=2, default=str))


# ---------------------------------------------------------------------------
# arbiter metrics — incident knowledge base metrics
# ---------------------------------------------------------------------------
@main.command()
def metrics():
    """Show incident metrics from the knowledge base."""
    from arbiter.core.metrics import compute_metrics, format_metrics_text

    incidents_dir = resolve_incidents_root()
    result = compute_metrics(incidents_dir)
    click.echo(format_metrics_text(result))


# ---------------------------------------------------------------------------
# arbiter rebuild-index — rebuild incident index from INC-*.json files
# ---------------------------------------------------------------------------
@main.command("rebuild-index")
def rebuild_index_cmd():
    """Rebuild incidents/index.json from all INC-*.json files."""
    from arbiter.core.incident_store import IncidentStore

    incidents_dir = resolve_incidents_root()
    store = IncidentStore(incidents_dir)
    store.rebuild_index()
    index_path = incidents_dir / "index.json"
    click.echo(f"  Index rebuilt: {index_path}")


# ---------------------------------------------------------------------------
# arbiter version — show current version
# ---------------------------------------------------------------------------
@main.command()
def version():
    """Show current Arbiter version."""
    from arbiter import __version__

    click.echo(f"  Arbiter v{__version__}")


# ---------------------------------------------------------------------------
# arbiter mcp — start MCP server
# ---------------------------------------------------------------------------
@main.command()
def mcp():
    """Start the MCP server (for Claude Code integration)."""
    from arbiter.mcp_server import run_server

    run_server()


if __name__ == "__main__":
    main()
