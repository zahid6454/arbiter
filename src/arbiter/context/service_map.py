"""Service dependency graph — reads from config/services.yaml."""

from __future__ import annotations

import logging
from importlib.resources import files
from pathlib import Path

import yaml

from arbiter.context.workspace import arbiter_home, is_in_repo
from arbiter.core.models import BlastRadiusEntry, ServiceInfo

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(str(files("arbiter.config")))

_MERGED_CONFIG_CACHE: dict | None = None


def _load_merged_config(config_path: Path | None = None) -> dict:
    """Load the full services.yaml config, merging user overrides.

    When ``config_path`` is provided (tests), loads only from that path.
    When running from the repo, loads only the bundled config.
    Otherwise (package install), merges ``~/arbiter/services.yaml`` on top
    of the bundled defaults.  User entries win entirely on duplicate keys.
    """
    global _MERGED_CONFIG_CACHE
    if _MERGED_CONFIG_CACHE is not None and config_path is None:
        return _MERGED_CONFIG_CACHE

    bundled_path = (config_path or CONFIG_DIR) / "services.yaml"
    if not bundled_path.exists():
        return {}

    with open(bundled_path) as f:
        data = yaml.safe_load(f) or {}

    if config_path is None and not is_in_repo():
        user_path = arbiter_home() / "services.yaml"
        if user_path.exists():
            try:
                with open(user_path) as f:
                    user_data = yaml.safe_load(f) or {}
                for section in ("services", "gke_clusters", "environments", "jira"):
                    if user_data.get(section):
                        base = data.get(section, {})
                        base.update(user_data[section])
                        data[section] = base
                logger.info("Merged user overrides from %s", user_path)
            except Exception:
                logger.warning("Failed to parse user services.yaml at %s, skipping", user_path)

    if config_path is None:
        _MERGED_CONFIG_CACHE = data
    return data


def _clear_caches() -> None:
    """Clear all config caches.  For testing only."""
    global _MERGED_CONFIG_CACHE, _GKE_CLUSTERS_CACHE, _ENV_MAP_CACHE
    _MERGED_CONFIG_CACHE = None
    _GKE_CLUSTERS_CACHE = None
    _ENV_MAP_CACHE = None


def load_service_graph(config_path: Path | None = None) -> dict[str, dict]:
    """Load the service dependency graph from services.yaml."""
    return _load_merged_config(config_path).get("services", {})


_GKE_CLUSTERS_CACHE: dict[str, dict] | None = None


def load_gke_clusters(config_path: Path | None = None) -> dict[str, dict]:
    """Load the GKE cluster map from services.yaml (cached after first call)."""
    global _GKE_CLUSTERS_CACHE
    if _GKE_CLUSTERS_CACHE is not None and config_path is None:
        return _GKE_CLUSTERS_CACHE

    result = _load_merged_config(config_path).get("gke_clusters", {})
    if config_path is None:
        _GKE_CLUSTERS_CACHE = result
    return result


def get_gke_cluster_config(service_name: str, graph: dict | None = None) -> dict | None:
    """Return {name, project, location} for the service's GKE cluster, or None."""
    if graph is None:
        graph = load_service_graph()
    canonical = resolve_service_name(service_name, graph)
    svc = graph.get(canonical, {})
    cluster_name = svc.get("infrastructure", {}).get("gke_cluster")
    if not cluster_name:
        return None
    clusters = load_gke_clusters()
    cluster = clusters.get(cluster_name)
    if not cluster:
        return None
    project = cluster.get("project")
    location = cluster.get("location")
    if not project or not location:
        logger.warning(
            "GKE cluster '%s' missing project or location in services.yaml", cluster_name
        )
        return None
    return {
        "name": cluster_name,
        "project": project,
        "location": location,
    }


_ENV_MAP_CACHE: dict[str, str] | None = None


def _load_environment_map(config_path: Path | None = None) -> dict[str, str]:
    """Load the environment alias map from services.yaml (cached after first call)."""
    global _ENV_MAP_CACHE
    if _ENV_MAP_CACHE is not None and config_path is None:
        return _ENV_MAP_CACHE

    data = _load_merged_config(config_path)
    result = {k.lower(): v for k, v in data.get("environments", {}).items()}
    if config_path is None:
        _ENV_MAP_CACHE = result
    return result


def resolve_datadog_environment(env: str, config_path: Path | None = None) -> str:
    """Resolve an environment name or alias to the Datadog env tag."""
    normalized = env.lower().replace("_", "-")
    env_map = _load_environment_map(config_path)
    resolved = env_map.get(normalized, normalized)
    if resolved != normalized:
        logger.info("Resolved environment '%s' -> '%s'", env, resolved)
    return resolved


def detect_environment_from_text(text: str | None, config_path: Path | None = None) -> str | None:
    """Detect an environment name from freeform text (conversation, alert).

    Returns the resolved Datadog env tag, or None if no environment is detected.
    """
    import re

    if not text:
        return None

    env_map = _load_environment_map(config_path)
    text_lower = text.lower()

    sorted_aliases = sorted(env_map.keys(), key=len, reverse=True)

    for alias in sorted_aliases:
        dd_env = env_map[alias]
        if dd_env == "production":
            continue
        if re.search(rf"\b{re.escape(alias)}\b", text_lower):
            logger.info("Auto-detected environment '%s' (-> '%s') from text", alias, dd_env)
            return dd_env

    return None


def _build_alias_map(graph: dict[str, dict]) -> dict[str, str]:
    """Build alias -> canonical name mapping."""
    alias_map: dict[str, str] = {}
    for name, info in graph.items():
        alias_map[name] = name
        for alias in info.get("aliases", []):
            alias_map[alias.lower()] = name
    return alias_map


def resolve_service_name(name: str, graph: dict[str, dict]) -> str:
    """Resolve a service name or alias to its canonical name."""
    normalized = name.lower().replace("_", "-")
    alias_map = _build_alias_map(graph)
    resolved = alias_map.get(normalized, normalized)
    if resolved not in graph:
        logger.warning(
            "Service '%s' not found in services.yaml. Available: %s",
            name,
            ", ".join(sorted(graph.keys())),
        )
    return resolved


def get_service_info(
    service_name: str,
    graph: dict[str, dict] | None = None,
) -> ServiceInfo:
    """Get service metadata including dependencies."""
    if graph is None:
        graph = load_service_graph()

    canonical = resolve_service_name(service_name, graph)
    svc_data = graph.get(canonical, {})

    depended_on_by = []
    for name, info in graph.items():
        if canonical in info.get("depends_on", []):
            depended_on_by.append(name)

    description = svc_data.get("description", "")

    return ServiceInfo(
        name=canonical,
        depends_on=svc_data.get("depends_on", []),
        depended_on_by=depended_on_by,
        description=description,
    )


def get_blast_radius(
    service_name: str,
    graph: dict[str, dict] | None = None,
) -> list[BlastRadiusEntry]:
    """Calculate the blast radius of an incident in a service."""
    if graph is None:
        graph = load_service_graph()

    canonical = resolve_service_name(service_name, graph)
    svc_data = graph.get(canonical, {})

    entries = [BlastRadiusEntry(service=canonical, role="primary", impact="Direct failure")]

    for name, info in graph.items():
        if canonical in info.get("depends_on", []):
            entries.append(
                BlastRadiusEntry(
                    service=name,
                    role="downstream",
                    impact=f"Depends on {canonical}",
                )
            )

    for dep in svc_data.get("depends_on", []):
        entries.append(
            BlastRadiusEntry(
                service=dep,
                role="upstream",
                impact=f"{canonical} depends on this",
            )
        )

    return entries


def list_services(
    graph: dict[str, dict] | None = None,
) -> list[str]:
    """List all known services."""
    if graph is None:
        graph = load_service_graph()
    return sorted(graph.keys())


def get_dependencies(
    service_name: str,
    graph: dict[str, dict] | None = None,
) -> dict[str, list[str]]:
    """Get upstream and downstream dependencies."""
    if graph is None:
        graph = load_service_graph()

    canonical = resolve_service_name(service_name, graph)
    svc_data = graph.get(canonical, {})

    depended_on_by = []
    for name, info in graph.items():
        if canonical in info.get("depends_on", []):
            depended_on_by.append(name)

    return {
        "depends_on": svc_data.get("depends_on", []),
        "depended_on_by": depended_on_by,
    }


def get_related_services(
    service_name: str,
    graph: dict[str, dict] | None = None,
) -> list[str]:
    """Get all services related to this one (upstream + downstream)."""
    deps = get_dependencies(service_name, graph)
    return sorted(set(deps["depends_on"] + deps["depended_on_by"]))


def get_transitive_dependencies(
    service_name: str,
    graph: dict[str, dict] | None = None,
    max_depth: int = 2,
    direction: str = "upstream",
) -> list[dict]:
    """Return transitive dependencies with distance via BFS."""
    from collections import defaultdict, deque

    if direction not in ("upstream", "downstream"):
        raise ValueError(f"direction must be 'upstream' or 'downstream', got '{direction}'")

    if graph is None:
        graph = load_service_graph()

    canonical = resolve_service_name(service_name, graph)
    visited: set[str] = {canonical}
    queue: deque[tuple[str, int, list[str]]] = deque()
    results: list[dict] = []

    reverse_map: dict[str, list[str]] = defaultdict(list)
    if direction == "downstream":
        for name, info in graph.items():
            for dep in info.get("depends_on", []):
                reverse_map[dep].append(name)

    def _get_neighbors(svc: str) -> list[str]:
        if direction == "upstream":
            return graph.get(svc, {}).get("depends_on", [])
        return reverse_map.get(svc, [])

    for neighbor in _get_neighbors(canonical):
        resolved = resolve_service_name(neighbor, graph)
        if resolved not in visited:
            visited.add(resolved)
            queue.append((resolved, 1, [canonical, resolved]))

    while queue:
        svc, depth, path = queue.popleft()
        results.append({"service": svc, "distance": depth, "path": path})
        if depth < max_depth:
            for neighbor in _get_neighbors(svc):
                resolved = resolve_service_name(neighbor, graph)
                if resolved not in visited:
                    visited.add(resolved)
                    queue.append((resolved, depth + 1, [*path, resolved]))

    return results


def get_gcp_project(
    service_name: str,
    graph: dict[str, dict] | None = None,
) -> str | None:
    """Get the GCP project ID for a service from services.yaml."""
    if graph is None:
        graph = load_service_graph()
    canonical = resolve_service_name(service_name, graph)
    svc_data = graph.get(canonical, {})
    return svc_data.get("gcp_project")


def get_source_root(
    service_name: str,
    graph: dict[str, dict] | None = None,
) -> str | None:
    """Get the source_root subdirectory for a service."""
    if graph is None:
        graph = load_service_graph()
    canonical = resolve_service_name(service_name, graph)
    svc_data = graph.get(canonical, {})
    return svc_data.get("source_root")


def get_github_repo(
    service_name: str,
    graph: dict[str, dict] | None = None,
) -> str:
    """Get the GitHub repo (org/name) for a service.

    Returns the github_repo from services.yaml if set,
    otherwise returns {org}/{canonical_name} using the organization config.
    """
    if graph is None:
        graph = load_service_graph()
    canonical = resolve_service_name(service_name, graph)
    svc_data = graph.get(canonical, {})
    if svc_data.get("github_repo"):
        return svc_data["github_repo"]
    org = _load_merged_config().get("organization", {}).get("github_org", "")
    if org:
        return f"{org}/{canonical}"
    return canonical


def get_jira_project(
    service_name: str,
    graph: dict[str, dict] | None = None,
) -> str:
    """Get the Jira project key for a service. Returns empty string if not configured."""
    if graph is None:
        graph = load_service_graph()
    canonical = resolve_service_name(service_name, graph)
    return graph.get(canonical, {}).get("jira_project", "")


def get_jira_cloud_id(config_path: Path | None = None) -> str:
    """Get the Jira cloud ID from the top-level jira config."""
    return _load_merged_config(config_path).get("jira", {}).get("cloud_id", "")


def get_infrastructure_profile(
    service_name: str,
    graph: dict[str, dict] | None = None,
) -> dict:
    """Get the infrastructure profile for a service."""
    if graph is None:
        graph = load_service_graph()
    canonical = resolve_service_name(service_name, graph)
    svc_data = graph.get(canonical, {})
    return svc_data.get("infrastructure", {})


def get_message_queues(
    service_name: str,
    graph: dict[str, dict] | None = None,
) -> list[dict]:
    """Get message queue configuration for a service. Returns [] if none configured."""
    if graph is None:
        graph = load_service_graph()
    canonical = resolve_service_name(service_name, graph)
    return graph.get(canonical, {}).get("message_queues", [])


def get_cloudsql_instance(
    service_name: str,
    graph: dict[str, dict] | None = None,
) -> tuple[str | None, str | None]:
    """Get the CloudSQL instance name and GCP project for a service.

    Returns (instance_name, project). Returns (None, None) if not configured.
    """
    if graph is None:
        graph = load_service_graph()
    canonical = resolve_service_name(service_name, graph)
    svc_data = graph.get(canonical, {})
    instance = svc_data.get("database", {}).get("cloudsql_instance")
    if not instance:
        return None, None
    project = svc_data.get("gcp_project")
    if not project:
        logger.warning(
            "Service '%s' has cloudsql_instance but no gcp_project in services.yaml",
            service_name,
        )
        return None, None
    return instance, project


def get_frontend_config(
    service_name: str,
    graph: dict[str, dict] | None = None,
) -> dict:
    """Get frontend configuration for a service. Returns {} if none configured."""
    if graph is None:
        graph = load_service_graph()
    canonical = resolve_service_name(service_name, graph)
    return graph.get(canonical, {}).get("frontend", {})


def get_noise_filters(
    service_name: str,
    graph: dict[str, dict] | None = None,
) -> list[dict]:
    """Get noise filter rules for a service. Returns [] if none configured."""
    if graph is None:
        graph = load_service_graph()
    canonical = resolve_service_name(service_name, graph)
    return graph.get(canonical, {}).get("noise_filters", [])


def get_datadog_service(
    service_name: str,
    graph: dict[str, dict] | None = None,
) -> str:
    """Get the Datadog service name for a service.

    Returns the datadog_service from services.yaml if set,
    otherwise returns the canonical service name.
    """
    if graph is None:
        graph = load_service_graph()
    canonical = resolve_service_name(service_name, graph)
    svc_data = graph.get(canonical, {})
    return svc_data.get("datadog_service", canonical)
