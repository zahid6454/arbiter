"""Workspace resolver — finds arbiter project root and repo paths."""

from __future__ import annotations

import os
from pathlib import Path

ARBITER_HOME_DEFAULT = Path.home() / "arbiter"


def arbiter_home() -> Path:
    """Return the Arbiter home directory (default ``~/arbiter/``)."""
    return Path(os.environ.get("ARBITER_HOME", str(ARBITER_HOME_DEFAULT))).expanduser()


def resolve_project_root() -> Path:
    """Return the arbiter project root directory.

    In repo mode: the git repo root (3 parents up from this file).
    In package mode (uvx): the arbiter package directory.
    """
    repo_root = Path(__file__).resolve().parents[3]
    if (repo_root / "pyproject.toml").exists():
        return repo_root
    return Path(__file__).resolve().parents[1]


def is_in_repo() -> bool:
    """Detect whether we're running from the arbiter source repository."""
    root = Path(__file__).resolve().parents[3]
    return (root / "pyproject.toml").exists() and (root / "src" / "arbiter").is_dir()


def is_marketplace_mode() -> bool:
    """True when running from a marketplace/plugin install.

    Set ARBITER_MARKETPLACE=1 in your plugin config to enable
    knowledge base sync features.
    """
    return os.environ.get("ARBITER_MARKETPLACE") == "1"


def resolve_workspace() -> Path:
    """Find the workspace root (the directory containing service repos).

    Resolution order:
      1. ARBITER_WORKSPACE_ROOT env var (if set)
      2. In-repo: parent of the arbiter project root
      3. Package mode: ARBITER_HOME (default ~/arbiter/)
    """
    env_root = os.environ.get("ARBITER_WORKSPACE_ROOT")
    if env_root:
        return Path(env_root)

    if is_in_repo():
        return resolve_project_root().parent

    return arbiter_home()


def resolve_output_root() -> Path:
    """Resolve the base directory for Arbiter output (reports, collected-data).

    Pure path resolution — does not create directories.  Callers should
    call ``path.mkdir(parents=True, exist_ok=True)`` before writing.

    Resolution order:
      1. ARBITER_OUTPUT_DIR env var
      2. In-repo: {project_root}/output/
      3. Package mode: $ARBITER_HOME/output/ (default ~/arbiter/output/)
    """
    env_dir = os.environ.get("ARBITER_OUTPUT_DIR")
    if env_dir:
        return Path(env_dir)

    if is_in_repo():
        return resolve_project_root() / "output"

    return arbiter_home() / "output"


def resolve_incidents_root() -> Path:
    """Resolve the base directory for the incident knowledge base.

    Pure path resolution — does not create directories.

    Resolution order:
      1. ARBITER_OUTPUT_DIR env var → {dir}/incidents/
      2. In-repo: {project_root}/incidents/
      3. Package mode: $ARBITER_HOME/incidents/ (default ~/arbiter/incidents/)
    """
    env_dir = os.environ.get("ARBITER_OUTPUT_DIR")
    if env_dir:
        return Path(env_dir) / "incidents"

    if is_in_repo():
        return resolve_project_root() / "incidents"

    return arbiter_home() / "incidents"


def resolve_claude_md() -> Path | None:
    """Resolve the path to CLAUDE.md for serving as an MCP resource.

    Resolution order:
      1. ARBITER_PROJECT_ROOT env var
      2. In-repo: arbiter project root
    """
    env_root = os.environ.get("ARBITER_PROJECT_ROOT")
    if env_root:
        candidate = Path(env_root) / "CLAUDE.md"
        if candidate.is_file():
            return candidate

    if is_in_repo():
        candidate = resolve_project_root() / "CLAUDE.md"
        if candidate.is_file():
            return candidate

    return None


def resolve_repo(service_name: str, workspace: Path | None = None) -> Path | None:
    """Find the repo directory for a service."""
    ws = workspace or resolve_workspace()
    repo_path = ws / service_name
    if repo_path.is_dir():
        return repo_path
    return None
