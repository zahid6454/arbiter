"""Version detection and update checking for Arbiter."""

from __future__ import annotations

import logging
import os
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

TAG_PREFIX = "v"


@dataclass
class VersionInfo:
    current_version: str
    latest_version: str
    update_available: bool
    release_url: str = ""


def _parse_version(tag: str) -> tuple[int, ...]:
    """Strip tag prefix and convert to comparable tuple."""
    version_str = tag.strip()
    if version_str.startswith("v"):
        version_str = version_str[1:]
    parts: list[int] = []
    for part in version_str.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            break
    return tuple(parts) if parts else (0,)


def _resolve_project_root() -> Path:
    """Resolve the project root directory."""
    for var in ("ARBITER_PROJECT_ROOT",):
        val = os.environ.get(var)
        if val:
            return Path(val)
    from arbiter.context.workspace import resolve_project_root

    return resolve_project_root()


def get_local_version(project_root: Path | None = None) -> str:
    """Get the current version from git tags, falling back to __version__."""
    root = project_root or _resolve_project_root()
    try:
        result = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=str(root),
        )
        if result.returncode == 0:
            tag = result.stdout.strip()
            if tag.startswith("v"):
                return tag[1:]
            return tag
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    from arbiter import __version__

    return __version__


def _check_via_gh(repo: str) -> tuple[str, str] | None:
    """Check latest version via gh CLI. Returns (tag, url) or None."""
    try:
        result = subprocess.run(
            ["gh", "api", f"repos/{repo}/releases/latest", "--jq", "[.tag_name,.html_url] | @tsv"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split("\t", 1)
            tag = parts[0]
            url = parts[1] if len(parts) > 1 else ""
            return tag, url
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


def _check_via_git_remote(project_root: Path) -> tuple[str, str] | None:
    """Fallback: check latest tag via git ls-remote."""
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--tags", "--sort=-v:refname", "origin", f"{TAG_PREFIX}*"],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(project_root),
        )
        if result.returncode == 0 and result.stdout.strip():
            first_line = result.stdout.strip().split("\n")[0]
            ref = first_line.split()[-1]
            tag = ref.replace("refs/tags/", "").rstrip("^{}")
            return tag, ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return None


def check_latest_version(
    repo: str = "",
    project_root: Path | None = None,
) -> VersionInfo | None:
    """Check GitHub for the latest release. Returns None on any failure."""
    if not repo:
        return None

    current = get_local_version(project_root)
    root = project_root or _resolve_project_root()

    result = _check_via_gh(repo)
    if result is None:
        result = _check_via_git_remote(root)
    if result is None:
        return None

    tag, url = result
    latest_str = tag
    if latest_str.startswith("v"):
        latest_str = latest_str[1:]

    update_available = _parse_version(latest_str) > _parse_version(current)

    return VersionInfo(
        current_version=current,
        latest_version=latest_str,
        update_available=update_available,
        release_url=url,
    )


# ---------------------------------------------------------------------------
# Background check — fire once at startup, read later from MCP resource/tool
# ---------------------------------------------------------------------------

_update_state: VersionInfo | None = None
_check_started: bool = False
_check_lock = threading.Lock()


def _run_check(repo: str) -> None:
    global _update_state
    try:
        _update_state = check_latest_version(repo=repo)
    except Exception:
        logger.debug("Background version check failed", exc_info=True)


def start_background_check(repo: str = "") -> None:
    """Start a non-blocking version check in a daemon thread."""
    global _check_started
    if not repo:
        return
    with _check_lock:
        if _check_started and _update_state is not None:
            return
        _check_started = True
    t = threading.Thread(target=_run_check, args=(repo,), daemon=True, name="arbiter-version-check")
    t.start()


def get_update_state() -> VersionInfo | None:
    """Return the cached version check result, or None if not yet available."""
    return _update_state
