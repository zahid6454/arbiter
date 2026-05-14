"""Git collector — gathers recent commits, tags, blame, and changed files."""

from __future__ import annotations

import subprocess
from pathlib import Path

from arbiter.collectors.base import Collector
from arbiter.core.models import EventSource, LogEntry, TimelineEvent


def _run_git(repo_path: Path, args: list[str], timeout: int = 30) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


class GitCollector(Collector):
    """Collector for git history — commits, tags, blame."""

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root

    @property
    def source(self) -> EventSource:
        return EventSource.GIT

    def collect_logs(self, service: str = "", **kwargs) -> list[LogEntry]:
        return []

    def collect_events(
        self,
        service: str,
        time_range: str = "2h",
        from_time: str | None = None,
        to_time: str | None = None,
    ) -> list[TimelineEvent]:
        """Return recent commits as timeline events."""
        repo_path = self.workspace_root / service
        if not repo_path.is_dir():
            return []

        hours = self._time_range_to_hours(time_range)
        commits = self.get_recent_commits(repo_path, hours_back=hours)
        return [
            TimelineEvent(
                timestamp=c["date"],
                message=f"Deploy: {c['message']} ({c['author']})",
                source=EventSource.GIT,
                service=service,
                metadata=c,
            )
            for c in commits
        ]

    def _time_range_to_hours(self, time_range: str) -> int:
        mapping = {
            "15m": 1,
            "30m": 1,
            "1h": 2,
            "2h": 4,
            "4h": 8,
            "6h": 12,
            "12h": 24,
            "24h": 48,
            "1d": 48,
            "2d": 72,
            "7d": 168,
        }
        return mapping.get(time_range, 48)

    def get_recent_commits(self, repo_path: Path, hours_back: int = 24) -> list[dict]:
        since = f"{hours_back} hours ago"
        output = _run_git(
            repo_path,
            ["log", f"--since={since}", "--format=%H|%an|%ae|%ai|%s", "--all", "-50"],
        )
        if not output:
            return []

        commits = []
        for line in output.splitlines():
            parts = line.split("|", 4)
            if len(parts) == 5:
                commits.append(
                    {
                        "hash": parts[0][:12],
                        "author": parts[1],
                        "email": parts[2],
                        "date": parts[3],
                        "message": parts[4],
                    }
                )
        return commits

    def get_recent_tags(self, repo_path: Path, count: int = 5) -> list[dict]:
        output = _run_git(
            repo_path,
            [
                "tag",
                "--sort=-creatordate",
                "--format=%(refname:short)|%(creatordate:iso)|%(subject)",
                f"-n{count}",
            ],
        )
        if not output:
            return []

        tags = []
        for line in output.splitlines():
            parts = line.split("|", 2)
            if len(parts) >= 2:
                tags.append(
                    {
                        "tag": parts[0],
                        "date": parts[1],
                        "message": parts[2] if len(parts) > 2 else "",
                    }
                )
        return tags

    def get_current_branch(self, repo_path: Path) -> str:
        return _run_git(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"])

    def get_changed_files(self, repo_path: Path, hours_back: int = 24) -> list[str]:
        output = _run_git(
            repo_path,
            ["log", f"--since={hours_back} hours ago", "--name-only", "--format=", "--all"],
        )
        if not output:
            return []
        return sorted(set(line.strip() for line in output.splitlines() if line.strip()))

    def gather_context(self, service: str, hours_back: int = 24) -> dict:
        """Gather comprehensive git context for a service."""
        repo_path = self.workspace_root / service
        if not repo_path.is_dir():
            return {"error": f"Repo not found at {repo_path}"}

        return {
            "repo": repo_path.name,
            "current_branch": self.get_current_branch(repo_path),
            "recent_commits": self.get_recent_commits(repo_path, hours_back),
            "recent_tags": self.get_recent_tags(repo_path),
            "changed_files": self.get_changed_files(repo_path, hours_back),
        }
