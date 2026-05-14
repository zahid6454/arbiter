"""GitHub collector — fetches PR details, reviews, merged PRs, code search, and releases via gh CLI."""

from __future__ import annotations

import json
import logging
import re
import subprocess
from datetime import UTC, datetime, timedelta

from arbiter.collectors.base import Collector
from arbiter.core.models import EventSource, LogEntry, TimelineEvent

logger = logging.getLogger(__name__)


def _gh_api(endpoint: str, params: dict | None = None, timeout: int = 30) -> dict | list | None:
    """Call GitHub REST API via gh CLI. Returns parsed JSON or None on failure."""
    args = ["gh", "api", endpoint, "--header", "Accept: application/vnd.github+json"]
    if params:
        # -f switches to POST by default; force GET so params go as query string.
        args.extend(["--method", "GET"])
    for key, value in (params or {}).items():
        args.extend(["-f", f"{key}={value}"])

    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            logger.warning("gh api %s failed: %s", endpoint, result.stderr.strip()[:200])
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("gh api call failed: %s", e)
        return None


def _gh_search(query: str, limit: int = 30, timeout: int = 30) -> list[dict]:
    """Search GitHub via gh CLI search command. Returns list of results."""
    try:
        result = subprocess.run(
            [
                "gh",
                "search",
                "prs",
                "--json",
                "number,title,author,mergedAt,url,repository",
                "--limit",
                str(limit),
                *query.split(),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            logger.warning("gh search failed: %s", result.stderr.strip()[:200])
            return []
        return json.loads(result.stdout) or []
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("gh search failed: %s", e)
        return []


class GitHubCollector(Collector):
    """Collector for GitHub data — PRs, reviews, deploys (merged PRs)."""

    def __init__(self, default_org: str = ""):
        self.default_org = default_org

    @property
    def source(self) -> EventSource:
        return EventSource.GITHUB

    def is_configured(self) -> bool:
        """Check if gh CLI is installed and authenticated."""
        try:
            result = subprocess.run(
                ["gh", "auth", "status"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def collect_logs(self, service: str = "", **kwargs) -> list[LogEntry]:
        return []

    def collect_events(
        self,
        service: str,
        time_range: str = "2h",
        from_time: str | None = None,
        to_time: str | None = None,
    ) -> list[TimelineEvent]:
        """Return recently merged PRs as timeline events."""
        repo = self._resolve_repo(service)
        hours = _time_range_to_hours(time_range)
        prs = self.get_merged_prs(repo, hours_back=hours, from_time=from_time, to_time=to_time)
        return [
            TimelineEvent(
                timestamp=pr.get("merged_at", ""),
                message=f"PR #{pr['number']} merged: {pr['title']} ({pr['author']})",
                source=EventSource.GITHUB,
                service=service,
                metadata=pr,
            )
            for pr in prs
        ]

    def _resolve_repo(self, service_or_repo: str) -> str:
        """Resolve to org/repo format. If already contains '/', use as-is."""
        if "/" in service_or_repo:
            return service_or_repo
        return f"{self.default_org}/{service_or_repo}"

    def get_pr(self, repo: str, pr_number: int) -> dict | None:
        """Get full details for a single PR.

        Returns: dict with number, title, body, state, author, merged_at,
        created_at, labels, changed_files count, additions, deletions.
        """
        repo = self._resolve_repo(repo)
        data = _gh_api(f"repos/{repo}/pulls/{pr_number}")
        if not data:
            return None

        return {
            "number": data.get("number"),
            "title": data.get("title", ""),
            "body": data.get("body", ""),
            "state": data.get("state", ""),
            "merged": data.get("merged", False),
            "merged_at": data.get("merged_at", ""),
            "created_at": data.get("created_at", ""),
            "author": (data.get("user") or {}).get("login", ""),
            "labels": [l.get("name", "") for l in data.get("labels", [])],
            "changed_files": data.get("changed_files", 0),
            "additions": data.get("additions", 0),
            "deletions": data.get("deletions", 0),
            "url": data.get("html_url", ""),
        }

    def get_pr_files(self, repo: str, pr_number: int) -> list[dict]:
        """Get files changed in a PR with patch diffs.

        Returns: list of dicts with filename, status, additions, deletions, patch.
        """
        repo = self._resolve_repo(repo)
        data = _gh_api(f"repos/{repo}/pulls/{pr_number}/files")
        if not data or not isinstance(data, list):
            return []

        return [
            {
                "filename": f.get("filename", ""),
                "status": f.get("status", ""),
                "additions": f.get("additions", 0),
                "deletions": f.get("deletions", 0),
                "patch": (f.get("patch") or "")[:2000],
            }
            for f in data
        ]

    def get_pr_reviews(self, repo: str, pr_number: int) -> list[dict]:
        """Get review comments on a PR.

        Returns: list of dicts with author, state, body, submitted_at.
        """
        repo = self._resolve_repo(repo)
        data = _gh_api(f"repos/{repo}/pulls/{pr_number}/reviews")
        if not data or not isinstance(data, list):
            return []

        return [
            {
                "author": (r.get("user") or {}).get("login", ""),
                "state": r.get("state", ""),
                "body": (r.get("body") or "")[:1000],
                "submitted_at": r.get("submitted_at", ""),
            }
            for r in data
            if r.get("state") != "PENDING"
        ]

    def get_merged_prs(
        self,
        repo: str,
        hours_back: int = 48,
        from_time: str | None = None,
        to_time: str | None = None,
        limit: int = 20,
    ) -> list[dict]:
        """Get recently merged PRs — these represent deploys.

        Args:
            repo: GitHub repo (org/name or just name)
            hours_back: How far back to look (used if from_time not set)
            from_time: Absolute start time (ISO 8601)
            to_time: Absolute end time (ISO 8601)
            limit: Max PRs to return
        """
        repo = self._resolve_repo(repo)

        if from_time:
            since = from_time.replace("+00:00", "Z")
            if to_time:
                until = to_time.replace("+00:00", "Z")
            else:
                until = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            now = datetime.now(UTC)
            since = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
            until = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Use the search API to find merged PRs in the time range
        query = f"repo:{repo} is:pr is:merged merged:{since}..{until}"
        data = _gh_api(
            "search/issues",
            params={"q": query, "sort": "updated", "order": "desc", "per_page": str(limit)},
        )
        if not data or "items" not in data:
            return []

        prs = []
        for item in data["items"][:limit]:
            pr_data = item.get("pull_request", {})
            prs.append(
                {
                    "number": item.get("number"),
                    "title": item.get("title", ""),
                    "author": (item.get("user") or {}).get("login", ""),
                    "merged_at": pr_data.get("merged_at", ""),
                    "created_at": item.get("created_at", ""),
                    "url": item.get("html_url", ""),
                    "labels": [l.get("name", "") for l in item.get("labels", [])],
                }
            )

        return prs

    def get_deploy_correlation(
        self,
        repo: str,
        incident_start: str,
        window_hours: int = 6,
    ) -> dict:
        """Find PRs merged shortly before an incident — potential deploy triggers.

        Args:
            repo: GitHub repo (org/name or just name)
            incident_start: When the incident began (ISO 8601)
            window_hours: How many hours before the incident to search

        Returns:
            Dict with pre_incident PRs (merged before incident) and
            during_incident PRs (merged after incident start).
        """
        from dateutil import parser as dateutil_parser

        incident_dt = dateutil_parser.isoparse(incident_start)
        window_start = incident_dt - timedelta(hours=window_hours)
        window_end = incident_dt + timedelta(hours=2)

        prs = self.get_merged_prs(
            repo,
            from_time=window_start.isoformat(),
            to_time=window_end.isoformat(),
        )

        pre_incident = []
        during_incident = []

        for pr in prs:
            merged_at = pr.get("merged_at", "")
            if not merged_at:
                continue
            try:
                merged_dt = dateutil_parser.isoparse(merged_at)
                if merged_dt < incident_dt:
                    hours_before = (incident_dt - merged_dt).total_seconds() / 3600
                    pr["hours_before_incident"] = round(hours_before, 1)
                    pre_incident.append(pr)
                else:
                    during_incident.append(pr)
            except (ValueError, TypeError):
                continue

        return {
            "incident_start": incident_start,
            "search_window": f"{window_start.isoformat()} to {window_end.isoformat()}",
            "pre_incident_deploys": sorted(
                pre_incident, key=lambda p: p.get("hours_before_incident", 999)
            ),
            "during_incident_deploys": during_incident,
        }

    def get_workflow_deploys(
        self,
        repo: str,
        workflow_name: str = "",
        hours_back: int = 48,
        from_time: str | None = None,
        to_time: str | None = None,
    ) -> list[dict]:
        """Fetch GitHub Actions workflow runs — tag-based deploys.

        Args:
            repo: GitHub repo (org/name or just name)
            workflow_name: Filter by workflow filename (e.g. "deploy.yml")
            hours_back: How far back to look (used if from_time not set)
            from_time: Absolute start time (ISO 8601)
            to_time: Absolute end time (ISO 8601)
        """
        repo = self._resolve_repo(repo)
        endpoint = f"repos/{repo}/actions/runs"
        params: dict[str, str] = {"per_page": "30"}
        if workflow_name:
            endpoint = f"repos/{repo}/actions/workflows/{workflow_name}/runs"

        if from_time:
            created = f"{from_time.replace('+00:00', 'Z')}..{(to_time or datetime.now(UTC).isoformat()).replace('+00:00', 'Z')}"
            params["created"] = created
        else:
            now = datetime.now(UTC)
            since = (now - timedelta(hours=hours_back)).strftime("%Y-%m-%dT%H:%M:%SZ")
            params["created"] = f">{since}"

        data = _gh_api(endpoint, params=params)
        if not data or not isinstance(data, dict):
            return []

        runs = []
        for run in data.get("workflow_runs", []):
            tag = ""
            head_branch = run.get("head_branch", "")
            if head_branch and re.match(r"v?\d+\.\d+", head_branch):
                tag = head_branch

            runs.append(
                {
                    "type": "workflow_run",
                    "workflow": run.get("name", ""),
                    "workflow_file": run.get("path", ""),
                    "sha": run.get("head_sha", "")[:12],
                    "created_at": run.get("created_at", ""),
                    "conclusion": run.get("conclusion", ""),
                    "status": run.get("status", ""),
                    "tag": tag,
                    "branch": head_branch,
                    "url": run.get("html_url", ""),
                }
            )
        return runs

    def get_recent_tags(self, repo: str, limit: int = 10) -> list[dict]:
        """Fetch recent tags for a repo.

        Args:
            repo: GitHub repo (org/name or just name)
            limit: Max tags to return (default: 10)
        """
        repo = self._resolve_repo(repo)
        data = _gh_api(f"repos/{repo}/tags", params={"per_page": str(limit)})
        if not data or not isinstance(data, list):
            return []

        return [
            {
                "name": tag.get("name", ""),
                "sha": (tag.get("commit") or {}).get("sha", "")[:12],
            }
            for tag in data[:limit]
        ]

    def search_code(
        self,
        query: str,
        repo: str = "",
        language: str = "",
        filename: str = "",
        path: str = "",
        limit: int = 20,
    ) -> list[dict]:
        """Search GitHub code via gh CLI.

        Args:
            query: Search term (function name, error message, variable name)
            repo: Specific repo to search (org/name). If empty, searches org-wide.
            language: Filter by language (python, go, javascript)
            filename: Filter by filename (e.g. "models.py")
            path: Filter by path prefix
            limit: Max results (default: 20)
        """
        args = ["gh", "search", "code", query, "--json", "path,repository,sha,textMatches"]
        if repo:
            args.extend(["--repo", self._resolve_repo(repo)])
        else:
            args.extend(["--owner", self.default_org])
        if language:
            args.extend(["--language", language])
        if filename:
            args.extend(["--filename", filename])
        if path:
            args[3] = f"{query} path:{path}"
        args.extend(["--limit", str(limit)])

        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                stderr = result.stderr.strip()[:200]
                if "authentication" in stderr.lower() or "login" in stderr.lower():
                    logger.error(
                        "GitHub CLI is not authenticated. Run `gh auth login` to enable code search."
                    )
                else:
                    logger.warning("gh search code failed: %s", stderr)
                return []
            data = json.loads(result.stdout) or []
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning("gh search code failed: %s", e)
            return []

        results = []
        for item in data:
            repo_info = item.get("repository", {})
            repo_url = repo_info.get("url", "")
            repo_name = repo_info.get("nameWithOwner", "") or repo_info.get("fullName", "")
            sha = item.get("sha", "")
            file_path = item.get("path", "")
            url = f"{repo_url}/blob/{sha}/{file_path}" if repo_url and sha and file_path else ""
            results.append(
                {
                    "path": file_path,
                    "repo": repo_name,
                    "sha": sha[:12] if sha else "",
                    "url": url,
                    "text_matches": item.get("textMatches", []),
                }
            )
        return results

    def read_file(
        self,
        repo: str,
        path: str,
        ref: str = "",
        start_line: int = 0,
        end_line: int = 0,
    ) -> dict:
        """Read a source file from GitHub.

        Args:
            repo: GitHub repo (org/name or just name)
            path: File path within the repo (e.g. "src/app.py")
            ref: Branch, tag, or commit SHA (default: repo default branch)
            start_line: Start line (1-indexed, inclusive). 0 = from beginning.
            end_line: End line (1-indexed, inclusive). 0 = to end.

        Returns:
            Dict with path, ref, content (decoded UTF-8 with line numbers),
            total_lines, and truncated flag. On error, returns {"error": ...}.
        """
        repo = self._resolve_repo(repo)
        endpoint = f"repos/{repo}/contents/{path}"
        params: dict[str, str] = {}
        if ref:
            params["ref"] = ref

        data = _gh_api(endpoint, params=params if params else None, timeout=15)
        if data is None:
            return {"error": f"File not found or API error: {repo}/{path}"}
        if isinstance(data, list):
            return {"error": f"Path is a directory, not a file: {path}"}

        encoding = data.get("encoding", "")
        if encoding != "base64":
            return {"error": f"Unsupported encoding: {encoding}. File may be binary or >1MB."}

        import base64

        try:
            raw = base64.b64decode(data.get("content", ""))
            content = raw.decode("utf-8")
        except Exception:
            return {"error": f"Cannot decode file as UTF-8 — likely a binary file: {path}"}

        lines = content.splitlines()
        total_lines = len(lines)

        if start_line > 0 or end_line > 0:
            s = max(start_line - 1, 0)
            e = end_line if end_line > 0 else total_lines
            lines = lines[s:e]
            line_offset = s
        else:
            line_offset = 0

        numbered = "\n".join(f"{i + line_offset + 1:>4}\t{line}" for i, line in enumerate(lines))

        return {
            "path": path,
            "ref": ref or "(default branch)",
            "blob_sha": data.get("sha", "")[:12],
            "content": numbered,
            "total_lines": total_lines,
            "showing": f"{line_offset + 1}-{line_offset + len(lines)}",
            "truncated": len(lines) < total_lines,
        }

    def get_releases(
        self,
        repo: str,
        limit: int = 10,
        from_time: str | None = None,
        to_time: str | None = None,
    ) -> list[dict]:
        """Fetch releases for a repo.

        Args:
            repo: GitHub repo (org/name or just name)
            limit: Max releases to return (default: 10)
            from_time: Filter releases published after this time (ISO 8601)
            to_time: Filter releases published before this time (ISO 8601)
        """
        from dateutil import parser as dateutil_parser

        repo = self._resolve_repo(repo)
        data = _gh_api(f"repos/{repo}/releases", params={"per_page": str(limit)})
        if not data or not isinstance(data, list):
            return []

        try:
            from_dt = dateutil_parser.isoparse(from_time) if from_time else None
            to_dt = dateutil_parser.isoparse(to_time) if to_time else None
        except (ValueError, TypeError):
            from_dt = None
            to_dt = None

        releases = []
        for r in data[:limit]:
            published = r.get("published_at", "")
            if published and (from_dt or to_dt):
                try:
                    pub_dt = dateutil_parser.isoparse(published)
                    if from_dt and pub_dt < from_dt:
                        continue
                    if to_dt and pub_dt > to_dt:
                        continue
                except (ValueError, TypeError):
                    pass

            body = r.get("body") or ""
            releases.append(
                {
                    "tag": r.get("tag_name", ""),
                    "name": r.get("name", ""),
                    "author": (r.get("author") or {}).get("login", ""),
                    "published_at": published,
                    "body": body[:2000],
                    "draft": r.get("draft", False),
                    "prerelease": r.get("prerelease", False),
                    "url": r.get("html_url", ""),
                }
            )
        return releases


def strip_variable_parts(msg: str) -> str:
    """Strip UUIDs, timestamps, and numeric IDs from an error message for code search.

    Unlike normalize_error_message() which replaces with placeholders (<UUID>),
    this removes variable parts entirely so the remaining static text is a valid
    search query.
    """
    stripped = re.sub(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "",
        msg,
    )
    stripped = re.sub(r"\d{10,}", "", stripped)
    stripped = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\dZ+-]*", "", stripped)
    stripped = re.sub(r"\s+", " ", stripped).strip()
    return stripped


def _time_range_to_hours(time_range: str) -> int:
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
