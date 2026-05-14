"""Knowledge base sync — pulls/pushes incident records via GitHub API."""

from __future__ import annotations

import base64
import contextlib
import json
import logging
import os
import subprocess
import tempfile
import time
from pathlib import Path

logger = logging.getLogger(__name__)


class IncidentSync:
    """Syncs the incident knowledge base with a configurable GitHub repo.

    Pull: fetches index.json before similarity searches so users
    get matches against the full shared knowledge base.

    Push: creates a PR with new incident records after save_incident_record.
    """

    INCIDENTS_PATH = "incidents"
    INDEX_FILE = "index.json"

    def __init__(self, incidents_dir: Path, repo: str = ""):
        self.incidents_dir = incidents_dir
        self.repo = repo
        self._last_pull_time: float | None = None
        self._pull_ttl: float = 300  # 5 minutes
        self._gh_available: bool | None = None

    def is_gh_available(self) -> bool:
        """Check if gh CLI is installed and authenticated. Cached for session."""
        if self._gh_available is not None:
            return self._gh_available

        try:
            result = subprocess.run(
                ["gh", "auth", "status"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self._gh_available = result.returncode == 0
            if not self._gh_available:
                logger.warning("gh CLI not authenticated — knowledge base sync disabled")
        except FileNotFoundError:
            logger.warning("gh CLI not installed — knowledge base sync disabled")
            self._gh_available = False
        except subprocess.TimeoutExpired:
            logger.warning("gh auth status timed out — knowledge base sync disabled")
            self._gh_available = False

        return self._gh_available

    def pull_index(self, force: bool = False) -> bool:
        """Fetch index.json from GitHub. Returns True if index is available."""
        if not self.repo:
            return self._has_cached_index()

        if not self.is_gh_available():
            return self._has_cached_index()

        if (
            not force
            and self._last_pull_time is not None
            and (time.time() - self._last_pull_time) < self._pull_ttl
        ):
            return self._has_cached_index()

        content = self._gh_api_raw(
            f"repos/{self.repo}/contents/{self.INCIDENTS_PATH}/{self.INDEX_FILE}",
            headers=["Accept: application/vnd.github.raw+json"],
        )

        if content is None:
            logger.warning("Failed to pull index.json from GitHub — using cached copy")
            self._last_pull_time = time.time()
            return self._has_cached_index()

        try:
            json.loads(content)
        except json.JSONDecodeError:
            logger.warning("Pulled index.json is not valid JSON — using cached copy")
            self._last_pull_time = time.time()
            return self._has_cached_index()

        self.incidents_dir.mkdir(parents=True, exist_ok=True)
        index_path = self.incidents_dir / self.INDEX_FILE
        tmp_fd, tmp_path = tempfile.mkstemp(dir=str(self.incidents_dir), suffix=".json.tmp")
        try:
            with os.fdopen(tmp_fd, "w") as f:
                f.write(content)
            os.replace(tmp_path, str(index_path))
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise

        self._last_pull_time = time.time()
        return True

    def push_incident(self, record_path: Path, record_data: dict, incident_id: str) -> dict:
        """Create a PR on GitHub with a new incident record."""
        if not self.repo:
            return self._manual_instructions("No sync repo configured")

        if not self.is_gh_available():
            return self._manual_instructions("gh CLI not available")

        # 1. Get main SHA
        ref_data = self._gh_api_json(f"repos/{self.repo}/git/ref/heads/main")
        if not ref_data:
            return self._manual_instructions("Failed to get main branch ref")
        main_sha = ref_data["object"]["sha"]

        # 2. Create branch
        branch_name = f"arbiter/incident/{incident_id}"
        branch_result = self._gh_api_json(
            f"repos/{self.repo}/git/refs",
            method="POST",
            body={"ref": f"refs/heads/{branch_name}", "sha": main_sha},
        )
        if branch_result is None:
            update_result = self._gh_api_json(
                f"repos/{self.repo}/git/refs/heads/{branch_name}",
                method="PATCH",
                body={"sha": main_sha, "force": True},
            )
            if update_result is None:
                return self._manual_instructions(f"Failed to create or update branch {branch_name}")

        # 3. Upload incident file
        record_content = json.dumps(record_data, indent=2, default=str)
        encoded_record = base64.b64encode(record_content.encode()).decode()
        upload_result = self._gh_api_json(
            f"repos/{self.repo}/contents/{self.INCIDENTS_PATH}/{incident_id}.json",
            method="PUT",
            body={
                "message": f"Add incident record: {record_data.get('title', incident_id)}",
                "content": encoded_record,
                "branch": branch_name,
            },
        )
        if upload_result is None:
            return self._manual_instructions("Failed to upload incident file")

        # 4. Create PR
        pr_body = (
            f"**Incident:** {record_data.get('title', incident_id)}\n"
            f"**Service:** {record_data.get('service', 'unknown')}\n"
            f"**Date:** {record_data.get('date', 'unknown')}\n"
            f"**Severity:** {record_data.get('severity', 'unknown')}\n"
            f"**Root Cause:** {record_data.get('root_cause_category', 'unknown')}\n\n"
            f"Auto-generated by Arbiter knowledge base sync."
        )
        pr_result = self._gh_api_json(
            f"repos/{self.repo}/pulls",
            method="POST",
            body={
                "title": f"Incident record: {record_data.get('title', incident_id)}",
                "body": pr_body,
                "head": branch_name,
                "base": "main",
            },
        )
        if pr_result is None:
            return self._manual_instructions("Failed to create PR")

        return {
            "status": "created",
            "pr_url": pr_result.get("html_url", ""),
            "pr_number": pr_result.get("number"),
        }

    def _has_cached_index(self) -> bool:
        index_path = self.incidents_dir / self.INDEX_FILE
        return index_path.exists()

    def _gh_api_raw(
        self,
        endpoint: str,
        headers: list[str] | None = None,
        timeout: int = 30,
    ) -> str | None:
        """Call GitHub API via gh CLI, return raw stdout."""
        args = ["gh", "api", endpoint]
        for h in headers or []:
            args.extend(["--header", h])

        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
            if result.returncode != 0:
                logger.warning("gh api %s failed: %s", endpoint, result.stderr.strip()[:200])
                return None
            return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning("gh api call failed: %s", e)
            return None

    def _gh_api_json(
        self,
        endpoint: str,
        method: str | None = None,
        body: dict | None = None,
        timeout: int = 30,
    ) -> dict | None:
        """Call GitHub API via gh CLI, return parsed JSON."""
        args = ["gh", "api", endpoint, "--header", "Accept: application/vnd.github+json"]
        if method:
            args.extend(["--method", method])
        if body:
            args.extend(["--input", "-"])

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=json.dumps(body) if body else None,
            )
            if result.returncode != 0:
                logger.warning("gh api %s failed: %s", endpoint, result.stderr.strip()[:200])
                return None
            return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning("gh api call failed: %s", e)
            return None

    @staticmethod
    def _manual_instructions(reason: str) -> dict:
        return {
            "status": "failed",
            "error": reason,
            "manual_instructions": (
                "The incident record was saved locally. To share it with your team:\n"
                "1. Clone your knowledge base repo\n"
                "2. Copy your incident file into incidents/\n"
                "3. Commit and open a PR\n"
                "4. The index will be rebuilt automatically after merge"
            ),
        }
