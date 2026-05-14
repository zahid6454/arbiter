"""Source code collector — reads relevant source files based on error context."""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# File extensions to search
SOURCE_EXTENSIONS = {".py", ".go", ".js", ".ts", ".java", ".rb"}

# Directories to skip
SKIP_DIRS = {
    "test",
    "tests",
    "migrations",
    "vendor",
    "node_modules",
    "__pycache__",
    ".git",
    ".venv",
    "venv",
    "dist",
    "build",
}

# Max constraints
MAX_FILES = 5
MAX_LINES_PER_FILE = 100
CONTEXT_LINES = 40


@dataclass
class SourceSnippet:
    """A relevant source code snippet."""

    file: str  # relative to repo root
    lines: str  # e.g., "180-220"
    content: str
    relevance: str  # why this file was selected
    match_source: str  # "stack_trace", "entity_grep", "keyword_grep"


class SourceCodeCollector:
    """Analyzes error context to find and read relevant source files."""

    def __init__(self, workspace_root: Path):
        self.workspace_root = workspace_root

    def analyze(
        self,
        service_name: str,
        context: dict,
        source_root: str | None = None,
    ) -> dict | None:
        """Analyze collected error context and find relevant source code.

        Args:
            service_name: Service name (used to find repo directory)
            context: The collected incident context dict
            source_root: Subdirectory within repo to search (e.g., "backend/flags")

        Returns:
            Dict with search terms used and source snippets, or None.
        """
        repo_path = self.workspace_root / service_name
        if not repo_path.is_dir():
            logger.warning("Repo not found at %s", repo_path)
            return None

        search_path = repo_path / source_root if source_root else repo_path

        snippets: list[dict] = []

        # Strategy A: Extract explicit file paths from stack traces
        file_refs = self._extract_file_paths(context)
        for ref in file_refs:
            if len(snippets) >= MAX_FILES:
                break
            snippet = self._read_snippet(
                repo_path,
                ref["file"],
                center_line=ref.get("line"),
                relevance=f"Referenced in stack trace: {ref.get('source', 'error')}",
                match_source="stack_trace",
            )
            if snippet:
                snippets.append(snippet)

        # Strategy B: Extract entity/class names and grep the repo
        search_terms = self._extract_search_terms(context)
        if search_terms and len(snippets) < MAX_FILES:
            grep_results = self._grep_repo(search_path, search_terms)
            for result in grep_results:
                if len(snippets) >= MAX_FILES:
                    break
                # Skip if we already have this file
                if any(s["file"] == result["file"] for s in snippets):
                    continue
                snippet = self._read_snippet(
                    repo_path,
                    result["file"],
                    center_line=result.get("line"),
                    relevance=f"Contains '{result['term']}' — {result.get('context', '')}",
                    match_source="entity_grep",
                )
                if snippet:
                    snippets.append(snippet)

        if not snippets:
            return None

        return {
            "files_analyzed": len(snippets),
            "search_terms_used": search_terms[:10],
            "file_paths_from_traces": [r["file"] for r in file_refs],
            "snippets": snippets,
        }

    def _extract_file_paths(self, context: dict) -> list[dict]:
        """Extract explicit file paths from stack traces in collected data.

        Scans: APM error_stack, DB error messages, log messages, Sentry culprit.
        """
        file_refs: list[dict] = []
        seen: set[str] = set()

        # Pattern: File "path/to/file.py", line 42
        py_trace_pattern = re.compile(r'File\s+"([^"]+\.py)",\s+line\s+(\d+)')
        # Pattern: path/to/file.py:42
        generic_pattern = re.compile(r"([a-zA-Z0-9_/.-]+\.(?:py|go|js|ts)):(\d+)")

        sources_to_scan = []

        # APM traces
        for trace in context.get("datadog_traces", []):
            if trace.get("error_stack"):
                sources_to_scan.append(("apm_trace", trace["error_stack"]))

        # Upstream traces
        for svc, traces in context.get("upstream_traces", {}).items():
            for trace in traces:
                if trace.get("error_stack"):
                    sources_to_scan.append((f"upstream_trace_{svc}", trace["error_stack"]))

        # DB errors
        for err in context.get("datadog_db_errors", []):
            sources_to_scan.append(("db_error", err.get("message", "")))

        # Upstream DB errors
        for _svc, errors in context.get("upstream_db_errors", {}).items():
            for err in errors:
                sources_to_scan.append((f"upstream_db_{svc}", err.get("message", "")))

        # Log messages
        for log in context.get("datadog_logs", []):
            sources_to_scan.append(("log", log.get("message", "")))

        # Sentry
        for issue in context.get("sentry_issues", []):
            culprit = issue.get("metadata", {}).get("culprit", "")
            if culprit:
                sources_to_scan.append(("sentry", culprit))

        for source_name, text in sources_to_scan:
            for pattern in [py_trace_pattern, generic_pattern]:
                for match in pattern.finditer(text):
                    file_path = match.group(1)
                    line_num = int(match.group(2))

                    # Skip site-packages and stdlib
                    if "site-packages" in file_path or "/lib/python" in file_path:
                        continue

                    key = f"{file_path}:{line_num}"
                    if key not in seen:
                        seen.add(key)
                        file_refs.append(
                            {"file": file_path, "line": line_num, "source": source_name}
                        )

        return file_refs

    def _extract_search_terms(self, context: dict) -> list[str]:
        """Extract entity names from error messages. Conservative — only high-confidence patterns.

        Only extracts from:
        - "Failed to create X object" → X
        - SQL: INSERT INTO table_name → table_name
        """
        terms: set[str] = set()

        all_messages = []

        for log in context.get("datadog_logs", []):
            all_messages.append(log.get("message", ""))
        for err in context.get("datadog_db_errors", []):
            all_messages.append(err.get("message", ""))
        for _svc, errors in context.get("upstream_db_errors", {}).items():
            for err in errors:
                all_messages.append(err.get("message", ""))

        for msg in all_messages:
            # "Failed to create X object"
            m = re.search(r"Failed to create (\w+) object", msg)
            if m:
                terms.add(m.group(1))

            # SQL: INSERT INTO table_name
            m = re.search(r"INSERT INTO (\w+)", msg)
            if m:
                terms.add(m.group(1))

        return sorted(terms)

    def _grep_repo(
        self,
        search_path: Path,
        terms: list[str],
        max_results: int = 20,
    ) -> list[dict]:
        """Grep the repo for search terms. Returns matching files with line numbers."""
        if not search_path.is_dir():
            return []

        results: list[dict] = []
        seen_files: set[str] = set()

        # Build include patterns for source files
        include_args = []
        for ext in SOURCE_EXTENSIONS:
            include_args.extend(["--include", f"*{ext}"])

        # Build exclude patterns
        exclude_args = []
        for skip_dir in SKIP_DIRS:
            exclude_args.extend(["--exclude-dir", skip_dir])

        # Prioritize action-oriented terms (duplicate_, copy_, get_all_)
        priority_terms = [
            t
            for t in terms
            if "_" in t and any(t.startswith(p) for p in ["duplicate", "copy", "create", "get_all"])
        ]
        other_terms = [t for t in terms if t not in priority_terms]

        for term in priority_terms + other_terms:
            if len(results) >= max_results:
                break
            try:
                result = subprocess.run(
                    [
                        "grep",
                        "-rn",
                        *include_args,
                        *exclude_args,
                        "-l",  # file names only first
                        term,
                        str(search_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    for file_path in result.stdout.strip().splitlines():
                        if file_path in seen_files:
                            continue
                        seen_files.add(file_path)

                        # Get the line number for context
                        line_result = subprocess.run(
                            [
                                "grep",
                                "-rn",
                                *include_args,
                                *exclude_args,
                                "-m",
                                "1",
                                term,
                                file_path,
                            ],
                            capture_output=True,
                            text=True,
                            timeout=5,
                        )
                        line_num = None
                        context_line = ""
                        if line_result.returncode == 0:
                            first_line = line_result.stdout.strip().splitlines()[0]
                            line_match = re.match(r".*?:(\d+):(.*)", first_line)
                            if line_match:
                                line_num = int(line_match.group(1))
                                context_line = line_match.group(2).strip()[:100]

                        # Make path relative to repo root
                        rel_path = file_path
                        try:
                            rel_path = str(Path(file_path).relative_to(self.workspace_root))
                            # Remove service name prefix if present
                            parts = rel_path.split("/", 1)
                            if len(parts) > 1:
                                rel_path = parts[1]
                        except ValueError:
                            pass

                        results.append(
                            {
                                "file": rel_path,
                                "line": line_num,
                                "term": term,
                                "context": context_line,
                            }
                        )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        return results

    def _read_snippet(
        self,
        repo_path: Path,
        relative_path: str,
        center_line: int | None = None,
        relevance: str = "",
        match_source: str = "",
    ) -> dict | None:
        """Read a source file snippet centered on a specific line."""
        # Try to find the file
        file_path = repo_path / relative_path
        if not file_path.exists():
            # Try without leading directories
            for parent in [repo_path, *list(repo_path.rglob("*"))]:
                if parent.is_dir():
                    candidate = parent / Path(relative_path).name
                    if candidate.exists():
                        file_path = candidate
                        break
            if not file_path.exists():
                return None

        # Skip non-source files
        if file_path.suffix not in SOURCE_EXTENSIONS:
            return None

        # Skip files in excluded directories
        rel_parts = set(file_path.relative_to(repo_path).parts)
        if rel_parts & SKIP_DIRS:
            return None

        try:
            content = file_path.read_text(errors="replace")
        except (OSError, PermissionError):
            return None

        lines = content.splitlines()
        total_lines = len(lines)

        if total_lines == 0:
            return None

        # Determine which lines to include
        if center_line and center_line > 0:
            start = max(0, center_line - CONTEXT_LINES - 1)
            end = min(total_lines, center_line + CONTEXT_LINES)
        elif total_lines <= MAX_LINES_PER_FILE:
            start = 0
            end = total_lines
        else:
            # No center line and file is too long — read first MAX_LINES_PER_FILE
            start = 0
            end = MAX_LINES_PER_FILE

        # Cap at MAX_LINES_PER_FILE
        if end - start > MAX_LINES_PER_FILE:
            end = start + MAX_LINES_PER_FILE

        snippet_lines = lines[start:end]
        snippet_content = "\n".join(snippet_lines)

        # Make relative path
        try:
            rel = str(file_path.relative_to(repo_path))
        except ValueError:
            rel = relative_path

        return {
            "file": rel,
            "lines": f"{start + 1}-{end}",
            "content": snippet_content,
            "relevance": relevance,
            "match_source": match_source,
        }
