"""Manual collector — parses pasted conversations and raw logs."""

from __future__ import annotations

import json
import re

from arbiter.collectors.base import Collector
from arbiter.core.models import EventSource, LogEntry, LogLevel, TimelineEvent

# ---- Chat thread patterns ----

SLACK_MSG_PATTERN = re.compile(
    r"^(?P<author>[A-Za-z][A-Za-z0-9_.\- ]{1,40}?)\s+"
    r"(?P<time>\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)?)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

TEAMS_MSG_PATTERN = re.compile(
    r"^\[?(?P<time>\d{1,2}:\d{2}(?::\d{2})?)\]?\s*[-\u2013]?\s*"
    r"(?P<author>[A-Za-z][A-Za-z0-9_.\- ]{1,40}?)\s*[:]\s*$",
    re.MULTILINE,
)

GENERIC_MSG_PATTERN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}\s+)?(?P<time>\d{1,2}:\d{2}(?::\d{2})?(?:\s*(?:AM|PM))?)\s+"
    r"[<\[]?(?P<author>[A-Za-z][A-Za-z0-9_.\-]{0,40})[>\]]?\s*:?\s+"
    r"(?P<message>.+)$",
    re.IGNORECASE | re.MULTILINE,
)

ACTION_KEYWORDS = [
    ("all clear", "resolution"),
    ("all-clear", "resolution"),
    ("resolved", "resolution"),
    ("incident over", "resolution"),
    ("root cause", "root_cause"),
    ("rca", "root_cause"),
    ("found it", "root_cause"),
    ("the issue is", "root_cause"),
    ("caused by", "root_cause"),
    ("revert", "revert"),
    ("rollback", "rollback"),
    ("rolling back", "rollback"),
    ("rolled back", "rollback"),
    ("restart", "restart"),
    ("scale", "scaling"),
    ("hotfix", "fix"),
    ("fix", "fix"),
    ("patch", "fix"),
    ("deploy", "deployment"),
    ("alert", "alert"),
    ("page", "page"),
    ("monitoring", "monitoring"),
    ("investigating", "investigation"),
    ("looking into", "investigation"),
    ("checking", "investigation"),
]

# ---- Log parsing patterns ----

TIMESTAMP_PATTERNS = [
    re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
    re.compile(r"(?P<ts>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})"),
    re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})"),
    re.compile(r"(?P<ts>\d{2}:\d{2}:\d{2}(?:\.\d+)?)"),
]

LOG_LEVEL_PATTERN = re.compile(
    r"\b(?P<level>CRITICAL|FATAL|ERROR|WARN(?:ING)?|INFO|DEBUG)\b", re.IGNORECASE
)

ERROR_PATTERNS = [
    re.compile(r"(?P<err>(?:Error|Exception|Traceback|FATAL|CRITICAL)[^\n]{0,200})", re.IGNORECASE),
    re.compile(r"(?P<err>HTTP\s+[45]\d{2}[^\n]{0,200})"),
    re.compile(r"(?P<err>status[_\s]?code[=:\s]+[45]\d{2}[^\n]{0,200})", re.IGNORECASE),
    re.compile(r"(?P<err>connection\s+(?:refused|timeout|reset)[^\n]{0,200})", re.IGNORECASE),
    re.compile(r"(?P<err>OOM|out\s+of\s+memory[^\n]{0,200})", re.IGNORECASE),
    re.compile(r"(?P<err>deadline\s+exceeded[^\n]{0,200})", re.IGNORECASE),
]


def _classify_message(message: str) -> str | None:
    lower = message.lower()
    for keyword, event_type in ACTION_KEYWORDS:
        if keyword in lower:
            return event_type
    return None


_ALERT_PREFIX_RE = re.compile(
    r"^\s*(?:\[(?:P[1-4]|FIRING|RESOLVED|OK|WARN(?:ING)?|CRITICAL|ALERT)\]\s*)+",
    re.IGNORECASE,
)
_ALERT_LABEL_RE = re.compile(
    r"^\s*(?:Alert|OpsGenie|PagerDuty|Datadog|Sentry)\s*:\s*",
    re.IGNORECASE,
)
_URL_ONLY_RE = re.compile(r"^\s*https?://\S+\s*$", re.IGNORECASE)


def derive_title_from_text(
    alert_text: str = "",
    conversation: str = "",
    service_name: str = "",
) -> str:
    """Derive a short incident title from alert text or conversation.

    Returns empty string if no meaningful title can be derived.
    """
    title = _title_from_alert(alert_text) or _title_from_conversation(conversation)
    if not title:
        return ""

    if service_name and not title.lower().startswith(service_name.lower()):
        title = f"{service_name} -- {title}"

    return title


def _title_from_alert(alert_text: str) -> str:
    if not alert_text or not alert_text.strip():
        return ""
    for line in alert_text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        if _URL_ONLY_RE.match(line):
            continue
        line = _ALERT_PREFIX_RE.sub("", line)
        while _ALERT_LABEL_RE.match(line):
            line = _ALERT_LABEL_RE.sub("", line).strip()
        if line:
            return _truncate_at_word_boundary(line, 80)
    return ""


def _title_from_conversation(conversation: str) -> str:
    if not conversation or not conversation.strip():
        return ""
    for line in conversation.strip().splitlines():
        line = line.strip()
        if not line or _URL_ONLY_RE.match(line):
            continue
        event_type = _classify_message(line)
        if event_type:
            return _truncate_at_word_boundary(line, 80)
    for line in conversation.strip().splitlines():
        line = line.strip()
        if line and not _URL_ONLY_RE.match(line):
            return _truncate_at_word_boundary(line, 80)
    return ""


def _truncate_at_word_boundary(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    truncated = text[:max_len]
    last_space = truncated.rfind(" ")
    if last_space > max_len // 2:
        truncated = truncated[:last_space]
    return truncated.rstrip()


def _parse_log_level(raw: str) -> LogLevel:
    upper = raw.upper()
    if upper in ("CRITICAL", "FATAL"):
        return LogLevel.CRITICAL
    if upper in ("ERROR", "ERR"):
        return LogLevel.ERROR
    if upper in ("WARN", "WARNING"):
        return LogLevel.WARNING
    if upper == "INFO":
        return LogLevel.INFO
    return LogLevel.DEBUG


class ManualCollector(Collector):
    """Collector for manually pasted content — conversations and raw logs."""

    @property
    def source(self) -> EventSource:
        return EventSource.MANUAL

    def collect_logs(self, service: str = "", **kwargs) -> list[LogEntry]:
        return []

    def collect_events(self, service: str = "", **kwargs) -> list[TimelineEvent]:
        return []

    # ---- Thread parsing ----

    def parse_thread(self, raw_thread: str) -> list[dict]:
        """Parse a Slack/Teams incident thread into structured entries."""
        if not raw_thread or not raw_thread.strip():
            return []

        entries = self._parse_structured_messages(raw_thread)
        if entries:
            return entries
        return self._parse_freeform_thread(raw_thread)

    def _parse_structured_messages(self, raw: str) -> list[dict]:
        entries = []
        for m in GENERIC_MSG_PATTERN.finditer(raw):
            date_part = (m.group("date") or "").strip()
            time_part = m.group("time").strip()
            timestamp = f"{date_part} {time_part}".strip() if date_part else time_part
            message = m.group("message").strip()
            entries.append(
                {
                    "timestamp": timestamp,
                    "author": m.group("author").strip(),
                    "message": message,
                    "event_type": _classify_message(message),
                    "source": "thread",
                }
            )
        return entries

    def _parse_freeform_thread(self, raw: str) -> list[dict]:
        entries = []
        lines = raw.strip().splitlines()
        current_author = None
        current_time = None

        for line in lines:
            line = line.strip()
            if not line:
                current_author = None
                current_time = None
                continue

            slack_match = SLACK_MSG_PATTERN.match(line)
            if slack_match:
                current_author = slack_match.group("author").strip()
                current_time = slack_match.group("time").strip()
                continue

            teams_match = TEAMS_MSG_PATTERN.match(line)
            if teams_match:
                current_author = teams_match.group("author").strip()
                current_time = teams_match.group("time").strip()
                continue

            if line and (current_author or _classify_message(line)):
                entries.append(
                    {
                        "timestamp": current_time,
                        "author": current_author,
                        "message": line[:500],
                        "event_type": _classify_message(line),
                        "source": "thread",
                    }
                )
        return entries

    # ---- Log parsing ----

    def parse_logs(self, raw_logs: str) -> list[LogEntry]:
        """Parse raw log text into structured LogEntry objects."""
        entries = []
        for line in raw_logs.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            # Try JSON
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    entries.append(self._parse_json_log(data))
                    continue
            except (json.JSONDecodeError, ValueError):
                pass

            # Text parsing
            entry = self._parse_text_log(line)
            if entry:
                entries.append(entry)

        return entries

    def _parse_json_log(self, data: dict) -> LogEntry:
        ts = (
            data.get("timestamp")
            or data.get("@timestamp")
            or data.get("time")
            or data.get("ts")
            or ""
        )
        level = data.get("level") or data.get("severity") or data.get("levelname") or ""
        service = data.get("service") or data.get("dd.service") or data.get("app") or ""
        message = data.get("message") or data.get("msg") or data.get("text") or ""
        error = data.get("error") or data.get("exception") or ""
        if error and error != message:
            message = f"{message} \u2014 {error}" if message else str(error)

        return LogEntry(
            timestamp=str(ts),
            level=_parse_log_level(str(level)) if level else LogLevel.ERROR,
            message=str(message),
            service=str(service),
            source=EventSource.MANUAL,
        )

    def _parse_text_log(self, line: str) -> LogEntry | None:
        ts = None
        for p in TIMESTAMP_PATTERNS:
            m = p.search(line)
            if m:
                ts = m.group("ts")
                break

        level_match = LOG_LEVEL_PATTERN.search(line)
        level = level_match.group("level").upper() if level_match else None

        error_msg = None
        for p in ERROR_PATTERNS:
            m = p.search(line)
            if m:
                error_msg = m.group("err").strip()
                break

        if ts or level or error_msg:
            return LogEntry(
                timestamp=ts or "",
                level=_parse_log_level(level) if level else LogLevel.ERROR,
                message=error_msg or line[:300],
                service="",
                source=EventSource.MANUAL,
            )
        return None
