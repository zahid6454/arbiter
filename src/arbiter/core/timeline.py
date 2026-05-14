"""Timeline utilities — timestamp formatting."""

from __future__ import annotations

import re


def format_timestamp(ts: str) -> str:
    """Format a timestamp for display."""
    if not ts:
        return "?"
    m = re.search(r"(\d{2}:\d{2}:\d{2})", ts)
    if m:
        return f"{m.group(1)} UTC"
    return ts[:19]
