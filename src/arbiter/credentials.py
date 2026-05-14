"""Credential loading — shared across all collectors.

Loads API keys from env files into ``os.environ``.  Shell environment
variables always take precedence — files only fill gaps.
"""

from __future__ import annotations

import os
from pathlib import Path

_loaded = False

ARBITER_HOME_DEFAULT = Path.home() / "arbiter"


def _parse_env_file(path: Path) -> None:
    """Parse key=value pairs from *path*. Only sets vars not already in ``os.environ``."""
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key and key not in os.environ:
            os.environ[key] = value


def load_credentials() -> None:
    """Load credentials from available sources.

    Resolution order (shell env always wins — files only fill gaps):

    1. Shell environment — already set, never overwritten.
    2. ``$ARBITER_HOME/credentials.env`` — default ``~/arbiter/credentials.env``.
    3. Repo ``.env`` — walk up from this file (local dev clones).
    """
    global _loaded
    if _loaded:
        return
    _loaded = True

    arbiter_home = Path(os.environ.get("ARBITER_HOME", str(ARBITER_HOME_DEFAULT))).expanduser()
    config_env = arbiter_home / "credentials.env"
    if config_env.exists():
        _parse_env_file(config_env)

    current = Path(__file__).resolve().parent
    for _ in range(5):
        env_file = current / ".env"
        if env_file.exists():
            _parse_env_file(env_file)
            return
        current = current.parent
