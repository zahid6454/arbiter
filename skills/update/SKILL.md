---
description: Update Arbiter to the latest release. Use when you see an update notification or want to check for new versions.
---

# arbiter:update

Update Arbiter to the latest release. This skill uses Bash tools only.

## Steps

### 1. Check current version

Run via Bash:
```bash
pip show arbiter-mcp 2>/dev/null | grep Version
```

If not installed via pip, check git:
```bash
git -C "$(python3 -c 'import arbiter; import os; print(os.path.dirname(os.path.dirname(os.path.dirname(arbiter.__file__))))')" describe --tags --abbrev=0 2>/dev/null
```

### 2. Check latest version

```bash
pip index versions arbiter-mcp 2>/dev/null | head -1
```

### 3. Update

If a newer version is available:

"Update available: {current} → {latest}

To update:
```
pip install --upgrade arbiter-mcp
```
Then restart Claude Code to activate the new version."

If already up to date: "Arbiter is up to date (version {version})."
