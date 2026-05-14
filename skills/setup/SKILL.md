---
description: Set up Arbiter for first use or check your existing configuration. Creates the ~/arbiter/ directory, credentials template, and validates API keys, GitHub CLI, and gcloud auth. Works even when the MCP server is disconnected.
---

# arbiter:setup

Set up or validate Arbiter configuration. This skill uses Bash, Read, and Write tools only — it works even when the Arbiter MCP server is not connected.

## Steps

### 1. Resolve ARBITER_HOME

Run `printenv ARBITER_HOME` via Bash. If set, use that path. Otherwise default to `~/arbiter/`.

Use this resolved path for all subsequent steps. Refer to it as `ARBITER_HOME` below.

### 2. Check/create directory structure

Check if `$ARBITER_HOME` exists. Create it and subdirectories if missing:

```
$ARBITER_HOME/
├── incidents/
└── output/
    ├── collected-data/
    └── reports/
```

Use `mkdir -p` to create all directories. Tell the user what was created.

### 3. Check/create credentials.env

Check if `$ARBITER_HOME/credentials.env` exists.

**If missing**, create it with this exact content and set `chmod 600`:

```
# Arbiter Credentials
# Fill in your API keys below, then restart Claude Code.
#
# DATADOG:
#   DD_API_KEY:  Organization Settings > API Keys
#   DD_APP_KEY:  Organization Settings > Application Keys (create a personal key)
#
# OTHER KEYS:
#   Sentry:   Settings > Account > API > Auth Tokens
#   OpsGenie: Request API key from your OpsGenie admin (optional)

# Required
DD_API_KEY=
DD_APP_KEY=
DD_SITE=datadoghq.com

# Recommended
SENTRY_AUTH_TOKEN=
SENTRY_ORG=

# GCP Cloud Logging — run `gcloud auth login` to authenticate
GCLOUD_CONFIGURATION=default

# Optional
OPSGENIE_API_KEY=
```

Tell the user: "Created `$ARBITER_HOME/credentials.env`. Open this file and fill in your API keys."

Ask the user to confirm when they've filled in their credentials before proceeding to validation.

**If the file already exists**, tell the user it exists and proceed to validation.

### 4. Validate credentials

Read `$ARBITER_HOME/credentials.env` and check each key:

**Required** (Arbiter won't connect without these):
- `DD_API_KEY` — must be non-empty
- `DD_APP_KEY` — must be non-empty

**Pre-filled** (should be present):
- `DD_SITE` — should be set

**Recommended** (some features won't work without these):
- `SENTRY_AUTH_TOKEN`

**Optional:**
- `OPSGENIE_API_KEY`

Report a summary like: "2/2 required keys configured. 1/1 recommended. 0/1 optional."

If any values contain quote characters (`"` or `'`), warn the user: "Remove quotes from credential values — they will cause auth failures."

### 5. Check GitHub CLI auth

Run `gh auth status` via Bash.

- If authenticated: report the username.
- If not authenticated or `gh` not installed: tell the user to run `gh auth login`.

### 6. Check gcloud auth

Run `gcloud auth print-access-token 2>/dev/null` via Bash.

- If it succeeds (exit code 0): report "gcloud authenticated."
- If it fails: tell the user to run `gcloud auth login`.

### 7. Summary

Report the overall status:

- What directories were created (or already existed)
- Credential status (required/recommended/optional counts)
- GitHub CLI status
- gcloud status

**If everything is configured:**
"Arbiter is ready. Restart Claude Code to connect the MCP server, then run /test-connections to verify all API connections are working."

**If issues remain:**
List what needs fixing. The user can run `/setup` again after fixing.
