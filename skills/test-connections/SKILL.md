---
description: Test connections to all configured services (Datadog, Sentry, GCP, OpsGenie, GitHub). Run anytime to verify API keys and auth are working. Works even when the MCP server is disconnected.
---

# arbiter:test-connections

Test API connections to all services Arbiter integrates with. This skill uses Bash tools only — it works even when the Arbiter MCP server is not connected.

## Prerequisites

Check that `$ARBITER_HOME/credentials.env` exists. If not, tell the user to run `/setup` first.

## Steps

### 1. Load credentials

Run via Bash:
```bash
set -a
source "${ARBITER_HOME:-$HOME/arbiter}/credentials.env"
set +a
```

### 2. Test Datadog API

```bash
curl -s -o /dev/null -w "%{http_code}" \
  "https://api.${DD_SITE:-datadoghq.com}/api/v1/validate" \
  -H "DD-API-KEY: ${DD_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DD_APP_KEY}"
```

- **200**: "Datadog: Connected"
- **403**: "Datadog: Authentication failed — check DD_API_KEY and DD_APP_KEY"
- **Other/empty**: "Datadog: Connection failed (HTTP {code})"

### 3. Test Datadog Logs API

```bash
curl -s -o /dev/null -w "%{http_code}" \
  "https://api.${DD_SITE:-datadoghq.com}/api/v2/logs/events?filter[query]=service:test&filter[from]=now-1m&filter[to]=now&page[limit]=1" \
  -H "DD-API-KEY: ${DD_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DD_APP_KEY}"
```

- **200**: "Datadog Logs: Connected"
- **403**: "Datadog Logs: Permission denied — app key may lack logs_read_data scope"
- **Other**: "Datadog Logs: Failed (HTTP {code})"

### 4. Test Sentry API

Skip if `SENTRY_AUTH_TOKEN` is empty. Otherwise:

```bash
curl -s -o /dev/null -w "%{http_code}" \
  "https://sentry.io/api/0/organizations/${SENTRY_ORG}/projects/?per_page=1" \
  -H "Authorization: Bearer ${SENTRY_AUTH_TOKEN}"
```

- **200**: "Sentry: Connected"
- **401**: "Sentry: Authentication failed — check SENTRY_AUTH_TOKEN"
- **404**: "Sentry: Organization not found — check SENTRY_ORG"
- **Other**: "Sentry: Failed (HTTP {code})"

### 5. Test OpsGenie API

Skip if `OPSGENIE_API_KEY` is empty. Otherwise:

```bash
curl -s -o /dev/null -w "%{http_code}" \
  "https://api.opsgenie.com/v2/alerts?limit=1" \
  -H "Authorization: GenieKey ${OPSGENIE_API_KEY}"
```

- **200**: "OpsGenie: Connected"
- **401**: "OpsGenie: Authentication failed — check OPSGENIE_API_KEY"
- **Other**: "OpsGenie: Failed (HTTP {code})"

### 6. Test GitHub CLI

```bash
gh auth status 2>&1
```

- If exit code 0: "GitHub: Connected as {username}"
- If exit code non-zero: "GitHub: Not authenticated — run `gh auth login`"

Also test API access:

```bash
gh api user -q '.login' 2>&1
```

### 7. Test GCP / gcloud

```bash
gcloud auth print-access-token 2>/dev/null
```

- If exit code 0: "GCP: Authenticated"
- If exit code non-zero: "GCP: Not authenticated — run `gcloud auth login`"

If authenticated, also check project access:

```bash
gcloud config get-value project 2>/dev/null
```

Report the active project if set.

### 8. Summary

Print a table summarizing all connection test results:

```
Service          Status
─────────────────────────────
Datadog API      Connected
Datadog Logs     Connected
Sentry           Connected
OpsGenie         Skipped (not configured)
GitHub           Connected (username)
GCP              Connected (project-id)
```

**If all required services are connected:**
"All connections verified. Arbiter is ready for investigations."

**If any required services failed:**
List the failures with fix instructions. Required services are Datadog API and Datadog Logs. Others are recommended or optional.
