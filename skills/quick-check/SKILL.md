---
description: Quick health check for a service. Use when you want to see if a service has errors right now without a full investigation.
---

# arbiter:quick-check

Run a quick error scan for a service and summarize the current state.

## Prerequisites

Before starting, verify Arbiter is connected by checking if the `list_available_services` MCP tool is available. If the MCP server is not connected, tell the user:

- If they have already run /setup and configured credentials: "Restart Claude Code to connect the MCP server."
- If they have not run /setup: "Arbiter is not configured. Run /setup to set up your credentials first."

Do not attempt the health check without a connected MCP server.

## Input

Parse `$ARGUMENTS` for:
- **Service name** (e.g., "catalog", "platform-core", "auth-service")
- **Time range** (optional, defaults to "1h")

## Steps

1. Call `fetch_datadog_error_summary` for the service with the parsed time range (default "1h") to get error pattern counts.
2. Call `fetch_datadog_traces` with `status_code="500"`, `limit=5`, and the same time range to see recent error details.
3. Summarize in 3-5 sentences:
   - How many errors, what patterns
   - Whether it looks like an active incident or background noise
   - Whether immediate action is needed

Do not run a full investigation. If the user wants deeper analysis, suggest `/arbiter:investigate`.
