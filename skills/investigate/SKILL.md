---
description: Investigate a production incident using Arbiter. Use when an alert fires, errors spike, someone reports a service issue, or you need root cause analysis. Collects data from Datadog, Sentry, GCP, GitHub, and OpsGenie, then performs hypothesis-driven investigation.
---

# arbiter:investigate

Run a full incident investigation using the Arbiter MCP tools.

## Prerequisites

Before starting, verify Arbiter is connected by checking if the `list_available_services` MCP tool is available. If the MCP server is not connected, tell the user:

- If they have already run /setup and configured credentials: "Restart Claude Code to connect the MCP server. In VS Code, use Command Palette (Cmd+Shift+P) > 'Developer: Reload Window'."
- If they have not run /setup: "Arbiter is not configured. Run /setup to set up your credentials first."

Do not attempt to investigate without a connected MCP server.

## Input

Parse `$ARGUMENTS` for:
- **Service name** (e.g., "catalog", "platform-core", "auth-service")
- **Time window** (e.g., "2h", "from 2am to 4am UTC today")
- **Symptoms** (e.g., "500 errors", "can't create items", alert text)

If the service name or time window is ambiguous, ask one clarifying question before proceeding.

## Investigation Protocol

Read the complete investigation protocol by calling ReadMcpResourceTool with server "arbiter" and uri "arbiter://claude-md". This returns CLAUDE.md which contains the full methodology.

Follow the **Investigation Protocol** section exactly as documented. It covers:
1. ORIENT — Preflight, phased signal collection, expectation-driven input awareness, narration contract
2. HYPOTHESIZE — Form explanation from expectation vs reality gap, consult enrichment providers if configured
3. TEST — Verify predictions with specific tools
4. CHALLENGE — Full challenge checklist including configured inputs, premature closure
5. ITERATE — Account for all evidence
6. REMEDIATE — Generate fix specifications, optionally create Jira tickets for code fixes
7. REPORT — validate_investigation, confidence assessment, investigation effort, causal chain

The resource also contains:
- **Report Format** — exact report structure with every section
- **Narration Contract** — templates for narrating findings between tool calls
- **Token Efficiency** — guidance on summary vs full detail levels
- **Common Pitfalls** — anti-patterns to avoid during investigation
- **Known Limitations** — data retention windows and API constraints
- **MCP Tools Reference** — all tools with when-to-use guidance

Follow the protocol and report format exactly. Do not abbreviate or skip sections.

If the resource call fails (MCP server disconnected, resource not found), tell the user: "The investigation protocol could not be loaded from the Arbiter MCP resource. The investigation cannot proceed without it."
