# ADR 0015: Exact desktop Codex approval compatibility

- Status: Accepted for opt-in implementation
- Date: 2026-10-15
- Supersedes only the supported Codex version restriction in ADR 0014

## Context

The desktop app bundles Codex `0.162.0-alpha.17.2`; the separate terminal CLI
is `0.155.1`. The installed launch environment correctly selects Codex mode,
but ADR 0014's stable 0.155 version check sends the desktop client to browser
command approval. A newer version number alone does not establish compatibility.

## Decision

Accept the exact `codex-mcp-client` version `0.162.0-alpha.17.2` in addition
to the stable 0.155 series starting at 0.155.1. Keep every other ADR 0014
condition: explicit owner startup opt-in, a clean absolute directory, host
authorization of each exact tools/call, and browser fallback for other clients,
versions, or modes. Do not accept neighboring prereleases, a whole new minor
series, or arbitrary version suffixes. Owner approval settings remain unchanged.

Before local installation, validate real-host allow/deny delivery with the
desktop executable and a harmless mock that holds no credential and executes
no command. Test overrides belong only to the probe's child invocation. Never
use a probe override to authorize the human's dummy-token command. Run the
transport regression and leak suites for the exact desktop identity, then
rerun the owner dummy-token test under existing settings in a fresh MCP process.

## Consequences

The verified desktop build can report `client_policy` and `host_policy`.
These describe owner-policy authorization, including delegated automatic
approval; they do not claim a human clicked. Secret entry stays in the isolated
browser. Commands remain outside the Codex sandbox and can send a credential
they hold anywhere. No tool schema, secret lifecycle, or cryptographic format
changes. A future desktop update requires another compatibility check.

Validation outcomes are recorded in
[the Codex approval check](../plans/codex-command-approval-check.md).
