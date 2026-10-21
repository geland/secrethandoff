# ADR 0014: Owner-selected Codex approval policy

- Status: Accepted for opt-in implementation
- Supported version restriction superseded by [ADR 0015](0015-codex-desktop-approval-compatibility.md)
- Date: 2026-10-09
- Partially supersedes ADR 0009 and ADR 0013 for Codex command authorization

## Context

The owner accepts delegated consent: if they configure allow rules, hooks, or
automatic review, that decision may authorize a command without a fresh click.
Codex's native MCP approval meets this requirement. Its stronger user-verification
extension remains unavailable to local plugin registrations and is not used.

## Decision

- Browser command approval stays the default. Secret entry stays in the isolated
  browser in every mode. No secret, fill token, or pickup token enters a card.
- An owner can start the server with `SECRETHANDOFF_COMMAND_APPROVAL=codex`.
  For the installed plugin, an explicit owner-run helper edits only its cached
  stdio launch environment. Reinstallation resets the opt-in; the helper can be
  rerun. It never modifies Codex approval policies, hooks, or reviewer settings.
- Accept `codex-mcp-client` in the verified 0.155 series, starting at 0.155.1,
  only with an explicit clean absolute directory. Unknown modes, clients,
  versions, prerelease labels, and noncanonical directories use browser approval.
- Trust the owner-selected host's decision for each exact tools/call. Allow
  rules, hooks, and automatic review can authorize it. A host denial prevents
  the tool call from reaching the binary. There is no separate approval tool,
  generic form acceptance, replayable grant, or agent-supplied approval bit.
- ClientInfo is self-reported, not cryptographic evidence. A malicious client,
  compromised owner settings, or unrestricted same-user process can bypass
  this boundary. Enabling it requires explicit owner authorization; the agent
  must not choose it merely because an approval would otherwise be inconvenient.
- Codex results report `presentation: client_policy` and `approval: host_policy`.
  These mean host-policy authorization, never a claim that a human clicked.
  Complete execution results and output redaction remain unchanged.
- Claude's mandatory interactive mode from ADR 0013 remains unchanged. Cards
  remain status-only; the native approval belongs to the host.

## Validation

Test owner opt-in, client/version/directory fallback, metadata, rejection of an
agent approval argument, complete command results, and raw-transport leak tests
in browser, Claude, and Codex modes. A harmless live Codex probe must show that
an owner allow policy delivers the call and a denied policy prevents delivery.
Record the exact host version. A fresh desktop chat and owner dummy-value test
are the acceptance boundary for native prompt rendering in the desktop host.

## Consequences

Codex can authorize execution inside its own UI or through owner delegation,
without another browser approval page. A prompt may not appear under automatic
settings. The command still runs outside Codex's sandbox and holds a secret it
can send anywhere; HTTP policy does not confine it. No encryption, secret
persistence, relay protocol, or secret-entry behavior changes.

Sources checked 2026-10-09:

- [Plugin MCP policies](https://developers.openai.com/plugins/build/plugins)
- [Approval settings](https://learn.chatgpt.com/docs/config-file/config-reference)
- [Installed client identity](https://github.com/openai/codex/blob/rust-v0.155.1/codex-rs/codex-mcp/src/rmcp_client.rs)
