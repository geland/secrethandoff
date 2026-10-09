# Codex command approval check

- Date: 2026-10-09
- Installed runtime: `codex-cli 0.155.1`
- Source examined: OpenAI Codex tag `rust-v0.155.1`
- Result: no verified human-only approval adapter for our local stdio plugin.
  Keep the browser gate. No command approval button was added.

## Ordinary approvals

Codex exposes server and per-tool `approval_mode` settings, including `prompt`.
These settings do not force a human decision: automatic review and
`PermissionRequest` hooks can authorize an operation without a user prompt.
Tool annotations guide host behavior; they do not replace server authorization.
An app-only approval tool would also not prove a human gesture.

The installed version's `codex-mcp/src/elicitation.rs` confirms another unsafe
shortcut: an ordinary MCP confirmation form with no schema properties can be
automatically accepted by `can_auto_accept_elicitation`. A card button or form
acceptance must not replace our browser approval grant.

## Biometric verification exists, but excludes this plugin

The generated app-server protocol includes `openai/userVerification` elicitation
and local `userVerification/status`, `enroll`, `verify`, and `delete` methods.
The proof contains a credential identifier and a P-256 signature over the exact
challenge. This is a distinct mechanism, not ordinary confirmation elicitation.

The source establishes two prerequisites for MCP access:

1. Trusted host activation enables the `openai/elicitation` extension's
   `userVerification` route (`codex-mcp/src/elicitation.rs`, `make_sender`).
2. `codex-mcp/src/user_verification_elicitation.rs`, `route`, requires
   `is_host_owned_apps`. Otherwise it returns `Cancel` without proof content.

`codex-mcp/src/catalog.rs`, `McpServerSource::is_host_owned_apps`, requires the
runtime's reserved apps server, a local execution environment, and a
`Compatibility` registration or an explicitly host-owned `Extension`.
`Plugin`, `SelectedPlugin`, and `Config` registrations do not qualify. Changing
our server's name cannot change its registration authority. Secret Handoff is
a local stdio plugin and does not meet this check.

This restriction is decisive even if the owner enrolls a biometric credential.
Do not enroll one, imitate the reserved server, or switch to hosted delivery to
work around the check. The current distribution and trust boundary remain the
ones accepted in ADR 0009 and ADR 0013.

## Local checks and limits

- Generated the installed runtime's experimental TypeScript protocol with
  `codex app-server generate-ts --experimental --out <temporary-directory>`.
- Queried only `userVerification/status` through an initialized, temporary
  stdio app-server. It reported `credentialMissing`. The credential identifier
  was not printed. No enrollment, signing, biometric prompt, agent turn,
  command execution, or approval acceptance was attempted.
- Examined the matching tagged source's route and catalog predicates above.
  This is source evidence for local-plugin exclusion, not a live desktop
  rendering or approve/deny test.
- The public MCP extension specification and SDK documentation reviewed here
  do not publish a supported third-party verification adapter.
- No binary approval behavior or global Codex approval configuration changed.

## Claude plugin refresh

Reinstalled `secrethandoff@secrethandoff` with the Claude CLI's uninstall/install
commands. Verified its cached `hooks/card.tsx`, `assets/icon.svg`, skill, and
`.mcp.json` against the local integrations source; the plugin is enabled.
Start a fresh Claude session to load it. The shared installed binary was already
updated in this chat.

Reran `scripts/check_claude_approval.py`. Its harmless control again stopped on
unavailable authentication; no probe invocation or permission denial occurred.
This is inconclusive about native approval. Reauthenticate through Claude's own
flow before the probe and interactive dummy-value acceptance check. Leave native
command approval off until those checks pass.

After the owner subsequently completed `claude auth login`, the same automated
probe passed the control and all three flagged-tool denial cases on Claude Code
2.1.284. See [the updated host check](host-command-approval-check.md) for the
results and owner-run interactive test. The owner later reported that the test
worked and supplied a screenshot verifying the native Deny / Allow once prompt.
The installed plugin still defaults to browser approval. This Claude evidence
does not change the Codex local-plugin exclusion described above.

## Revisit when

Codex exposes verification to local plugin registrations, or documents another
per-call human gate that cannot be satisfied by automatic approval, hooks, a
remembered grant, or agent-supplied input. Before an adapter is enabled, validate
the exact command, absolute folder, secret bindings, timeout, one-time grant,
decline/cancel, concurrent calls, and redacted results. Keep secret entry in the
isolated browser.

## Sources

- [Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
- [Codex approval reviewers](https://learn.chatgpt.com/docs/config-file/config-reference)
- [PermissionRequest hooks](https://learn.chatgpt.com/docs/hooks#permissionrequest)
- [MCP server authorization requirements](https://developers.openai.com/plugins/build/mcp-server)
- [OpenAI MCP extensions specification](https://github.com/openai/mcp-extensions/blob/main/docs/spec.md)
- [Versioned elicitation routing](https://github.com/openai/codex/blob/rust-v0.155.1/codex-rs/codex-mcp/src/elicitation.rs)
- [Versioned verification route](https://github.com/openai/codex/blob/rust-v0.155.1/codex-rs/codex-mcp/src/user_verification_elicitation.rs)
- [Versioned registration authority](https://github.com/openai/codex/blob/rust-v0.155.1/codex-rs/codex-mcp/src/catalog.rs)
- [Versioned proof transport validation](https://github.com/openai/codex/blob/rust-v0.155.1/codex-rs/rmcp-client/src/user_verification.rs)
