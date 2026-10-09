# ADR 0013: Owner-selected host command approval

- Status: Accepted for opt-in implementation; native prompt verified in owner test
- Date: 2026-10-09
- Extends ADR 0009 for command approval only

## Context

The user wants command approval visible in the assistant UI while only the human
can authorize execution. The approval contains command metadata, never a secret
value. Generic MCP elicitation is not a reliable human gate: Claude Code's
Elicitation and ElicitationResult hooks can synthesize or replace acceptance.
MCP Apps tool visibility also does not establish that a human clicked a button.

Claude Code documents a stricter tool annotation,
`anthropic/requiresUserInteraction: true`. It forces a permission prompt for
every call despite allow rules, automatic permission modes, and PreToolUse allow
hooks. SDK canUseTool callbacks remain an exception and are not accepted hosts.

## Decision

- Keep isolated browser secret entry and default browser command approval.
- The owner can set `SECRETHANDOFF_COMMAND_APPROVAL=claude-code` when starting
  the MCP server. This is a trust decision about the interactive client, never a
  tool argument or a setting the agent may enable. Unknown modes use the browser.
- In this mode, the command tool declares the mandatory human-interaction
  annotation. Bypass browser approval only for `claude-code` clientInfo in the
  2.1 series at version 2.1.284 or later, with an explicit clean absolute `dir`.
  Other hosts, versions, or directory representations retain the browser gate.
- Trust the selected host's permission boundary. ClientInfo is self-reported,
  not a signed proof of a user gesture. A fake or compromised host, SDK callback,
  or unrestricted same-user process is outside this guarantee. Never infer
  permission from form support, a card, an agent Boolean, or a generic allow rule.
- The host gates each tools/call with its exact arguments. There is no separate
  approval RPC, replayable grant, form response, or remembered client approval.
  The assistant may observe command metadata and outcome.
- Browser waiters atomically consume their particular page's grant. Concurrent
  waiters cannot reuse it or take a replacement grant. Include execution timeout
  in the browser approval key so changed limits create a separate request.
- Cards remain status-only and use surface-neutral wording while a command is
  running. Completed results report redacted presentation metadata.

## Validation and acceptance

Test metadata, owner opt-in, host/version/directory fallback, rejection of an
agent-supplied approval argument, redaction on client execution, and single-use
browser grants. The integrations probe checks the installed Claude CLI with a
harmless server, no built-in tools, no other MCP servers, and no actual command
execution: an unflagged control must run; flagged calls must be denied under an
allow rule and a PreToolUse allow hook in dontAsk mode, then a PermissionRequest
allow hook in default mode without a human permission handler.

This automated check cannot prove interactive prompt rendering, approve/deny,
or exclusion of agent UI automation. These must be verified with a dummy value
in the exact host before opting in. Codex and generic MCP Apps have no approved
adapter here. No cached plugin or user configuration is changed by this work.

Acceptance update, 2026-10-09: the automated live-host probe passed its control
and all three flagged-tool denial cases. The owner subsequently reported that
the interactive dummy test worked and supplied a screenshot of the native
**Deny / Allow once** prompt, with command, environment binding, and directory
visible. This verifies prompt rendering in that tested host; the image does
not independently establish execution outcomes or exclusion of arbitrary UI
automation. See [the host check](../plans/host-command-approval-check.md) for
the evidence and limits. The decision and owner-selected trust boundary remain
unchanged.

## Consequences

Interactive Claude Code can use its own permission prompt rather than opening a
second browser page, once the owner accepts that host boundary. Secret fill
stays outside the client. No cryptographic format or relay behavior changes.
An approved command still holds the credential and can send it outside its HTTP
policy; this feature changes where approval happens, not process confinement.

Sources checked 2026-10-09:

- [Mandatory tool approval](https://code.claude.com/docs/en/mcp#require-approval-for-a-specific-tool)
- [Hooks cannot auto-allow flagged tools](https://code.claude.com/docs/en/hooks#tools-that-require-user-interaction)
- [Forms can be answered and modified by hooks](https://code.claude.com/docs/en/hooks#elicitation)
