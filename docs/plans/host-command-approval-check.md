# Host command approval check

- Date: 2026-10-09
- Implementation decision: [ADR 0013](../adr/0013-host-command-approval.md)
- Installed Claude CLI: 2.1.284
- Status: local checks and automated live-host probe passed; native prompt verified; owner reports interactive test worked

## Available boundary

Claude Code's documented `anthropic/requiresUserInteraction` tool metadata
forces a per-call human permission prompt even when an allow rule or a
PreToolUse hook tries to allow it. Ordinary form elicitation does not supply
this boundary: hooks can answer a form or change a user's response. MCP App
visibility likewise does not attest a human gesture. The cards remain status
displays with no secret input or approval endpoint.

Sources checked on the date above:

- [Mandatory tool approval](https://code.claude.com/docs/en/mcp#require-approval-for-a-specific-tool)
- [PreToolUse limitation](https://code.claude.com/docs/en/hooks#tools-that-require-user-interaction)
- [Elicitation hooks](https://code.claude.com/docs/en/hooks#elicitation)

## Local evidence

The binary tests cover owner-selected mode, mandatory metadata, host and version
fallback, an explicit absolute working directory, rejection of agent-supplied
approval arguments, single-use browser grants, and redacted output. The
real-process leak suite exercises both browser and client execution paths and
checks tool results, raw stdout, stderr, and encoded forms of its known dummy
value. These synthetic clients intentionally do not establish real human
approval; the owner-selected MCP host is the new trusted boundary.

## Live probe

`python3 scripts/check_claude_approval.py` in the integrations repository uses
only a harmless test server, with no built-in tools or other MCP servers. It
checks an unflagged control, then a flagged call under an allow rule, then under
a PreToolUse allow hook and a PermissionRequest allow hook. No secret is filled
and no command is executed. A
flagged call must be denied, with a recorded permission denial rather than
merely no tool call.

The initial run stopped at the control: the installed CLI reported that its
OAuth session had expired and could not be refreshed. This is **not** evidence
that the approval flag passed or failed. No browser mode setting, installed
plugin, global configuration, or sign-in state was changed.

The probe was repeated after the reported Claude panel test on 2026-10-09.
Its control still returned `auth_unavailable: true`, with no call or permission
denial. Native approval remained unverified and disabled at that point.

After the owner completed `claude auth login`, the probe passed all four cases
on the same installed Claude Code 2.1.284 build:

| Case | Tool called | Permission denial recorded | Result |
|---|---|---|---|
| Unflagged control | Yes | No | Passed |
| Flagged tool with allow rule | No | Yes | Passed |
| Flagged tool with PreToolUse allow hook | No | Yes | Passed |
| Flagged tool with PermissionRequest allow hook | No | Yes | Passed |

Each CLI run exited successfully with authentication available. The probe used
no secret, executed no command, and changed no installed plugin or global
approval setting. This verifies those automatic bypass attempts, not native
prompt rendering or a human gesture in the desktop panel.

## Owner-provided interactive evidence

On 2026-10-09 the owner reported that the interactive test worked and provided
a screenshot showing the native Claude permission prompt for `run_with_secret`.
The prompt displays the complete Python argument vector, the dummy secret's
environment binding, and the explicit absolute working directory. It offers
**Deny** and **Allow once** buttons. The Secret Handoff status band appears
separately below it. No secret value is visible in the prompt.

This verifies native prompt rendering in the owner's tested host, alongside
the owner's report of a working flow. The screenshot itself does not contain
a denied-call trace or the approved command's structured result, so those
outcomes are not independently established by the image. No screenshot or
unrelated workspace metadata was copied into the repository.

## Command result follow-up

The Claude test exposed incomplete structured command metadata: it carried only
`command_finished` and the presentation, while exit code and output existed only
in compatibility text. Results now include approval, execution, exit code,
redacted stdout/stderr, truncation, timeout, and cancellation fields. Denial,
pending approval, expiry, and startup failure cannot claim completed execution.
Both status cards interpret these fields when compatibility text is absent.
The per-command redactor snapshots the exact environment values before they can
be replaced or forgotten, and retains those patterns until results are redacted.

Regression tests exercise both approval paths over MCP, successful and nonzero
exits, timeout, truncation, startup failure, pending/denied approvals, and output
after erasure of a dummy value containing JSON/HTML-sensitive characters. The
full Go race/leak suite and both cards' state tests pass. These checks do not
establish native prompt rendering or a human click in Claude.

## Acceptance scope

The automated negative probe passes, native prompt rendering is verified, and
the owner reports that the interactive test worked. Approval still relies on
the owner-selected interactive host's permission boundary, as described in
ADR 0013. This evidence does not certify other host versions, custom Agent SDK
permission callbacks, or resistance to arbitrary same-user UI automation.
The installed plugin defaults remain in browser mode; owner-run sessions can
select native approval. Codex and generic MCP Apps retain the browser path.

## Owner-run interactive test

The owner starts one fresh Claude Code session with native approval enabled:

```bash
SECRETHANDOFF_COMMAND_APPROVAL=claude-code claude
```

This environment variable applies to that launched process and its MCP child.
An additional harmless live MCP probe confirmed that Claude Code 2.1.284
forwards a custom launch environment variable to its stdio MCP child. That
probe used a test-only marker, with no secret or command execution.
It does not change an already running desktop session. A desktop session needs
the same owner-selected environment in its MCP server launch configuration.
There is no added approval button in the plugin's status card: the clickable
approval belongs to the host's permission prompt.

In the new session, use this dummy-only test prompt, replacing the example
working directory with an existing absolute path:

```text
Test Secret Handoff native command approval. Change no files and do not run init.
Request TEST_TOKEN with reason "Native approval test. Enter any dummy value."
and policy {"hosts":["api.github.com"],"methods":["GET"]}. If pending, use
wait_for_secret for TEST_TOKEN until ready.

Call run_with_secret with command ["python3","-c","import os; assert os.environ.get('TEST_TOKEN'); print('Dummy check passed')"],
secrets ["TEST_TOKEN:TEST_TOKEN"], and explicit absolute dir
"/absolute/path/to/project".
I will deny the first prompt and approve the second. After the first denial,
retry exactly once. Never approve or interact with the approval UI yourself.
Report which approval surface appeared and the approved result's presentation,
executed, exit_code, stdout, and stderr. Forget TEST_TOKEN when the test ends.
Never ask me to paste the value in chat or display it.
```

Denial in native mode happens in the host before the binary receives the call;
it is a host permission denial, not the binary's browser `command_denied` result.
The approved result should report `client_permission`, `executed: true`, exit
code 0, stdout `Dummy check passed`, and empty stderr. Secret entry still opens
in the isolated browser. This prompt authorizes only a dummy test and a single
retry after denial, not agent interaction with the human approval controls.
