# secrethandoff

`secrethandoff` gives secrets to AI agents without the value entering the chat, the transcript, or the model context. It runs as a local stdio MCP (Model Context Protocol) server. When an agent needs a credential, the binary opens a fill page in your own browser. The agent then uses the secret by name and never receives the value.

Status: phases 0 to 3 of the plan are built. No version is released yet.

- Decision records: [ADR 0009](../../docs/adr/0009-local-secret-requests-for-agents.md) (local mode), [ADR 0010](../../docs/adr/0010-relay-for-phone-fill.md) (phone fill), [ADR 0011](../../docs/adr/0011-remote-mode-and-gateway.md) (remote mode)
- Plan: [`docs/plans/sealed-requests-plan.md`](../../docs/plans/sealed-requests-plan.md)
- Threat model: [`docs/security/sealed-request-threat-model.md`](../../docs/security/sealed-request-threat-model.md)
- Invariants: the local and relay requirements in [`CONTRIBUTING.md`](../../CONTRIBUTING.md)

## Commands

| Command | Use |
|---|---|
| `secrethandoff mcp` | The stdio MCP server. Agent clients start it. |
| `secrethandoff doctor [--json]` | Check that local mode can work on this computer. Also notes whether Claude Code and Codex have the plugin, and whether the current folder has the rules block. |
| `secrethandoff setup [--init \| --no-init] [--bin-dir DIR] [--marketplace SOURCE] [--dry-run]` | Install this binary in the user binary directory, configure PATH, connect available Claude Code and Codex CLIs, offer project guidance, and run verification. Safe to rerun. |
| `secrethandoff init` | Add the secrets rules block to the project's agent rule files. |
| `secrethandoff hook user-prompt\|bash` | Claude Code hooks that stop a pasted or literal secret. |
| `secrethandoff fill <link>` | Fill a phone or remote request from a terminal. |
| `secrethandoff version` | Print the version. |

## One-command setup

After downloading and extracting the binary for your OS and processor, run it
from a terminal. Go is not required:

```sh
./secrethandoff setup
```

On Windows PowerShell, use `.\secrethandoff.exe setup`. This installs the running
binary into `~/.local/bin` on macOS/Linux or
`%LOCALAPPDATA%\Programs\secrethandoff` on Windows. `--bin-dir` (or
`SECRETHANDOFF_BIN_DIR`) overrides the destination. No administrator privileges
or background service are needed.

Setup adds a marked PATH block to the current shell's startup files (sh, bash,
zsh, or fish), or updates Windows user PATH. Existing content is preserved;
rerunning replaces only its own block. Symlinked dotfiles retain their symlinks.
Restart terminals and agent applications afterward. On macOS/Linux, launch the
agent CLI from a new terminal; an already-running desktop app may retain its old
PATH. A GUI-only client without its CLI requires manual MCP configuration.

When run interactively, setup offers to add guidance to the current project's
agent rule files. The default answer is no. Use `--init` to explicitly include
this step in automation, or `--no-init` to skip the prompt. Noninteractive input
never counts as consent. `--dry-run` prints planned changes without installing,
editing profiles, invoking clients, or starting the local checks.

The shell and PowerShell download scripts verify the release checksum and hand
off to this same Go setup flow. They skip the project prompt. Setting
`SECRETHANDOFF_NO_SETUP=1` invokes `setup --binary-only`, which installs only the
binary and PATH. The native equivalent is `secrethandoff setup --binary-only`.

Full setup verifies enabled plugin registration and runs the local doctor checks.
Missing clients, disabled/missing plugins, or failed local checks return a
nonzero exit code, even if the binary was installed successfully. Repeat setup
keeps an already-enabled plugin; it is not a plugin updater. No secret is requested
or sent during verification. Successful checks do not prove a complete agent
credential workflow or a signed public release; fresh installs on each supported
OS and live client acceptance remain release gates.

## MCP tools

| Tool | Use |
|---|---|
| `request_secret` | Open a fill page for a named secret with a use policy. Without a browser, use remote mode. |
| `wait_for_secret` | Wait for an existing request by name, without opening another page or changing its policy. |
| `list_secrets` | List secret names and states. Never values. |
| `forget_secret` | Remove a secret from memory and cancel its open request. |
| `http_request` | Send an HTTPS request with `{{secret:NAME}}` references, only to hosts in the policy. |
| `run_with_secret` | Run an argument vector with the secret in one environment variable, after the human approves the command. |
| `proxy_settings` | Get the settings that send one command's HTTPS requests through the local secrets proxy, for tools that cannot use `http_request`. |
| `confirm_secret` | Remote mode only: make a filled secret usable after the human reads its confirmation code. |

Lifecycle tools preserve human-readable text and return value-free MCP `structuredContent`. Request and wait results include `status` (`ready`, `pending`, `declined`, `cancelled`, `expired`, `confirmation_required`, `missing`, or `error`) and `name`. `presentation` reports `browser_page` for the local entry page, `client_prompt` for client-managed remote URL elicitation, or `remote_link` for the remote link fallback. It does not claim that the host rendered a chat card. Remote URL elicitation can first return an input-required result without content, as required by the host protocol; lifecycle metadata follows when the host resumes the call. A pending result includes `next_tool: wait_for_secret` and `next_arguments: {name}`. Calls wait up to the configured timeout; repeat the wait call while pending. Older repeated `request_secret` calls still rejoin the same request.

`list_secrets` returns `status: listed`, ready metadata, and pending request states, including remote confirmation. `forget_secret` returns `forgotten` or `missing`, closes pending local fill pages, and erases unconfirmed remote values. Relay cancellation is best effort; an unreachable relay still enforces the original expiry. No request or pickup token is added to these metadata fields.

## Layout

| Path | Contents |
|---|---|
| `main.go` | Command dispatch and `const version` |
| `mcp.go` | Server setup and the server instructions |
| `session.go`, `tools.go` | Session state, `request_secret`, `list_secrets`, `forget_secret` |
| `httpuse.go`, `runuse.go`, `proxytool.go` | The tools that use secrets |
| `phonefill.go`, `remote.go`, `fillcmd.go` | Relay use: phone fill, remote mode, terminal fill |
| `hook.go`, `doctor.go`, `initcmd.go`, `setup.go`, `install*.go` | The other commands and native installer |
| `internal/secrets` | In-memory store and redaction of each encoding |
| `internal/policy` | Use policy parsing and matching |
| `internal/localpage` | Loopback server and the embedded fill and approval pages |
| `internal/browser` | OS browser launcher and display detection |
| `internal/relay` | HPKE, relay client, pairing and confirmation codes, QR code, shared test vectors |
| `internal/proxy` | HTTPS proxy with a per-session CA |
| `internal/detect` | Secret patterns for the hooks |
| `internal/hardening` | Turn off core dumps and mark the process as not dumpable |
| `release/` | Release builder: archives, MCPB bundles, and `server.json` |
| `scripts/sign-macos.sh` | macOS signing and notarization for CI |

## Environment variables

| Variable | Effect |
|---|---|
| `SECRETHANDOFF_COMMAND_APPROVAL` | Default or `browser`: approve commands on the local page. `claude-code`: opt into Claude Code's mandatory per-call permission prompt, for the supported interactive host described below. Unknown values keep browser approval. |
| `SECRETHANDOFF_ISOLATED_BROWSER` | `0` opens fill pages in the default browser instead of the isolated window. The isolated window is a separate Chrome, Edge, Brave, or Chromium window with a temporary profile and no extensions, so AI browser extensions cannot read the page. |
| `SECRETHANDOFF_NO_BROWSER` | Act as if no browser is available. `request_secret` uses remote mode. |
| `SECRETHANDOFF_BROWSER` | One program to open fill pages, run with the URL as its only argument. |
| `SECRETHANDOFF_RELAY_URL` | Relay service URL. Default: `https://secrethandoff.com`. Use a local `wrangler dev` URL for tests. |
| `SECRETHANDOFF_WAIT_SECONDS` | How long `request_secret` and `wait_for_secret` wait for a fill, 1 to 600 seconds. Default: 45. |

## Command approval in Claude Code

Secret entry always stays on the Secret Handoff page. To move command approval
into **interactive Claude Code 2.1.284 or later in the 2.1 series**, the owner can
set `SECRETHANDOFF_COMMAND_APPROVAL=claude-code` in the environment of the MCP
server and start a fresh session. Do not let the agent enable it for you. This
mode trusts that specific host to collect your approval before calling the tool.
It is not for an Agent SDK app or a custom permission handler: their callbacks
can approve without a human. Client name/version are self-reported context,
not authentication. Leave browser mode on when the host is not trusted.

The command tool declares `_meta["anthropic/requiresUserInteraction"]: true`.
Claude Code documents that this forces a fresh prompt despite allow rules,
automatic permission modes, and `PreToolUse` allow hooks. Ordinary form
elicitation is unsuitable: hooks can answer forms without you. The host prompt
shows the exact argument vector, secret-to-environment bindings, and explicit
absolute `dir`. Omitted, relative, or unclean directories, other clients, and
unsupported versions fall back to browser approval. There is no approval tool,
`approved` argument, or stored client grant. Each call needs its own approval.
Chat cards display status only; they do not approve or collect secret values.

Command results report `presentation: client_permission` or `browser_page`.
`command_finished` includes `approval: approved`, `executed`, `exit_code`,
redacted `stdout` and `stderr`, per-stream truncation flags, and `timed_out` and
`cancelled` flags. Nonzero exit codes still report the execution outcome.
`command_not_started` reports a startup error with `executed: false`, without an
exit code or invented output. Browser approvals report `command_pending`,
`command_denied`, `command_expired`, or `command_cancelled` when nothing ran.
Compatibility text remains available for older clients. A command can
send an environment secret anywhere; host/path/method enforcement applies to
`http_request` and the proxy, not to `run_with_secret`.

Before enabling this mode in a new host build, run the integrations repository's
`python3 scripts/check_claude_approval.py` (no secrets or actual commands), then
verify an interactive approve and deny with a dummy value. The automated probe
checks denial under allow rules and both PreToolUse and PermissionRequest allow
hooks, with an unflagged control;
it cannot certify a human click or exclusion of agent UI automation.
Codex and generic MCP Apps currently keep browser approval.

References: [Claude Code mandatory tool approval](https://code.claude.com/docs/en/mcp#require-approval-for-a-specific-tool),
[hook limitations](https://code.claude.com/docs/en/hooks#tools-that-require-user-interaction),
[ADR 0013](../../docs/adr/0013-host-command-approval.md).

## Build and test

Go 1.27.1 is the build toolchain. An older `go` command downloads it automatically. Releases use `CGO_ENABLED=0`.

```bash
go vet ./...
CI=1 go test -race ./...
CGO_ENABLED=0 go build -trimpath -o secrethandoff .
```

- `leak_test.go` is the leak suite (gate GG-01). It must pass before a release.
- With `CI` set, the relay test runs the TypeScript HPKE code in Node 22.18 or newer, and fails if it cannot.
- The MIT license is in `LICENSE`.
