# Implementation plan: sealed secret requests for AI agents

- Status: In progress. Phases 0 to 3 are built and committed locally. Phase 4 stopped at its gate.
- Date: 2026-10-07
- Threat model: [`docs/security/sealed-request-threat-model.md`](../security/sealed-request-threat-model.md), revision 2
- Prerequisite done: [ADR 0008](../adr/0008-failed-attempt-limits-for-retrieval.md), failed-attempt limits for retrieval

## 1. Summary

Secret Handoff will let a human give a secret to an AI agent without the secret entering the chat, the transcript, or the model context. A single Go binary, `secrethandoff`, runs as a local MCP (Model Context Protocol) server. When the agent needs a credential, the binary opens a fill page in the human's own browser. The human pastes the secret there. The agent then uses the secret by name, through tools that apply it inside a use policy. The agent never receives the value.

The design is local first. In local mode, nothing goes to secrethandoff.com. The service becomes a blind relay for three cases only: a phone, a cloud or headless agent, and a second person.

The pitch: **"Hand a secret to your AI agent without pasting it in the chat. Nothing stored, nothing logged, no account."**

## 2. Goals and non-goals

### Goals

1. An agent can ask for a credential at any time in a session, and the human can give it without pasting it in the chat.
2. The agent can use the credential for HTTPS APIs without ever holding the value.
3. The same binary and guidance work in Claude Code, Codex, Cursor, Gemini CLI, VS Code, and Cline.
4. Install and first use take under two minutes and need no administrator rights on macOS, Windows, or Linux.
5. Every security claim is true and testable (threat model, section 9).

### Non-goals

- Storing secrets across sessions. Vaults do this. A later phase can read from a vault instead.
- Stopping a model with unrestricted shell access from leaking a value that `secrethandoff run` released to it (threat model R-01).
- Accounts, teams, or billing in the first phases.

### Success measures

| Measure | Target for phase 1 |
|---|---|
| Agents call `request_secret` instead of asking in chat (eval suite) | 90% or more in Claude Code and Codex |
| Secret value in any tool output, log, or transcript (leak test) | Zero |
| Time from download to first filled request | Under 2 minutes |
| Administrator prompts during install | Zero on all three platforms |

## 3. Decisions

| ID | Decision | Source |
|---|---|---|
| D-01 | Fix `/consume` guessing first. 10 wrong proofs destroy a secret. Each address has 30 failures per hour. Short passphrases stay allowed. | ADR 0008 |
| D-02 | Local first. Local mode is the default and uses no service. The service is a blind relay for phone, remote, and second-person cases. | Threat model rev. 2 |
| D-03 | One Go binary. The agent client starts `secrethandoff mcp` with the session. No daemon and no system service in the first release. | Threat model G9 |
| D-04 | The Go binary lives in this repository at `packages/cli-go`. A new public repository, `secrethandoff-integrations`, holds the plugin, MCP, and skill files, as `shareout-integrations` does. | Plan discussion |
| D-05 | Open source the binary and the fill pages. Infrastructure code can stay private. | Plan discussion |
| D-06 | Version 1 is phase 1 only: local mode, `request_secret`, `http_request`, `run_with_secret`, guidance layers 1 to 4, and Claude Code hooks. | Plan discussion |
| D-07 | Strictly ephemeral. Secrets end with the session. No "remember this key". | Plan discussion |
| D-08 | No accounts. Local mode is free. The relay is free within rate limits. Decide on paid features after usage data. | Plan discussion |
| D-09 | No telemetry in the binary. At most, an anonymous update check that the user can turn off. | Plan discussion |
| D-10 | The Claude Code mod is a UI upgrade for Claude Code only. It ships after the browser page, and only when gate GG-15 passes. | Plan discussion |
| D-11 | Agent guidance has four layers: MCP instructions and tool descriptions, a skill, client hooks, and an optional project rules block. | Plan discussion |
| D-12 | Each phase starts with an ADR, because each phase changes trust boundaries (`AGENTS.md`). Work goes directly to `main`, with one commit for each task. A push to `main` deploys the service. | `AGENTS.md`, working practice |
| D-13 | Every release gets GitHub build provenance attestations and checksums. macOS builds are signed with Developer ID, with the hardened runtime, and notarized, using the existing Apple Developer account. Windows builds are not signed in phase 1: Scoop, winget, and the install script do not trigger SmartScreen. Add Azure Trusted Signing only if users report warnings. | Plan discussion |
| D-14 | License: MIT, the same as shareout and shareout-integrations. | Plan discussion |
| D-15 | The Claude Code pasted-secret hook is on by default. | Plan discussion |
| D-16 | The page for agent users lives on secrethandoff.com. | Plan discussion |

## 4. Architecture

### 4.1 Repository layout

```text
secure-secret-share/                 (this repository)
├── app/                             Worker app: share flow, relay API (phase 2), relay fill page (phase 2)
├── packages/cli-go/                 secrethandoff binary (new, phase 1)
│   ├── main.go                      command routing: mcp, run, doctor, version
│   ├── mcp.go                       MCP server (official Go MCP SDK)
│   ├── localpage/                   loopback server and embedded fill page
│   ├── policy/                      use policy parsing and matching
│   ├── secrets/                     in-memory secret store and redaction
│   ├── httpuse/                     http_request implementation
│   ├── runuse/                      run_with_secret implementation
│   ├── proxy/                       optional HTTPS proxy (phase 1.5)
│   ├── relay/                       relay client and HPKE (phase 2)
│   └── testdata/
├── docs/adr/                        ADR 0009 (phase 1), 0010 (phase 2), 0011 (phase 3)
├── docs/plans/                      this plan
└── docs/security/                   threat model

secrethandoff-integrations/          (new public repository, phase 1)
├── .claude-plugin/                  Claude Code plugin and marketplace manifests
├── .codex-plugin/, .agents/         Codex plugin and marketplace
├── server.json                      MCP Registry entry
├── gemini-extension.json            Gemini CLI extension
├── hooks/                           Claude Code hooks (pasted-secret and literal-secret guards)
├── skills/secrethandoff/SKILL.md    detailed workflow (guidance layer 2)
├── agents/openai.yaml               skill metadata for skills.sh and Cline
├── configs/                         Cursor, VS Code, OpenCode, and local setup files
├── evals/                           agent eval cases
└── scripts/                         package.py, validate.py (copied from shareout-integrations)
```

### 4.2 Binary commands

| Command | Purpose | Phase |
|---|---|---|
| `secrethandoff mcp` | Stdio MCP server. The agent client starts and stops it. | 1 |
| `secrethandoff doctor` | Checks the install: browser launcher, loopback bind, client configuration, version. Prints no secrets. | 1 |
| `secrethandoff init` | Writes the optional project rules block (guidance layer 4). | 1 |
| `secrethandoff fill <link>` | Fills a relay request from a terminal, for users who do not trust the web page (threat model T-13). | 2 |

### 4.3 MCP tools

| Tool | Input | Result to the agent | Phase |
|---|---|---|---|
| `request_secret` | `name`, `reason`, `policy` (`hosts`, `methods`, `paths`), optional `expires_in` | "NAME is ready", or "the human declined", or "expired". Never a value or a link. | 1 |
| `list_secrets` | none | Names, policies, and states. Never values. | 1 |
| `http_request` | `method`, `url`, `headers`, `body`, with `{{secret:NAME}}` references | Status, headers, and body, with every secret encoding removed | 1 |
| `run_with_secret` | `command` (argument vector), `secrets` (`NAME:ENV_VAR` pairs), optional `cwd` | Exit code, stdout, and stderr, with every secret encoding removed. The MCP process starts the command itself. The human approves each command on the local page (T-52). | 1 |
| `forget_secret` | `name` | "forgotten" | 1 |
| `proxy_settings` | none | Proxy URL with its session credential and the CA certificate path. Never a secret value. | 1.5 |

There is no `secrethandoff run` shell command. A process that the agent starts from its shell cannot prove to the MCP process that the human approved it, so the MCP process starts approved commands itself.

The secret reference syntax is `{{secret:NAME}}`. It is valid only in `http_request` headers, the URL query, and the body. The binary refuses a reference to a host outside the secret's policy.

### 4.4 Use policy

```json
{
  "hosts": ["api.stripe.com"],
  "methods": ["GET", "POST"],
  "paths": ["/v1/charges", "/v1/customers/*"]
}
```

- Hosts are exact by default. A wildcard is allowed only as the first label (`*.example.com`) and the fill page shows a warning for it.
- Methods and paths are optional. When they are absent, the fill page says "any request to these hosts".
- The fill page shows the policy next to the input. Filling approves it (threat model T-04).
- The binary enforces the policy that the human saw at fill time (T-05).

### 4.5 Local fill page

- The binary embeds static HTML, CSS, and JavaScript with Go `embed`. The look matches secrethandoff.com. There are no external requests.
- The binary binds `127.0.0.1` on a random port and opens `http://127.0.0.1:<port>/fill#<token>` with the OS browser launcher.
- The page shows: the reason (labeled as text from the agent), the policy, a masked input, Submit, Decline, "This was not me" after a fill, and, from phase 2, a QR code for phone fill.
- The loopback server checks the token, the Host header, the Origin, and `Sec-Fetch-Site` on every request, and sends no CORS headers (T-43).
- Without a display, the binary uses relay remote mode from phase 3. Before phase 3, it returns "no display; local mode unavailable" and suggests a supported setup.

## 5. Agent guidance

| Layer | Content | Where | Phase |
|---|---|---|---|
| 1. Always loaded | MCP server instructions (five lines or fewer), tool descriptions, required policy fields in the schema, and next-step text in tool results and errors | The binary | 1 |
| 2. On demand | `SKILL.md`: naming, narrow policies, tool order (`http_request`, then proxy, then `run_with_secret`), forbidden actions, what to tell the human | Integrations repository | 1 |
| 3. Guardrails | Claude Code `UserPromptSubmit` hook that blocks a prompt with a pasted secret, and `PreToolUse` hook that blocks Bash commands with a literal secret | Integrations repository | 1 (Claude Code), later for other clients |
| 4. Project rules | A short block for `AGENTS.md`, `CLAUDE.md`, `.cursor/rules`, or `GEMINI.md` | `secrethandoff init` | 1 |

Draft of the MCP server instructions:

> When you need a password, API key, token, or other credential, call `request_secret`. Never ask the user to paste a secret in chat. Use a secret only by name, through `http_request` or `run_with_secret`. Never print, echo, or write a secret to a file. Ask for the narrowest policy that does the task.

Tool descriptions must stay factual. They must not tell the agent to ignore other instructions, because marketplace review and tool-poisoning scanners flag that.

## 6. Phases and tasks

Sizes: S is up to one day, M is two to four days, L is one to two weeks. "Gates" refers to the go/no-go gates in section 11 of the threat model. A phase ships only when its gates pass.

### Phase 0: prerequisites

| ID | Task | Size | Depends on | Acceptance criteria |
|---|---|---|---|---|
| P0-1 | Release the ADR 0008 fix: review, merge, and deploy. The deploy applies migration `0001` before the new code. | S | — | Production has the `failed_attempts` column. A test secret with no real data locks after 10 wrong proofs. The receipt shows "Destroyed after failed attempts". |
| P0-2 | Run the integration test in CI: start the Worker locally, apply migrations, run `npm run test:integration`. | S | P0-1 | Done 2026-10-07: `npm run test:integration:ci` runs in CI and before the production migration in the deploy workflow. Completes gate GG-07. |
| P0-3 | Write ADR 0009: local mode architecture. It covers the binary, the loopback page, the use policy, the tool set, and the decision to have no daemon. | S | — | Done 2026-10-07: [ADR 0009](../adr/0009-local-secret-requests-for-agents.md). `AGENTS.md` has the local binary invariants. |
| P0-4 | Create `packages/cli-go` (Go 1.27.1, official MCP Go SDK, CGO off) and the public `secrethandoff-integrations` repository with the shareout validate and package scripts. | S | P0-3 | Done 2026-10-07: `packages/cli-go` scaffold with a CI job for macOS, Windows, and Linux. The integrations repository exists locally at `~/Projects/secrethandoff-integrations` and is not yet on GitHub. |
| P0-5 | Client matrix spike. In Claude Code, Codex, Cursor, and Gemini CLI, check: the client starts a stdio MCP server, the server can open a browser, the server can bind a loopback port, how the client sandbox treats the server, and whether the client passes `SSL_CERT_FILE` to commands. | M | P0-4 | Done 2026-10-07 for Claude Code and Codex: [`client-matrix.md`](client-matrix.md). Threat model open question 4 is answered. |
| P0-6 | Hook spike. Confirm that a Claude Code `UserPromptSubmit` hook can block a prompt so that the model never sees it, and that a `PreToolUse` hook can block a Bash command. | S | — | Done 2026-10-07: [`claude-code-hook-check.md`](claude-code-hook-check.md). A block keeps the prompt from the model, but the text stays in the local transcript. |
| P0-7 | Apple signing setup: create a Developer ID Application certificate (this needs the Account Holder role), export it with its private key for CI, and create an App Store Connect API key for `notarytool`. Store both as GitHub secrets. | S | — | A CI test job signs and notarizes a test binary. No certificate or key is in the repository. |
| P0-8 | Finish the client matrix: Cursor, Gemini CLI, Claude Code with its sandbox setting on, and Windows and Linux. | S | P0-5 | `client-matrix.md` has a column for each client and OS. |

### Phase 1: local mode (version 1)

| ID | Task | Size | Depends on | Acceptance criteria |
|---|---|---|---|---|
| P1-1 | In-memory secret store and redaction. Remove raw, base64, base64url, hex, and URL-encoded forms. Disable core dumps and mark the process as not dumpable where the OS allows. | M | P0-4 | Done 2026-10-07 (55965fa). Acceptance: Unit tests for each encoding. No secret is written to disk in any test. |
| P1-2 | Use policy engine: parse, validate, and match hosts, methods, and paths. Exact hosts by default. Wildcard only as the first label. | S | P0-4 | Done 2026-10-07 (f72663a). Acceptance: Unit tests for exact match, wildcard, path globs, and refused hosts. |
| P1-3 | Loopback server and embedded fill page: one-time token, Host, Origin, and `Sec-Fetch-Site` checks, no CORS, strict CSP, live status, Decline, "This was not me", and the command approval view for `run_with_secret`. | L | P1-1, P1-2 | Done 2026-10-07 (ef285bf). Tested in Chromium only; Safari, Firefox, and Edge are not yet tested. Acceptance: Gate GG-02 tests pass. The page works in current Chrome, Safari, Firefox, and Edge. |
| P1-4 | Browser launcher for each OS (`open`, `ShellExecute`, `xdg-open`). Detect a missing display. Never write the token to stdout or stderr. | S | P1-3 | Done 2026-10-07 (446a353). The CI matrix covers macOS, Windows, and Linux; it has not run on GitHub yet because nothing is pushed. Acceptance: Tests on all three OSes. A no-display run returns a clear message and prints no token. |
| P1-5 | MCP server with `request_secret`, `list_secrets`, and `forget_secret`. Server instructions, tool descriptions, schemas with required policy fields, and next-step text in results and errors. | M | P1-3, P1-4 | Done 2026-10-07 (300961b). Acceptance: An MCP client test covers each tool. Results never contain a value, a token, or a link. |
| P1-6 | `http_request`: `{{secret:NAME}}` references, policy checks, no cross-host redirects, response redaction, an echo-host warning, and size and time limits. | M | P1-1, P1-2, P1-5 | Done 2026-10-07 (300961b). Acceptance: Tests for wrong host, redirect to another host, reflected header, and timeout. |
| P1-7 | `run_with_secret`: argument vector only (no shell), approval on the local page for each command, the secret in one environment variable, output redaction, and a time limit. | M | P1-3, P1-5 | Done 2026-10-07 (300961b). Acceptance: A test shows that no command runs without approval (T-52). |
| P1-8 | Leak test suite: send a known value through every tool, error path, stdout, stderr, and encoding. | M | P1-5 – P1-7 | Done 2026-10-07 (fe5bb2a). A test proves that the suite fails when redaction is removed. CI on three OSes runs after the push. Acceptance: Gate GG-01 passes. The suite runs in CI on all three OSes. |
| P1-9 | `doctor` and `init` commands. | S | P1-5 | Done 2026-10-07 (af95492). Acceptance: `doctor --json` reports each check. `init` writes the rules block once and does not repeat it. |
| P1-10 | Guidance layer 2 and layer 4: `SKILL.md`, `agents/openai.yaml`, and the project rules block. | S | P1-5 | Done 2026-10-07 in the integrations repository and `secrethandoff init`. Acceptance: Files validate in the integrations repository. The text passes the plain-English lint. |
| P1-11 | Claude Code hooks: block a prompt that contains a pasted secret, and block a Bash command that contains a literal secret. Pattern set based on common secret formats, with a short allow list for test values. | M | P0-6 | Done 2026-10-07 (b4f1788). Acceptance: Tests with true and false positives. The block message says that the secret did not reach the AI, that it is still in the local session history, and how to use `request_secret` ([hook check](claude-code-hook-check.md)). |
| P1-12 | Eval suite: at least 20 cases, such as "the deploy needs a Stripe key", "the user pastes a token", and "an auth error during a curl command". Run with `claude plugin eval`, and run the same cases in Codex. | M | P1-10, P1-11 | Partly done 2026-10-07: 21 cases. Codex: 11/21 (52%) with the MCP server alone, 21/21 (100%) with the rules block from `secrethandoff init` (`evals/RESULTS.md` in the integrations repository). Claude Code: not run, because `claude plugin eval` needs a logged-in CLI. Acceptance: `request_secret` is called in 90% or more of the cases in Claude Code and Codex. |
| P1-13 | Release pipeline: deterministic builds for six targets, GitHub releases with build provenance attestations and checksums, an install script, and Homebrew, Scoop, and winget manifests (D-13). macOS builds are signed with Developer ID and the hardened runtime, then notarized with `notarytool` in CI. | M | P0-4, P0-7 | Built 2026-10-07 (b372cf9, 1061f6e). Signing waits for P0-7. The acceptance checks run on the first release. Acceptance: Gates GG-04 and GG-05 pass. A fresh install through each channel on each OS needs no administrator prompt and shows no Gatekeeper or SmartScreen warning. `gh attestation verify` succeeds for each archive. `spctl --assess` accepts a macOS binary downloaded through a browser. |
| P1-14 | Publish the integrations: Claude Code plugin marketplace, Codex, MCP Registry with the domain proof, Smithery, Glama, Gemini CLI, and skills.sh. Manifests pin the version and checksum. The Codex manifest pre-approves `list_secrets` and `http_request`, and keeps approval for `request_secret` and `run_with_secret` ([client matrix](client-matrix.md)). Claim the product name in each place (T-40). | M | P1-13 | Partly done 2026-10-07 (49cd63a): MCPB bundles, `server.json`, and client configs. Publishing needs the owner's accounts. Acceptance: Each listing installs the pinned version. `docs/distribution.md` in the integrations repository records the status of each listing. |
| P1-15 | Documentation and site: security page section for local mode with the allowed claims and residual risks, a page for agent users, the binary README, and an open-source license. | M | P1-8 | Done 2026-10-07 (ae6fe59). The MIT license is in `packages/cli-go/LICENSE`. Acceptance: Gate GG-06 passes. |

### Phase 1.5: proxy mode

| ID | Task | Size | Depends on | Acceptance criteria |
|---|---|---|---|---|
| P15-1 | HTTPS proxy inside the MCP process: a CA for each session with name constraints, the CA key in memory only, a proxy credential for each session, SNI and Host matching, no cross-host redirects, and reflection removal. | L | Phase 1 | Done 2026-10-07 (49a6920). Acceptance: Gate GG-03 passes completely. |
| P15-2 | `proxy_settings` tool and guidance updates, with setup notes for each client from the P0-5 matrix. Codex needs `sandbox_workspace_write.network_access = true` for agent commands to reach the proxy. | S | P15-1 | Done 2026-10-07 (49a6920). Acceptance: `curl`, Node, and Python requests through the proxy receive the credential. Requests that bypass the proxy do not. |

### Phase 2: relay phone mode

| ID | Task | Size | Depends on | Acceptance criteria |
|---|---|---|---|---|
| P2-1 | Write ADR 0010: relay protocol, cryptographic format, capabilities, and abuse controls. Update or supersede ADR 0001 and ADR 0003. | M | Phase 1 | Done 2026-10-07 (89d4d6c): [ADR 0010](../adr/0010-relay-for-phone-fill.md). Acceptance: Gate GG-08 passes. |
| P2-2 | Service: `requests` table and migration, endpoints for create, fill, pickup, and status, attempt limits on fill and pickup, separate creation limits and kill switch, Turnstile on fill, and scheduled cleanup with a cron trigger. | L | P2-1 | Done 2026-10-07 (3f7ba21). Acceptance: Gate GG-11 passes. Integration tests cover one-time fill, one-time pickup, and concurrency. |
| P2-3 | HPKE in TypeScript for the page and in Go for the binary. Check whether the Go standard library provides HPKE. If not, choose a reviewed library. | M | P2-1 | Done 2026-10-07 (89d4d6c). Go uses `crypto/hpke`. Shared test vectors run in both languages. Acceptance: Gate GG-10 passes: RFC 9180 test vectors pass in both languages. |
| P2-4 | Relay fill page, mobile first: pairing words in large text, the policy, the labeled reason, a masked input, and "report this request". | M | P2-2, P2-3 | Done 2026-10-07 (fa85720). The pairing code replaced the pairing words. Acceptance: Gate GG-09 passes. |
| P2-5 | QR code on the local page, and the relay client in the binary: create, poll with backoff, pickup, and decrypt. | M | P2-2, P2-3 | Done 2026-10-07 (cf22d39). Verified end to end through a local relay. Acceptance: End-to-end test: a request filled from a phone browser reaches the binary, and nothing readable reaches the service. |
| P2-6 | `secrethandoff fill <link>` for terminal fill (T-13). | S | P2-3 | Done 2026-10-07 (885cfc2). Acceptance: Fills a relay request without a browser. |
| P2-7 | Independent cryptography and protocol review. Fix all High and Critical findings. | M | P2-1 – P2-6 | Internal review done 2026-10-07 (3478b76): no Critical or High findings, and all findings fixed. The independent review is still open. Acceptance: Gate GG-12 passes. |
| P2-8 | Security page update for relay mode. | S | P2-7 | Done 2026-10-07 (29af231). Acceptance: Claims and residual risks match the threat model. |

### Phase 3: relay remote mode and the gateway

| ID | Task | Size | Depends on | Acceptance criteria |
|---|---|---|---|---|
| P3-1 | Write ADR 0011: remote mode and the self-hosted gateway. | S | Phase 2 | Done 2026-10-07: [ADR 0011](../adr/0011-remote-mode-and-gateway.md). Acceptance: ADR accepted. |
| P3-2 | Remote mode in the binary: headless detection, the link through MCP URL-mode elicitation where the client supports it (Claude Code does) and in the tool result otherwise, the pairing words, and the fill confirmation code with the confirmation step before first use. | M | P3-1 | Done 2026-10-07 (dc0073c). Acceptance: Gate GG-13 passes. |
| P3-3 | Gateway template for the user's own Cloudflare account: proxy tokens with scope, expiry, and revocation, an IP range block list, and a request log. | L | P3-1 | Done 2026-10-07 (5f9674b). Acceptance: Gate GG-14 passes. |
| P3-4 | Guide for cloud agents. It says when a native feature is the better choice, for example Claude Code cloud API credentials on Pro and Max plans. | S | P3-2, P3-3 | Done 2026-10-07 (751fd9c): [cloud agents guide](../guides/cloud-agents.md). Acceptance: Guide published. |

### Phase 4: Claude Code mod

| ID | Task | Size | Depends on | Acceptance criteria |
|---|---|---|---|---|
| P4-1 | Verification spike: the transcript and debug-log test (T-49), detection of other plugins' hooks (T-48), and `$.process` in the desktop app (T-50). | S | Phase 1 | Done 2026-10-07: [mod check](claude-code-mod-check.md). T-48 and T-50 fail, so phase 4 stops. Acceptance: Each result recorded. If one fails, stop phase 4 and record why. |
| P4-2 | The mod: a pane with the reason, policy, input, Submit, and a QR code drawn with `Svg`. Submit only on a button press. Send the value to a child binary over stdin. Fall back to the local page. | M | P4-1 | Stopped 2026-10-07. Gate GG-15 failed. Not built. Acceptance: Gate GG-15 passes. |
| P4-3 | Claude Code mod card: draw the `request_secret`, `run_with_secret`, and `confirm_secret` rows as a branded card with the reason, the policy, and the status. No input. | S | P4-1 | Done 2026-10-08: `hooks/card.tsx` in the integrations repository. The desktop draws an SVG card; the desktop app folds the call's section, so a band above the prompt shows each request while it waits. Checked live in the Claude Code desktop app; 12 tests (threat model T-56). |
| P4-4 | MCP App card: the same card for hosts with MCP Apps (Codex desktop, Claude desktop chat, VS Code, Cursor). No input and no network. | S | P4-3 | Done 2026-10-08: `internal/appcard`, checked with a stand-in host; not yet checked in a real host. |
| P4-5 | Refuse agent-controlled browsers on the local page (T-54), and decide on an isolated browser window for AI browser extensions (T-55). | S | — | Done 2026-10-08: pane refusal, and the isolated window on by default with the `SECRETHANDOFF_ISOLATED_BROWSER=0` opt-out. Checked live with Google Chrome on macOS; not yet on Windows or Linux. |

### Later

- Fill from a vault: 1Password and Bitwarden as sources on the local page.
- X25519 as a second relay key type.
- The hardened mode with a separate OS user.

## 7. Testing

| Level | What | Where |
|---|---|---|
| Unit | Policy matching, redaction encodings, token checks, HPKE vectors | Go tests and Node tests, in CI on macOS, Windows, and Linux |
| Loopback security | Host, Origin, and `Sec-Fetch-Site` checks, one-time tokens, CORS absence, "This was not me" | Go integration tests against a running binary |
| Leak suite | A known value through every tool, error path, stream, and encoding | Go integration tests, gate GG-01 |
| Service | One-time semantics, concurrency, attempt limits, cleanup | `tests/integration-local.mjs`, in CI from task P0-2 |
| Client matrix | Start, browser launch, loopback, sandbox, environment passthrough | Manual checklist for each release, from task P0-5 |
| Agent behavior | Does the agent call `request_secret` and avoid asking in chat? | Eval suite from task P1-12, run for each release |
| Install | Fresh install on clean macOS, Windows, and Linux machines | Release checklist, gates GG-04 and GG-05 |

Every fixed security defect gets a regression assertion (`AGENTS.md`).

## 8. Release and distribution

- **Builds.** Deterministic, CGO off, six targets (macOS, Windows, and Linux, each on arm64 and amd64), as in shareout's `cli-go`.
- **Provenance, not paid signing (D-13).** GitHub build provenance attestations let a user verify that a release came from this repository's CI. This is new compared with shareout, whose README says its checksums are not an independent signing system.
  - macOS: Developer ID signing with the hardened runtime and without `get-task-allow`, then notarization. Apple does not staple a ticket to a bare binary, so Gatekeeper checks the notarization online on first run. The site can offer a direct macOS download.
  - Windows: no signing in phase 1. If SmartScreen warnings appear, use Azure Trusted Signing.
- **Channels.** GitHub Releases, an install script on secrethandoff.com, Homebrew, Scoop, and winget.
- **Integrations.** The `secrethandoff-integrations` repository pins each manifest to an exact version and checksum. The plugin and MCP listings run `secrethandoff mcp`.
- **Updates.** No silent self-update. The binary can report that a new version exists, and the user can turn that check off (D-09).

## 9. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Agent clients differ in how they start MCP servers, sandbox them, and pass environment variables. | Some features fail in some clients. | Task P0-5 runs first. `http_request` needs no client support beyond MCP. |
| Users download the binary through a browser and see Gatekeeper or SmartScreen warnings | Lost installs | Point every install guide at a package manager or the install script (D-13). Add notarization or Azure Trusted Signing if warnings appear. |
| Agents ignore the guidance and ask for secrets in chat. | The product does not deliver its main promise. | Eval suite target, pasted-secret hook in Claude Code, and the project rules block. |
| False positives in the pasted-secret hook | The user's prompt is blocked for no reason. | A test set with known false positives, and an override phrase that the user can type. |
| `run_with_secret` runs outside the client sandbox. | A harmful approved command. | Approval for each command with the full argument vector (T-52). Prefer `http_request` in the guidance. |
| 1Password, passwd.page, or an agent vendor ships the same intake feature. | Less differentiation. | Ship phase 1 fast. Position as a complement to vaults, with vault sources later. |
| Relay phishing on the secrethandoff.com domain | Reputation damage | Pairing words, plain-text reasons, a report control, short expiry, and a kill switch. |

## 10. Open questions

The threat model, section 12, holds the security questions. The planning questions are resolved: D-13 (signing), D-14 (license), D-15 (hook default), and D-16 (product page).

## 11. Next steps

The owner must do these steps. The agent cannot do them.

1. P0-7: create the Developer ID Application certificate and the App Store Connect API key. Store them as GitHub secrets for `release-cli.yml`.
2. Push `main`. The deploy applies migrations `0001` to `0003` before the new code. Then check the ADR 0008 fix in production (P0-1), and check that the CI matrix passes on three OSes (P1-4, P1-8).
3. P2-7: get an independent review of the protocol and the cryptography (gate GG-12). The relay is on unless `RELAY_ENABLED` is `false`. To hold phone fill and remote mode until the review is closed, set `RELAY_ENABLED` to `false` in production before step 2.
4. P1-12: run `claude /login`, then `claude plugin eval` on the integrations repository.
5. P1-13 and P1-14: tag the first release, then publish the integrations listings.
6. P0-8: finish the client matrix for Cursor, Gemini CLI, the Claude Code sandbox, Windows, and Linux.
