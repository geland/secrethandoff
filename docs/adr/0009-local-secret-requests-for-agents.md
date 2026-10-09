# ADR 0009: Local secret requests for AI agents

- Status: Accepted
- Date: 2026-10-07
- Threat model: [`docs/security/sealed-request-threat-model.md`](../security/sealed-request-threat-model.md), revision 2
- Plan: [`docs/plans/sealed-requests-plan.md`](../plans/sealed-requests-plan.md)

## Context

AI coding agents often need a credential, such as an API key or a database password, while they work. Today the human pastes it into the chat. The value then enters the model context, the transcript, and the logs of the agent client.

Secret Handoff moves secrets between two browsers. An agent is not a browser, and the human and the agent usually use the same computer. Vaults such as 1Password can give an agent a stored secret, but nothing lets a human give a new secret to a running agent without the chat.

The client matrix ([`client-matrix.md`](../plans/client-matrix.md)) shows that Claude Code and Codex start stdio MCP (Model Context Protocol) servers outside their sandboxes. Such a server can open the browser, listen on loopback, and reach the network.

## Decision

Ship a local binary, `secrethandoff`, that receives secrets from the human and uses them for the agent. In local mode, nothing goes to the Secret Handoff service.

**Binary.** One Go binary for macOS, Windows, and Linux, at `packages/cli-go`. The agent client starts `secrethandoff mcp` as a stdio MCP server with the session and stops it when the session ends. There is no daemon, no system service, and no administrator step.

**Fill page.** For each request, the binary binds `127.0.0.1` on a random port and opens `http://127.0.0.1:<port>/fill#<token>` with the OS browser launcher. The token is 256 random bits and works once. The page comes from files embedded in the binary. It shows the reason (labeled as text from the agent), the use policy, and a masked input. Filling the form approves the policy.

**Tools.** `request_secret`, `list_secrets`, `forget_secret`, `http_request`, and `run_with_secret`. No tool returns a secret value, a page token, or a fill link.

**Use policy.** Each secret has hosts, and optionally methods and paths. `http_request` sends a secret only to a request that matches the policy that the human saw at fill time. Secrets are referenced as `{{secret:NAME}}`.

**Commands.** `run_with_secret` takes an argument vector, not a shell string. The human approves each command on the local page before it runs. The MCP process starts the command, because a process that the agent starts cannot prove the human's approval.

**Storage.** Secrets, tokens, and keys stay in process memory only. They end when the session ends.

**Telemetry.** None. The binary may check for a new version, and the user can turn the check off.

**Distribution.** Releases have GitHub build provenance attestations and checksums. macOS builds are signed with Developer ID and notarized. Windows builds are not signed in phase 1.

## Consequences

- A secret given through the fill page never enters the chat, the transcript, or the model context.
- Through `http_request`, the agent never holds the secret value. Through `run_with_secret`, the started command holds it, and a model with shell access can leak it (threat model R-01).
- The binary runs as the same OS user as the agent. Same-user isolation is defense in depth, not a hard boundary (R-05). A fill conflict is visible to the human (T-42).
- The loopback server must resist malicious websites in the same browser (T-43). Every request needs the token and a correct Host header and Origin.
- `run_with_secret` runs outside the agent client's sandbox (T-52), so every command needs human approval.
- A computer without a display cannot use local mode. Relay remote mode (phase 3) covers it.
- Codex blocks agent commands from loopback by default, which matters only for the later proxy mode. `http_request` works in Codex as is.
- The service does not change in this phase. Phase 2 (relay) needs its own ADR.
