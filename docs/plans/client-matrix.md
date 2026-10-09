# Client matrix (task P0-5)

- Date: 2026-10-07
- Method: a probe stdio MCP server that records what the client lets it do, and an agent run that calls the probe, then runs shell commands. No real secrets were used.

## Results

| Check | Claude Code 2.1.289 (desktop app) | Codex CLI 0.155.1 |
|---|---|---|
| Starts a stdio MCP server | Yes, from a plugin's `.mcp.json` | Yes, from `mcp_servers` configuration |
| MCP tool calls need approval | Normal Claude Code permission rules | Yes, each tool, unless the configuration sets `mcp_servers.<name>.tools.<tool>.approval_mode = "approve"` |
| MCP server is sandboxed | No: it writes to the home folder, reaches the internet, and listens on loopback | No: same results |
| MCP server opens a browser tab (`open -g`) | Yes | Yes |
| MCP server environment | Not tested for inherited variables (the desktop app starts the client) | Filtered: a custom variable from the client's environment did not reach the server. `SSL_CERT_FILE` did. |
| Agent shell commands reach the MCP server's loopback port | Yes | **No by default** (curl exit code 7). Yes with `sandbox_workspace_write.network_access = true`. |
| Agent shell commands inherit the client's environment | Not tested | Yes |
| Inline `VAR=value command` works in agent commands | Yes | Yes |
| Client reads `SSL_CERT_FILE` for its own connections | Not tested | **Yes.** A wrong value breaks Codex's own connections. |
| MCP elicitation modes the client declares | `form` and `url` | Not recorded |

Not tested: Cursor and Gemini CLI (not installed), the Claude Code sandbox setting (off on the test machine), Windows, and Linux.

## Effects on the plan

1. **Local mode works in both clients.** The MCP server can open the browser and serve the loopback fill page. `http_request` works, because the MCP server has network access.
2. **Proxy mode does not work in Codex's default sandbox.** Agent commands cannot reach loopback. The proxy setup guide must tell Codex users to set `sandbox_workspace_write.network_access = true`, or to use `http_request`. Keep `http_request` as the first choice in the guidance.
3. **Never set `SSL_CERT_FILE` in the client's environment.** Codex uses it for its own connections. The proxy CA goes only into single commands, as an inline prefix. This confirms threat model T-29.
4. **Codex asks for approval of each MCP tool call.** Approval for `request_secret` is useful, because the human sees the request. Approval for every `http_request` call adds friction. The Codex plugin manifest should pre-approve `list_secrets` and `http_request`, and leave `request_secret` and `run_with_secret` on approval. `run_with_secret` also has its own approval on the local page (T-52).
5. **Claude Code supports URL-mode elicitation.** In relay remote mode, the binary can send the request link through URL mode, so the link does not enter the model context. This answers threat model open question 1 for Claude Code. An earlier third-party report said that Claude Code did not support URL mode. That report was about version 2.1.237 and is out of date.
6. **The MCP server runs outside both clients' sandboxes.** This confirms T-52: `run_with_secret` runs commands that the client's sandbox would block, so each command needs human approval.

## Side finding

The test machine's `~/.codex/config.toml` has `network_access = true` at the top level. Codex ignored it: the sandbox blocked network access until `sandbox_workspace_write.network_access` was set.
