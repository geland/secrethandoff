# ADR 0011: Remote mode and the self-hosted gateway

- Status: Accepted
- Date: 2026-10-07
- Threat model: [`docs/security/sealed-request-threat-model.md`](../security/sealed-request-threat-model.md), T-14, T-19, T-31 to T-34

## Context

Local mode (ADR 0009) and phone fill (ADR 0010) need a browser on the agent's computer. An agent in a cloud VM, an SSH session, or CI has none. There, the request link must reach the human through the agent client, so a transcript reader can see it, and could fill the request first with a value of their choice (T-14).

A cloud agent that holds a secret in its VM can also leak it. An HTTPS gateway outside the VM can use the secret for the agent, as the Claude Code cloud proxy does for API credentials.

## Decision

### Remote mode

- The binary uses remote mode when no browser is available (`secrethandoff doctor` reports it).
- It creates a relay request as in ADR 0010. If the agent client declares MCP URL-mode elicitation, the binary sends the link through it, so the link does not enter the model context. Otherwise the tool result holds the link and the pairing code.
- After a fill, the phone or terminal shows a **fill confirmation code**: the first 35 bits of `SHA-256("sh-fill v1" || request ID || ciphertext)`, as 7 Crockford base32 characters.
- **The binary never tells the agent the confirmation code.** It holds a remote value apart from ready secrets. The value becomes usable only when the agent calls `confirm_secret` with the code that the human read on their own page. The binary compares it with the code that it computes from the ciphertext. Five wrong codes discard the value.
- An attacker who fills first never sees the human's page, so they cannot supply the code. The model cannot guess 35 bits.

### Self-hosted gateway

- A Cloudflare Worker template, `templates/gateway/`, that the user deploys in their own account. The Secret Handoff operator never hosts it (T-32).
- The gateway has its own HPKE key pair. Its private key is a Worker secret. A sealed request for the gateway delivers the secret into the gateway, never into the agent's VM.
- The agent gets a proxy token instead of the secret: a random token, stored as a hash, scoped to the policy's hosts, methods, and paths, with an expiry of at most 24 hours. The owner can revoke it.
- The agent calls `https://<gateway>/proxy/<host>/<path>` with the token. The gateway substitutes `{{secret:NAME}}`, forwards only to policy hosts, refuses IP literals and private names, does not follow redirects, and redacts the secret from responses.
- An agent key, set by the owner as a secret in the cloud environment, lets the agent create requests and use tokens. It cannot read secrets.
- The gateway logs each proxied request: time, token ID, method, host, path, and status. It never logs values, query strings, or bodies.

## Consequences

- Remote mode needs one more human step: reading the confirmation code back to the agent.
- Without URL-mode elicitation, the link is in the transcript. The confirmation code still stops a fill by someone else.
- The gateway's Cloudflare account becomes a high-value target (T-34). The template keeps its dependencies at zero and its code small so that the owner can review it.
- A leaked proxy token works only through the gateway, within its scope, until it expires or the owner revokes it (T-31).
