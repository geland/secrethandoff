# ADR 0012: Agent request lifecycle and cancellation

- Status: Accepted
- Date: 2026-10-09
- Extends: ADR 0009 and ADR 0011 (agent-facing lifecycle and cancellation)

## Context

Agent clients previously inferred lifecycle state from prose and repeated the entire request to keep waiting. Chat cards are status displays; they must not be described as secret entry forms. Forgetting a pending local request erased no value but left its fill page live, allowing it to populate the store later.

## Decision

- Keep compatibility text and add redacted, value-free MCP structured results. Report lifecycle state, secret name, and the presentation surface. Presentation describes the local browser page or remote prompt/link delivery, never claims that the client rendered a card.
- Add `wait_for_secret(name)`. It waits within the existing configured call budget, cannot create a request or change policy, and preserves remote confirmation requirements. Repeated `request_secret` calls remain supported. No new token, persistent state, or secret-entry surface is introduced.
- Keep shared agent rules in server instructions and the synchronized project/skill guidance. Tool descriptions describe each operation without duplicating those rules.
- A name has one current request. A changed policy supersedes and cancels its older fill page or remote request, discarding any unconfirmed remote value. Waits follow the current request rather than an older ready value with a different policy.
- `forget_secret` cancels the name's open local request before erasing its value. A fill racing cancellation either finishes first and is erased, or loses and cannot reach the store. It also discards unconfirmed remote values and invalidates late pickups. A waiter for an older remote request cannot remove a newer request with the same name.
- Attempt remote relay cancellation after local erasure, within a five-second budget. Local erasure does not depend on network success; relay expiry still applies if cancellation cannot reach the service.
- Apply secret redaction to structured metadata as well as prose. No private keys, secret values, request tokens, pickup tokens, or confirmation codes are added to metadata.

## Consequences

Agents can resume waiting with only the name and make decisions from explicit states. Both card implementations consume structured states and retain prose parsing for old hosts. Forgetting an open request prevents the old page or an in-flight pickup from restoring its value. A new explicitly requested handoff can reuse the name. Cryptographic formats, approval requirements, and service retention rules are unchanged.
