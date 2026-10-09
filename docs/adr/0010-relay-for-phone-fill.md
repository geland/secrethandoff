# ADR 0010: Relay for phone fill of agent secret requests

- Status: Accepted
- Date: 2026-10-07
- Supersedes in part: ADR 0001 (adds a second cryptographic format), ADR 0003 (adds the fill proof and pickup token capabilities)
- Threat model: [`docs/security/sealed-request-threat-model.md`](../security/sealed-request-threat-model.md), revision 2, relay sections

## Context

ADR 0009 gives secrets to a local agent through a page on the same computer. A phone cannot reach that page. The human must be able to fill a request on a phone, and the service must never see the secret.

## Decision

Add a relay: the binary creates a sealed request on the service, the phone encrypts the secret to the binary's public key, and the binary collects the ciphertext once.

**When the relay is used.** Only when the human presses "Fill on my phone instead" on the local page. Local mode alone never contacts the service. The link and the pairing code go to the local page, never to the agent.

**Cryptography.**

- HPKE (RFC 9180) base mode: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM. The binary uses Go's `crypto/hpke`. The page uses Web Crypto with an RFC 9180 implementation, tested against Go in both directions.
- One key pair for each request. The private key stays in the binary's memory.
- The HPKE `info` string binds the format and the request: `secrethandoff sealed-request v1|<id>|<policy hash>|<expires>`. Go's one-shot `Seal` has no separate AAD, so `info` carries the binding.
- The public key comes only from the link fragment. The service never serves it.

**Link.** `https://secrethandoff.com/q/<id>#v1.<public key>.<fill secret>.<policy hash>`. All parts after `#` are base64url.

**Capabilities.**

- Fill proof: `HKDF-SHA256(fill secret, info "secrethandoff fill-proof v1")`. The service stores its SHA-256. It lets the holder submit one ciphertext.
- Pickup token: 256 random bits. The service stores its SHA-256. It lets the binary collect the ciphertext once, or cancel the request. It never appears in a link.

**Policy integrity.** The binary sends the policy as a JSON string. The page shows it only if its SHA-256 equals the policy hash in the fragment. The service cannot change the policy that the human sees.

**Pairing code.** `SHA-256("sh-pair v1" || public key)`, first 65 bits, shown as 13 Crockford base32 characters in groups of five, four, and four. The local page and the phone page both show it. A different key gives a different code. The first draft used 50 bits; the internal review showed that GPU key search could match 50 bits within a request's lifetime when the code is in a transcript (remote mode), so the code has 65 bits.

**State machine.** `pending` → `filled` → `picked_up`, or `pending` → `cancelled`, `locked`, or `expired`. Fill and pickup are conditional updates with exactly one winner (ADR 0002 pattern). Picked-up, cancelled, locked, and expired requests keep no ciphertext.

**Abuse controls.**

- Creation needs a proof of work: SHA-256 over every request field (fill proof hash, pickup hash, policy hash, reason hash, expiry) and a nonce must start with 18 zero bits. The binary computes it in well under a second. No server challenge is needed. A unique index on the pickup hash stops one solution from creating a second request.
- Rate limits count an IPv6 address by its /64.
- The reason and the policy may not contain control, bidi, or zero-width characters, because they could fake or hide the pairing code in a terminal or on a page.
- Separate creation limits for each address and overall, and a separate kill switch, `RELAY_ENABLED`.
- Turnstile on a fill from the web page. A fill from `secrethandoff fill` in a terminal sends an 18-bit proof of work over the request ID and the ciphertext instead, because a terminal cannot run Turnstile. A fill also always needs the fill proof from the link.
- Wrong fill proofs and pickup tokens count only toward the per-address failure limit. Both have 256 bits, so a per-request lock adds no safety, and it would let anyone who knows a request ID destroy it.
- Turnstile on the web page is a human check, not the access control: the fill proof is. A client may send the proof of work instead. This is accepted.
- The reason is plain text, at most 500 characters, shown with the label "written by the requester". A "Report this request" control records a report, limited to 10 for each address and hour. An operator lists reported requests with `SELECT id, reason, reported FROM requests WHERE reported > 0`.
- A scheduled job deletes expired requests every 15 minutes.
- The lifetime is at most one hour.

## Consequences

- The service stores only ciphertext that it cannot decrypt, plus request metadata.
- A compromised deployment can serve changed phone-page JavaScript (threat model T-13, residual risk R-02). `secrethandoff fill <link>` lets a user fill from a terminal instead.
- Phone fill depends on the service being available. Local fill does not.
- The proof of work raises the cost of bulk creation. It does not stop a determined abuser, so the rate limits and the kill switch stay necessary.
- An independent review of the protocol and the cryptography is required before release (gate GG-12).
