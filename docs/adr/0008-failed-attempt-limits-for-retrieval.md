# ADR 0008: Failed-attempt limits for retrieval

- Status: Accepted
- Date: 2026-10-07
- Supersedes: the ADR 0002 sentence "A wrong proof performs no destructive mutation."

## Context

ADR 0001 allows short passphrases for usability. ADR 0002 made a wrong proof harmless, so a recipient can retry a mistyped passphrase. Together, these let anyone who holds a complete share link guess the passphrase online with no limit until the secret expires. A four-digit passphrase falls in at most 10,000 guesses. The receipt and burn endpoints also had no limit on wrong management tokens.

## Decision

Count wrong proofs for each secret. After 10 wrong proofs, destroy the ciphertext and move the receipt to a new terminal state, `locked`.

- The counter is a `failed_attempts` column on `secrets`. A D1 batch increments it, deletes the ciphertext when it reaches the limit, and moves the receipt to `locked`. Concurrent wrong proofs still produce exactly one destruction.
- Wrong proofs 1 to 9 do not consume or destroy the secret. The response tells the recipient how many attempts remain.
- The correct proof works at any time before the limit.
- The sender's receipt shows `locked`, so the sender knows that someone tried to guess.

Limit failed attempts per address across all secrets: 30 wrong proofs or management tokens per address per hour, then HTTP 429. The counter uses the existing `rate_limits` table with a hashed address. Literal local development hosts bypass this limit, as they bypass the creation limits (ADR 0004).

Keep the ADR 0001 decision to allow short passphrases. The per-secret limit gives a four-digit passphrase a guessing chance of 10 in 10,000.

## Consequences

- Online guessing of a passphrase is limited to 10 tries for each secret.
- Anyone who knows a secret ID can destroy the secret with 10 wrong proofs. The ID is in the path of both links, but the fragment key is not. This failure is safe: the secret is destroyed, not disclosed, and the sender can send it again.
- The receipt state machine is now `available` → `consumed`, `burned`, `expired`, or `locked`.
- Users behind one shared address share the hourly failure limit. Normal use does not reach 30 failures.
- The per-address limit is not tested by the local integration test, because local hosts bypass it. The per-secret limit has regression tests.
