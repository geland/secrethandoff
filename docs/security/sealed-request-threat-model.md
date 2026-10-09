# Threat model: sealed secret requests

- Status: Draft, revision 2
- Date: 2026-10-07
- Applies to: the proposed sealed request feature and the local `secrethandoff` binary. It does not change the current one-time share flow.
- Related decisions: ADR 0001 (browser-only encryption), ADR 0002 (atomic one-time retrieval), ADR 0003 (access and receipt capabilities), ADR 0004 (abuse controls), ADR 0007 (operational logs)

## 1. Purpose

This document defines the security goals, trust boundaries, threats, and mitigations for sealed secret requests. Use it to decide whether to build the feature, and to review each design and code change against it.

A sealed request reverses the current flow. The receiver asks for a secret first. The sender then gives the secret to the receiver. In the target use case, the receiver is software that runs an AI agent, and the sender is the human who works with that agent.

The design is local first:

- **Local mode** is the default. A local binary shows a page in the human's own browser and receives the secret directly. Nothing goes to the service.
- **Relay mode** is for cases where the two ends cannot reach each other: a phone, a cloud or headless agent, or a second person. The service stores only ciphertext that it cannot decrypt.

The feature must stay inside the invariants in `AGENTS.md`. Section 10 lists the new invariants that the feature needs.

## 2. Scope

### In scope

- The `secrethandoff` binary: a single Go binary for macOS, Windows, and Linux. It runs as a stdio MCP (Model Context Protocol) server and as an optional local HTTPS proxy.
- The local fill page that the binary serves on the loopback address.
- The relay protocol: request creation, the phone or remote fill page, ciphertext pickup, and expiry.
- The QR code and the pairing code that move a request from the agent's screen to a phone.
- The remote injection gateway, a later phase: a gateway that the user deploys in their own Cloudflare account for cloud agents.
- The optional Claude Code mod, which shows the fill form inside Claude Code (section 7.9).
- Distribution of the binary through package managers and plugin, MCP, and skill marketplaces.

### Out of scope

- Compromise of the human's phone, operating system, or browser. ADR 0003 already notes that a malicious browser extension can read same-origin data.
- Protection of a secret after the target system receives it.
- Legal and compliance duties of the operator.

## 3. Security goals

| ID | Goal |
|---|---|
| G1 | In local mode, the secret never leaves the human's computer. In relay mode, the plaintext never reaches the service, its logs, or its database. |
| G2 | The plaintext never enters the model context, the chat transcript, the MCP client, or tool output. |
| G3 | Only the requesting binary can decrypt or receive the secret. |
| G4 | The human can confirm, before they submit, that they give the secret to their own agent. |
| G5 | The binary can confirm that the secret it received came from its own human, not from an attacker or from the model. |
| G6 | A request can be filled once. In relay mode, its ciphertext can be picked up once. Expired or finalized requests keep no ciphertext. |
| G7 | When the agent uses the secret through `http_request`, the proxy, or the gateway, the agent never holds the secret value. |
| G8 | Any value that can appear in a transcript (a relay request link, the pairing code, a proxy token) gives an attacker no access to the secret. |
| G9 | Normal use needs no administrator rights, no system service, and no change to the system trust store on any supported OS. |

### Non-goals

- **The feature does not stop a model with unrestricted shell access from leaking a secret that it holds.** When `run_with_secret` releases a secret into a process environment, the model can read and leak it. G7 applies only to `http_request`, the proxy, and the gateway.
- **Same-user isolation is not a hard boundary.** The agent runs as the same OS user as the binary. The default design detects and limits same-user misuse. An optional hardened mode gives a stronger boundary.
- The feature does not hide relay metadata from the operator: request times, sizes, IP addresses, and fill times.
- The feature does not authenticate people. It has no accounts. It binds a request to a key, not to a person.

## 4. System overview

### 4.1 Modes

| Mode | When | Service used | Request link in transcript |
|---|---|---|---|
| Local | The agent and the human use the same computer. The human fills on that computer. | No | No |
| Relay, phone | The human fills on a phone by scanning the QR code on the local page. | Yes, ciphertext only | No |
| Relay, remote | The agent has no local screen (cloud VM, SSH session, CI), or a second person fills the request. | Yes, ciphertext only | Yes, by design |

Remote relay is the only mode where an attacker can see the request link. It needs extra controls (T-14, T-19).

### 4.2 Components

| Component | Runs where | Holds |
|---|---|---|
| Agent (the model) | Model provider, through an agent client such as Claude Code or Codex | Nothing secret. It sees request names, status, and action results. |
| `secrethandoff mcp` | The user's computer, or the cloud agent's VM. The agent client starts it with the session and stops it when the session ends. | The request private key, the local page token, the pickup token, and secrets, in memory only |
| Local fill page | The human's default browser, served by the binary on `127.0.0.1` | The secret, only while the page is open |
| Relay service | Cloudflare Worker with D1 | The request record, the ciphertext, and hashes of capabilities |
| Relay fill page | The human's phone or another browser | The public key and the plaintext, only while the page is open |
| Local HTTPS proxy (optional) | Inside the same `secrethandoff mcp` process, on `127.0.0.1` | Nothing extra. It uses the secrets that the process holds. |
| Remote gateway (later phase) | The user's own Cloudflare account | Secrets and the policies for proxy tokens |
| Claude Code mod (optional) | Inside Claude Code | The secret, only while the human types it (section 7.9) |

There is no background daemon in the first release. Secrets live as long as the agent session. If a later release needs sharing across sessions, it starts a daemon on demand, as `ssh-agent` does, and the daemon exits when idle.

### 4.3 Local mode flow

1. The agent calls the MCP tool `request_secret` with a name, a reason, and a use policy. The use policy names the hosts, paths, and methods that may receive the secret.
2. The binary creates a one-time local page token (256 random bits). It opens `http://127.0.0.1:<port>/fill#<token>` with the OS browser launcher. The URL never goes into a tool result.
3. The page shows the reason (labeled as text from the agent), the use policy, a masked input, and a QR code for relay phone mode.
4. The human pastes the secret and submits. The page sends the secret and the token to the binary over loopback.
5. The binary accepts the first valid submission only, then invalidates the token. Filling the form approves the use policy.
6. The tool result to the agent says only that the named secret is ready.
7. The agent calls a use action: `http_request`, `run_with_secret`, or a request through the proxy. The binary applies the secret inside the use policy. The agent receives only the result, with the secret value removed.

If the computer has no browser or display, the binary falls back to relay remote mode.

### 4.4 Relay phone mode flow

1. The binary creates a request key pair, a fill secret, and a pickup token. It keeps all three in memory only.
2. The binary sends the service a request record: the reason, the expiry, the policy hash, `SHA-256(fill proof)`, and `SHA-256(pickup token)`. The service returns a request ID.
3. The local page shows a QR code of `https://<host>/q/<id>#v1.<public key>.<fill secret>.<policy hash>` and the pairing code. The link never goes into a tool result.
4. The human scans the QR code. The phone page reads the fragment, removes it from the address bar, and shows the reason, the use policy, and the pairing code in large text next to the input.
5. The human checks that the code matches the local page, at a glance, and enters the secret. The page encrypts the secret to the public key and sends the ciphertext with the fill proof.
6. The binary polls the service with the pickup token. The service returns the ciphertext once, then deletes it with a conditional delete (ADR 0002).
7. The binary decrypts the ciphertext. The local page shows "filled from phone". The flow continues as in step 6 of section 4.3.

### 4.5 Relay remote mode flow

This mode is for an agent with no local screen, or for a second person.

1. The binary creates the request as in section 4.4, steps 1 and 2.
2. If the agent client supports MCP URL-mode elicitation, the binary sends the link through it, so the link does not enter the model context. Claude Code supports URL mode. Otherwise, the tool result contains the request link and the pairing code, and both are in the transcript (G8).
3. The human or the second person opens the link, checks the pairing code against the agent's output, and fills the request.
4. The fill page shows a fill confirmation code, computed from the ciphertext.
5. The binary picks up and decrypts the ciphertext. Before the first use, it asks the human to confirm the fill confirmation code (T-14). On a cloud agent, the confirmation comes from the human's reply in the agent client, or from a confirmation link on the relay page.

### 4.6 Protocol sketch

This section names candidate primitives. A cryptography review must confirm them before implementation.

- **Relay encryption.** HPKE (RFC 9180) base mode with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, and AES-256-GCM. Every target browser supports P-256 ECDH in Web Crypto. X25519 can replace P-256 in a later version with a new version tag.
- **Key pair lifetime.** One key pair for each relay request. The binary erases the private key after it decrypts the ciphertext, or when the request expires.
- **HPKE info string.** `secrethandoff sealed-request v1`.
- **Binding.** The HPKE info string holds the version, request ID, policy hash, and expiry time. Go's one-shot `Seal` takes no separate AAD, so the info string carries the binding (ADR 0010).
- **Fill proof.** `HKDF(fill secret, info = "fill-proof v1")`. The service stores only a hash, as with the access proof in ADR 0001.
- **Pickup token.** 256 random bits. The service stores only a hash. It is a separate capability, as with the receipt token in ADR 0003.
- **Pairing code.** `SHA-256("sh-pair v1" || public key)`, first 50 bits, shown as 10 Crockford base32 characters in two groups of five (ADR 0010).
- **Fill confirmation code (remote mode only).** `SHA-256("sh-fill v1" || request ID || ciphertext)`, cut to at least 32 bits.
- **Local page token.** 256 random bits in the URL fragment of the local page. One use only.
- **Expiry.** Short. The default is 10 minutes, and the maximum is 1 hour.

## 5. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | The plaintext secret | The main asset |
| A2 | The relay request private key | It decrypts A1 in relay mode |
| A3 | The pickup token | It lets the holder collect the ciphertext once. It does not decrypt the ciphertext. |
| A4 | The fill secret | It lets the holder submit a value for a relay request |
| A5 | The use policy | It limits where the secret goes |
| A6 | Proxy tokens for the remote gateway | They let the holder use a secret through the gateway |
| A7 | The per-session CA private key for the local proxy | It can issue certificates that the agent's commands trust |
| A8 | The integrity of delivered code: the binary and the relay fill page JavaScript | Malicious code can read A1 |
| A9 | The local page token | It lets the holder fill a local request |

## 6. Trust boundaries and adversaries

### 6.1 Trust boundaries

| ID | Boundary | Crosses it |
|---|---|---|
| B1 | Model and transcript ↔ binary | Tool calls and tool results. In remote mode, also the request link and the pairing code. |
| B2 | Binary ↔ local fill page, over loopback | The local page token and the secret |
| B3 | Binary ↔ relay service | The request record, hashes, and the ciphertext |
| B4 | Human's browser ↔ relay service | The relay fill page code, the ciphertext, and the fill proof |
| B5 | Agent's screen ↔ human's phone | The QR code and the pairing code |
| B6 | Agent's commands ↔ local proxy | Proxied HTTPS requests and responses |
| B7 | Cloud agent ↔ remote gateway | A proxy token and proxied requests |
| B8 | Marketplace or package manager ↔ user's computer | The binary and its updates |
| B9 | Claude Code mod ↔ binary | The secret, from the mod's input to the binary (section 7.9) |

### 6.2 Adversaries

| ID | Adversary | Capabilities |
|---|---|---|
| X1 | A manipulated or misaligned model | It can call any tool the agent has, including shell tools, as the same OS user. Prompt injection from a web page, file, or issue can drive it. |
| X2 | A transcript reader | It can read the chat transcript, session logs, or a shared screen, during or after the session |
| X3 | A phisher | It can send the human a valid relay link or QR code that it controls |
| X4 | A malicious or compromised operator | It controls the relay service, its database, and the JavaScript it serves |
| X5 | A network attacker | It can observe or change traffic outside TLS |
| X6 | An abuser | It uses the relay to send spam or phishing, or to exhaust resources |
| X7 | A supply-chain attacker | It can publish a changed binary, or a look-alike package, to a marketplace |
| X8 | A same-user local process | It runs as the same OS user as the binary |
| X9 | A malicious website | It runs JavaScript in the human's browser and can send requests to loopback addresses |
| X10 | Another local user | It has its own account on the same computer and can reach loopback ports |
| X11 | Another Claude Code plugin with function hooks | It can observe and change events that pass through the plugin chain |
| X12 | A browser that the agent controls | The agent client's own browser pane, or a browser extension that gives the agent page access in the human's browser (for example Claude in Chrome: `<all_urls>`, `scripting`, `debugger`). It can read and change any page there, including input fields |

## 7. Threats and mitigations

Each table lists the threat, the adversary, the goal at risk, the mitigation, and the residual risk. "Required" marks a mitigation that is a go/no-go gate in section 11. Threat IDs from revision 1 keep their numbers. Section 14 lists the changes.

### 7.1 Model and transcript (B1)

| ID | Threat | Adv. | Goal | Mitigation | Residual risk |
|---|---|---|---|---|---|
| T-01 | A tool returns the plaintext to the model, for example in a `get_secret` result or an error message. | X1 | G2 | Required: the binary has no tool or API that returns plaintext. Error text never contains the secret value. A test sends a known value through every tool and asserts that no output contains it. | None, if the test covers every tool and error path. |
| T-02 | The model writes a secret that `run_with_secret` released to a file, then reads the file with another tool. Output redaction does not see this. | X1 | G2 | Prefer `http_request` or the proxy (G7), where the agent never holds the value. For `run_with_secret`, put the secret in an environment variable or stdin, never in arguments, and ask the human to approve each command on the local page. | Accepted for `run_with_secret` (R-01). |
| T-03 | The model encodes the secret (base64, hex, split, encrypted) so that redaction misses it. | X1 | G2 | Redact the raw, base64, base64url, hex, and URL-encoded forms. Treat redaction as a defense against accidents only. | Accepted, as T-02. |
| T-04 | Prompt injection makes the agent request a high-value secret with a believable reason, for example "paste the production database password to fix the outage". | X1 | G2, G7 | Every fill page labels the reason as text from the agent. Every fill page shows the use policy (the hosts, paths, and methods that will receive the secret) next to the input. Filling the form approves that policy. There is no separate approval step. | The human makes the final decision (R-03). |
| T-05 | The model widens the use policy after the fill, for example by sending the secret to a new host. | X1 | G7 | The binary enforces the policy that the human saw at fill time. In relay mode, the policy hash is also in the request link and the HPKE info string. A policy change needs a new request and a new fill. | None. |
| T-06 | A relay request link in the transcript gives a transcript reader something of value. | X2 | G8 | In local and relay phone modes, the link never enters a tool result. In relay remote mode, the link holds only the public key, the fill secret, and the policy hash. None of these decrypts anything. The pickup token never appears in a link, a tool result, stdout, or stderr. | In remote mode, the link lets its holder fill the request (T-14). |

### 7.2 Human, phone, and phishing (B5)

| ID | Threat | Adv. | Goal | Mitigation | Residual risk |
|---|---|---|---|---|---|
| T-07 | A phisher sends the human a valid relay link or QR code that encrypts to the phisher's key. The service domain makes the request look trusted. | X3 | G4 | Required: every relay fill page shows the pairing code in large text next to the input, with the text "Continue only if your own computer shows this code." The code comes from the public key in the fragment. A phisher cannot make it match the human's own agent (T-19). The human compares at a glance. No typing is needed. | A human who does not look, or who has no request open and trusts the message. The short expiry and the page text reduce this. |
| T-08 | The phisher includes a pairing code in the message, so the human compares against the message and not against their own agent. | X3 | G4 | The page text names the source: "the code on your own computer". The local page and the agent output are the only places that show the code for a request. | Social engineering stays possible, as with number matching in MFA push approval. |
| T-09 | A QR code on a shared or recorded screen exposes the request. | X2 | G8 | The QR code holds only the relay request link. Exposure gives no secret. Do not add QR codes to the existing one-time share links, because those links are the secret. | The viewer can fill the request before the human. The local page then shows "filled from another device" (T-42). |
| T-10 | A shoulder-surfer or a screen recording sees the secret while the human types it. | X2 | G1 | Every fill page uses a masked input with a reveal control and clears the field after submit. | Accepted. The human controls their own screen. The mod has no masked input (T-47). |
| T-11 | A link-preview scanner or a crawler opens a relay link and changes state. | X6 | G6 | Page loads never change state. Fill needs an explicit POST with the fill proof. The fragment never reaches the server. | None. |

### 7.3 Relay service and operator (B3, B4)

| ID | Threat | Adv. | Goal | Mitigation | Residual risk |
|---|---|---|---|---|---|
| T-12 | The service substitutes its own public key, so the human encrypts to the operator. | X4 | G3, G4 | The public key comes from the URL fragment, never from the service. A substituted key gives different pairing code. | None. |
| T-13 | The operator serves changed relay fill page JavaScript that copies the plaintext before encryption. | X4, X7 | G1, G3 | Applies to relay mode only. The local page comes from the signed binary. For relay pages: a strict CSP, no third-party scripts except Cloudflare's Turnstile script (Cloudflare already hosts the service, so this adds little trust), Subresource Integrity, reproducible builds with published hashes, and a fill option from the CLI. State this limit on the security page. | Accepted for relay mode (R-02). |
| T-14 | In relay remote mode, an attacker with the request link fills the request first, with a value they choose. The agent then uses the attacker's value. For example, it uploads data to an account the attacker controls. | X2, X3 | G5 | Required in remote mode: the fill page shows a fill confirmation code after submit. The binary shows the same code and waits for the human to confirm it before the first use. Only one fill is allowed, so a human who arrives second sees "already filled". Not needed in local and relay phone modes, because the link never leaves the human's screen. | A human who confirms without comparing the codes. |
| T-15 | The operator replays an old ciphertext, or moves a ciphertext from another request. | X4 | G3, G5 | Each request has its own key pair. The HPKE info string binds the request ID, policy hash, and expiry. | None. |
| T-16 | The operator or the database keeps ciphertext after pickup or expiry. | X4 | G6 | Conditional delete on pickup. Scheduled cleanup of expired requests. An integration test in CI asserts that no ciphertext remains. | A malicious operator can copy ciphertext. It still cannot decrypt it (G3). |
| T-17 | Two pickup calls run at the same time and both get the ciphertext. | X1, X8 | G6 | Conditional delete with exactly one winner, and a concurrency test in CI. | None. |
| T-18 | Logs or traces record request bodies, capability values, or link fragments. | X4 | G1, G8 | ADR 0007 settings. Never log request bodies, capability values, or proofs. | Metadata stays visible to the operator (R-06). |

### 7.4 Cryptography

| ID | Threat | Adv. | Goal | Mitigation | Residual risk |
|---|---|---|---|---|---|
| T-19 | An attacker who reads the pairing code in a remote-mode transcript searches for a key pair whose code matches, then phishes with that key. | X2, X3 | G4 | Required: 65 bits in the pairing code (ADR 0010), and a request lifetime of 1 hour or less. A search of 2^65 key pairs in one hour needs about 10^16 key generations per second, far beyond a GPU farm. The first draft used 50 bits, which the internal review showed was within reach of 30 to 300 GPUs. In local and relay phone modes, the code never enters the transcript. | Low, while the bit count and expiry hold. |
| T-20 | Nonce reuse or a weak random source. | — | G3 | HPKE derives a fresh key and nonce for each message. Use only `crypto.getRandomValues` and the OS random source. | None, if the HPKE library is correct. |
| T-21 | Version downgrade: an attacker changes `v1` in the fragment to an older or weaker format. | X3 | G3, G4 | The version tag is in the HPKE info string and the HPKE info string. Clients accept only versions on a fixed allow list. | None. |
| T-22 | The HPKE implementation in the page or the binary has a defect. | X7 | G3 | Use reviewed HPKE implementations, and run the RFC 9180 test vectors in CI for both the page and the binary. | A cryptography review is still required. |

### 7.5 Local binary, local page, and local proxy (B2, B6)

| ID | Threat | Adv. | Goal | Mitigation | Residual risk |
|---|---|---|---|---|---|
| T-23 | A same-user process reads the private key or a secret from disk. | X1, X8 | G3, G7 | Keep the private key, tokens, the CA key, and secrets in memory only. Never write them to disk. Erase them on use, expiry, or exit. Disable core dumps for the process. | The OS can still write memory to swap. |
| T-24 | A same-user process reads the binary's memory or attaches a debugger. | X1, X8 | G7 | On macOS, sign with Developer ID and use the hardened runtime without the `get-task-allow` entitlement. On Linux, set the process as not dumpable. Offer an optional hardened mode that runs the binary as a separate OS user. The hardened mode is not part of normal setup (G9). | Same-user mode is defense in depth, not a hard boundary (R-05). |
| T-25 | The model asks the binary to export a secret or to change a policy. | X1 | G7 | The binary has no export call. Policy changes need a new request and a new fill by the human. | None for export. |
| T-26 | The proxy or `http_request` sends the credential to the wrong host, through a redirect, a DNS rebind, or a Host header that does not match SNI. | X1 | G7 | Match on the TLS SNI and the Host header after TLS termination, with exact host names by default. Remove the credential on any redirect to another host. Do not follow redirects across hosts. | None. |
| T-27 | An allowed host reflects request headers in its response, so the credential returns to the agent. | X1 | G7 | Remove the injected value from responses in all encodings from T-03. Block known echo services. Warn when a policy names a host that reflects headers. | A host that transforms and returns the credential. Keep policies narrow. |
| T-28 | The agent uses the credential for any action that the key allows on the allowed host. | X1 | G7 | Policies support paths and methods. Advise users to create keys with the smallest scope and a short life. | Accepted (R-04). |
| T-29 | The proxy CA key leaks, or the CA is trusted by the whole system. | X1, X8 | A7 | Create the CA in memory for each session. Write only the CA certificate, never its key, to a temporary file for agent commands (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`). Never install it in the system trust store. Use X.509 name constraints so it can sign only the hosts in active policies. | Low, because of the name constraints. |
| T-30 | The model bypasses the proxy. | X1 | — | A bypass sends the request without the credential. This reveals nothing. | None. |
| T-42 | The model or a same-user process fills the local page before the human, with a value it chooses. | X1, X8 | G5 | Required: the binary opens the page with the OS browser launcher. The token never enters a tool result, stdout, or stderr. Each token works once. The page shows live status. If the page says "filled" and the human did not fill it, the human selects "This was not me", and the binary discards the value and stops the request. | A same-user process that reads the launcher arguments or browser history in the short time before the human acts. The human sees the conflict (R-05). |
| T-43 | A malicious website in the human's browser sends requests to the loopback server: cross-site request forgery, DNS rebinding, or reading responses. | X9 | G1, G5 | Required: bind to `127.0.0.1` only, on a port that the OS picks. On Windows the listener sets `SO_EXCLUSIVEADDRUSE`, so another program cannot bind the same port with `SO_REUSEADDR` and take its connections. Reject any request whose Host header is not `127.0.0.1:<port>`. Reject POST requests whose Origin is not the local page. Reject `Sec-Fetch-Site: cross-site`. Send no CORS headers. Require the token on every call. Use a strict CSP on the local page. | None, if the tests cover each check. |
| T-44 | Another local user connects to the loopback ports and uses the page or the proxy. | X10 | G3, G7 | The page needs the token. The proxy needs a random proxy credential for each session, given to agent commands in the proxy URL. Without it, the proxy refuses the request. | None. |
| T-53 | The human pastes a secret into the chat instead of using a fill page. | X2 | G2 | Required for Claude Code: a `UserPromptSubmit` hook blocks a prompt that contains a likely secret, so the model never receives it. The block message tells the human that the secret is still in the local session history and to replace it if it matters. Guidance layers 1 to 4 steer the agent to `request_secret`. | The agent client saves the text to disk before the hook runs (R-07). Clients without hooks send the text to the model. |
| T-45 | The computer has no display, or the browser launcher fails, so the binary prints the local URL as a fallback. | X1, X2 | G5, G8 | Never print a local page token. Without a display, switch to relay remote mode, which has the controls for a link in the transcript (T-14, T-19). | Remote-mode residual risks apply. |
| T-52 | `run_with_secret` starts commands from the MCP process, which runs outside the agent client's sandbox. The model can use it to run a command that the sandbox would block. | X1 | — | Required: the local page shows the full argument vector, the working directory, and the secret names, and the human approves each command. No shell is used, so there is no expansion or chaining. Approval cannot be remembered for later commands. | A human who approves a harmful command. |

### 7.6 Remote injection gateway (B7), later phase

| ID | Threat | Adv. | Goal | Mitigation | Residual risk |
|---|---|---|---|---|---|
| T-31 | A proxy token leaks from the cloud agent's VM or transcript. | X1, X2 | G8 | Required: each token is scoped to policy hosts, paths, and methods. It expires in hours or less. The user can revoke it, and it is shown in the gateway log. | The attacker can use the token within its scope until expiry or revocation. |
| T-32 | The service operator hosts the gateway and so sees secrets. | X4 | G1 | The gateway is a template that the user deploys in their own Cloudflare account. The operator never hosts gateway secrets. A hosted gateway needs a new ADR, because it breaks G1. | None while the user self-hosts. |
| T-33 | The agent uses the gateway to reach internal hosts (server-side request forgery). | X1 | — | The gateway forwards only to hosts on the token's allow list. It refuses private, link-local, and metadata IP ranges. | None. |
| T-34 | The gateway decrypts the secret, so it is a high-value target. | — | G7 | This is the intended design for cloud agents. The agent receives only a proxy token. | The gateway's Cloudflare account becomes a high-value target. |

### 7.7 Relay abuse and availability

| ID | Threat | Adv. | Goal | Mitigation | Residual risk |
|---|---|---|---|---|---|
| T-35 | The binary cannot pass Turnstile, so relay request creation needs a new path that abusers can also use. | X6 | — | Required: separate limits for request creation, per IP and global. Use a small proof of work, or optional free API keys. Keep a separate emergency kill switch for requests. Keep Turnstile on the relay fill page. A terminal fill (`secrethandoff fill`) sends a proof of work instead, and every fill needs the fill proof (ADR 0010). | Some abuse within the limits. |
| T-36 | The relay becomes a phishing platform: attacker-written reasons on a trusted domain. | X3, X6 | G4 | Show the reason as plain text, with a length limit, no links, no HTML, and a label "written by the requester". The pairing code (T-07) block the result even when the human believes the text. Add a "report this request" control. | Reputation risk for the domain. |
| T-37 | Pickup polling overloads the service, or an attacker floods pickup calls. | X6 | — | Poll with backoff, a minimum interval, and a rate limit per request. A wrong pickup token never reveals whether the request exists. | None. |
| T-38 | Online guessing of a passphrase or a capability, with no attempt limit. | X6 | G6 | Done for consume, receipt, and burn by ADR 0008: 10 wrong proofs destroy a secret, and each address has 30 failures per hour. Relay fill and pickup count wrong values per address only, because their capabilities have 256 bits and a per-request lock would let a stranger destroy a request (ADR 0010). | None after the fix. |

### 7.8 Distribution and supply chain (B8)

| ID | Threat | Adv. | Goal | Mitigation | Residual risk |
|---|---|---|---|---|---|
| T-39 | A changed release of the binary steals secrets. | X7 | G1–G9 | Required: GitHub build provenance attestations and checksums for every release. Plugin and MCP manifests pin exact versions and checksums. macOS releases are signed with Developer ID and notarized (plan decision D-13). Keep dependencies few, as in `shareout/packages/cli-go`. | Compromise of the CI release workflow or the repository. Protect them with branch protection, required reviews for workflow changes, and hardware keys on the maintainer account. |
| T-40 | A look-alike package or MCP registry entry uses the product name. | X7 | — | Claim the names in each marketplace and package manager. Use domain-ownership proofs for the MCP Registry. Link the official entries from the security page. | Users who install from an unlisted source. |
| T-41 | An automatic update ships a defect. | X7 | G1–G9 | Staged releases. Package managers verify checksums. The binary never updates itself. | Normal release risk. |

### 7.9 Claude Code mod (B9), optional

The mod shows the fill form inside Claude Code instead of in a browser. It is a different way to show the form. It does not replace the binary, which still holds and uses the secret. Other agent clients use the local page.

| ID | Threat | Adv. | Goal | Mitigation | Residual risk |
|---|---|---|---|---|---|
| T-46 | The model triggers the mod's fill action itself and submits a value it chooses. | X1 | G5 | The mod submits only on a human button press (`ui.press`), never from a tool call. The mod registers no tool that submits a value. | None. |
| T-47 | The mod's `Input` element has no masked mode, so the secret shows on screen while the human types it. | X2 | G1 | Clear the field at once after submit. Offer the local page as the masked alternative. | Accepted while the plugin API has no masked input. |
| T-48 | Another plugin with function hooks reads the value through `ui.input`, `process.spawn`, or `http.fetch` events. | X11 | G1, G2 | Required: at start, the mod checks whether any other loaded plugin hooks these events. If one does, the mod does not show the form and uses the local page instead. | Checked 2026-10-07: the API has no list of other plugins' hooks, and `ui.input` hooks of any plugin see each keystroke. The mitigation cannot work. The mod does not ship ([mod check](../plans/claude-code-mod-check.md)). |
| T-49 | Claude Code writes the `Input` value to the transcript, the debug log, or crash reports. | — | G2 | Required: a test enters a known value in the mod with debug logging on, then searches the transcript, the debug log, and all session files for it. | Not tested, because T-48 and T-50 fail and the mod does not ship. |
| T-50 | The mod sends the value to the binary over a channel that the model can also use, such as the loopback page. | X1, X8 | G5 | The mod starts its own child binary with `$.process.spawn` and writes the value to the child's stdin, a private pipe. If `$.process` is not available, the mod uses the local page. | Checked 2026-10-07: `$.process` is in the core API, but the `process.run` and `process.spawn` events give the stdin text to other plugins' hooks. Stdin is not private. The mod does not ship. |
| T-51 | A mod pane opened without a human action cannot show, so the request waits. | — | — | Open the pane from the tool's result handler. If the pane cannot show, fall back to the local page. | Availability, not security. |

### 7.10 Browsers that the agent controls

| ID | Threat | Adv. | Goal | Mitigation | Residual risk |
|---|---|---|---|---|---|
| T-54 | The fill page opens in the agent client's own browser pane, where the agent can read the field or fill it. | X1, X12 | G1, G5 | The binary opens pages only with the OS launcher, which never uses an agent client's pane. The page and the server refuse the Claude desktop browser pane (its user agent has `Claude/<version>` beside `Chrome/`): the server answers 403 to every page API call before the request is claimed, and the page says why. | A pane with a user agent that the check does not know. The Codex app's browser label was not confirmed for loopback pages. |
| T-55 | An AI browser extension in the human's browser reads the secret from the fill page, or reads the page token and fills the page first. | X1, X12 | G1, G5 | Decided 2026-10-08: by default the binary opens each page in a separate window of an installed Chrome, Edge, Brave, or Chromium, with a temporary profile for the session: `--disable-extensions`, no sync, and on macOS no keychain access. The window is a normal one, so the address bar shows 127.0.0.1. The binary closes it and deletes the profile when the session ends. The page says when it is in this window. `SECRETHANDOFF_ISOLATED_BROWSER=0` turns it off. | With no Chromium-family browser, or with the opt-out, the page opens in the default browser, where an extension can read it (R-08). An extension that an organization policy forces into every profile. |

### 7.11 Request cards in the chat

The Claude Code mod card and the MCP App card show a request in the chat. Neither takes input: the secret is typed only on the local page.

| ID | Threat | Adv. | Goal | Mitigation | Residual risk |
|---|---|---|---|---|---|
| T-56 | The agent client, the MCP Apps host, or another plugin reads or changes what a card shows. | X11, X4 | G1 | A card shows only the tool call's arguments and result text, which the agent client already has. It has no input field and makes no requests: the MCP App card declares no CSP domains, and a test fails if its HTML has an input, a text area, or a network call. In remote mode it shows the pairing code, not the link. | A changed card can show a wrong status. The local page stays the authority. |

## 8. Accepted residual risks

These risks stay after all required mitigations. A release must state them on the security page.

| ID | Risk | Why it is accepted |
|---|---|---|
| R-01 | A model with shell access can leak a secret that `run_with_secret` released into a process (T-02, T-03). | No tool can stop this while the model holds the value. `http_request` and the proxy avoid it for HTTPS APIs. |
| R-02 | In relay mode, malicious fill page JavaScript from a compromised operator or deploy can read the plaintext (T-13). | This is the limit of all browser-delivered encryption. Local mode and the CLI fill avoid it. |
| R-03 | A human can approve a broad policy, or skip the pairing code or the fill confirmation code (T-04, T-07, T-14). | The human is the authority. The design makes the safe action the easy action, but it cannot force judgment. |
| R-04 | An allowed request through `http_request` or the proxy can do anything the key allows (T-28). | The binary enforces where the secret goes, not what each request means. Narrow keys limit the impact. |
| R-05 | Same-user isolation is defense in depth. A same-user process can try to fill the local page first or read process memory (T-24, T-42). | Normal setup needs no administrator rights (G9). The human sees a fill conflict. The hardened mode gives a stronger boundary. |
| R-07 | A secret that the human pastes into the chat is saved in the agent client's local session history before any hook can block it (T-53). | The client writes the text before hooks run. The hook can only keep it from the model and tell the human. |
| R-06 | The relay operator sees metadata: times, sizes, and IP addresses. | No accounts, short retention, and ADR 0007 log settings limit it. Local mode sends nothing. |
| R-08 | When the isolated window is not used (no Chromium-family browser, or the opt-out), an AI browser extension with access to all sites can read the local fill page (T-55). | The page cannot detect or block an extension. The isolated window is the default wherever it can run. |

## 9. Security claims

Public text, marketplace listings, and tool descriptions may make only these claims.

### Allowed

- "In local mode, your secret never leaves your computer."
- "When you use a phone or a remote agent, the secret is encrypted on your device. Our servers never see it."
- "The secret never enters the chat, the transcript, or the AI model's context."
- "No account. Nothing stored. Secrets end with your agent session."
- "Through `http_request` or the proxy, the AI agent can call an API without ever holding the key."
- "Normal setup needs no administrator rights on macOS, Windows, or Linux."

### Not allowed

- "The AI cannot misuse your secret." This is false for `run_with_secret` (R-01) and for allowed requests (R-04).
- "Zero trust" or "unhackable". These words make no testable claim.
- Any claim that the gateway is end to end encrypted. The gateway decrypts the secret by design (T-34).

## 10. New invariants

Add these to `AGENTS.md` when the feature is accepted.

- The binary never returns plaintext to a model, a tool result, stdout, stderr, a log, or an error message.
- The binary never writes a local page token, a pickup token, or the request link for local or phone mode to a tool result, stdout, or stderr.
- Secrets, private keys, tokens, and the proxy CA key stay in memory only.
- The local server binds to `127.0.0.1` only and checks the token, the Host header, and the Origin on every request.
- The relay request public key comes only from the URL fragment. The service never serves it.
- Every fill page shows the use policy and labels the reason as text from the agent. Relay fill pages show the pairing code.
- The binary enforces the use policy that the human saw at fill time.
- Normal setup needs no administrator rights, no system service, and no change to the system trust store.
- Fill, pickup, and consume endpoints have attempt limits.
- The operator never hosts the remote gateway or any secret for it.

## 11. Go/no-go gates

The feature ships in phases. Each phase ships only when its gates pass. Each phase also needs the gates of earlier phases.

### Phase 1: local mode

| Gate | Condition | Threats |
|---|---|---|
| GG-01 | A test sends a known value through every tool, error path, stdout, stderr, and redaction encoding, and asserts that no output contains it. A test shows that `run_with_secret` refuses to run without approval on the local page. | T-01, T-03, T-06, T-27, T-52 |
| GG-02 | Tests for the loopback server cover the Host check, the Origin check, `Sec-Fetch-Site`, missing CORS headers, one-time tokens, and the "This was not me" control. | T-42, T-43, T-44 |
| GG-03 | `http_request` and the proxy pass tests for exact host matching, cross-host redirects, header reflection, the proxy credential, and a CA with name constraints that is not in the system trust store. | T-26, T-27, T-29, T-44 |
| GG-04 | Install and first use need no administrator rights on macOS, Windows, and Linux. | G9 |
| GG-05 | Releases have build provenance attestations and checksums, and `gh attestation verify` succeeds for each archive. Manifests pin versions and checksums. | T-39, T-41 |
| GG-06 | The security page states the residual risks that apply to local mode and uses only the claims in section 9. | All |

### Phase 2: relay phone mode

| Gate | Condition | Threats |
|---|---|---|
| GG-07 | The current service has attempt limits on `/consume` (done by ADR 0008), and the concurrency, burn, and attempt-limit integration test runs in CI. ADR 0008 keeps short passphrases, so no minimum length is required. | T-17, T-38 |
| GG-08 | An ADR accepts the relay trust boundaries, the cryptographic format, and the capability set. ADR 0001 and ADR 0003 are updated or superseded. | All relay threats |
| GG-09 | The pairing code has 65 bits, shows on every relay fill page, and a test shows that a different key gives a different code. | T-07, T-12, T-19 |
| GG-10 | RFC 9180 test vectors pass in CI for both the page and the binary. | T-20, T-22 |
| GG-11 | Request creation has its own limits and kill switch. Relay fill pages keep Turnstile. | T-35, T-36, T-37 |
| GG-12 | An independent reviewer has reviewed the protocol and the cryptography, and every High or Critical finding is closed. | T-19 – T-22 |

### Phase 3: relay remote mode and the gateway

| Gate | Condition | Threats |
|---|---|---|
| GG-13 | The fill confirmation code works in remote mode, and a test shows that the binary refuses to use an unconfirmed fill. | T-14 |
| GG-14 | Gateway tokens have scope, expiry, revocation, and an IP range block list, with tests. | T-31, T-33 |

### Claude Code mod

| Gate | Condition | Threats |
|---|---|---|
| GG-15 | The transcript and debug log test (T-49) passes, the plugin hook check (T-48) works, and `$.process` works in the desktop app (T-50). If any of these fails, the mod does not ship. **Failed 2026-10-07 on T-48 and T-50** ([mod check](../plans/claude-code-mod-check.md)). | T-46 – T-50 |

## 12. Open questions

1. **Which agent clients support MCP URL-mode elicitation?** Claude Code 2.1.289 declares URL mode ([client matrix](../plans/client-matrix.md)). Codex is not yet recorded. In local mode, the binary opens the browser itself, so URL mode is not needed.
2. **Is the CLI fill path in phase 2?** It answers T-13 for users who distrust the operator.
3. **Is proof of work enough for relay request creation, or are API keys necessary?**
4. **Answered for Claude Code and Codex.** Inline `VAR=value` works in both. Codex blocks agent commands from loopback unless `sandbox_workspace_write.network_access = true`, and Codex reads `SSL_CERT_FILE` for its own connections. See the [client matrix](../plans/client-matrix.md).
5. **How does each OS browser launcher expose its arguments?** This sets the T-42 exposure window on macOS (`open`), Windows (`ShellExecute`), and Linux (`xdg-open`).
6. **Answered: no.** Claude Code 2.1.289 has no call that lists other plugins' hooks ([mod check](../plans/claude-code-mod-check.md)).
7. **Can the gateway template reuse the HPKE code without copying it?** Shared code belongs in one package.

## 13. References

- RFC 9180, Hybrid Public Key Encryption: https://www.rfc-editor.org/rfc/rfc9180
- MCP specification 2025-11-25, elicitation and URL mode: https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation
- Claude Code cloud environments, API credentials added by the agent proxy: https://code.claude.com/docs/en/cloud-environments
- `docs/adr/0001` to `0007` in this repository

## 14. Revision history

### Revision 2.1 (2026-10-08): agent-controlled browsers and request cards

- New adversary X12, a browser that the agent controls, with threats T-54 and T-55 and residual risk R-08. T-55 is mitigated by an isolated browser window, on by default.
- New threat T-56 for the in-chat request cards (Claude Code mod card and MCP App card). The cards take no input.
- The Claude Code mod no longer shows a fill form (gate GG-15 failed). Section 7.9 stays as the record of why.
- T-43: the Windows listeners are exclusive.

### Revision 2 (2026-10-07): local-first design

- Local mode is the default. The binary serves the fill page on loopback, and nothing goes to the service. The service is now a relay for phone, remote, and second-person cases.
- One Go binary for all platforms. The agent client starts it with the session. There is no daemon and no system service in the first release (G9).
- T-04: policy approval moved to the fill page. Filling approves the policy. The separate approval step is removed.
- T-07: the human compares the pairing code at a glance. Typing is no longer required.
- T-14: the fill confirmation code is required only in relay remote mode.
- T-24: the separate-user install is an optional hardened mode, not part of normal setup.
- T-25, T-29: approvals happen on the local page, not through OS prompts. The proxy CA is created in memory for each session.
- New threats T-42 to T-53 for the local page, the loopback server, headless fallback, the Claude Code mod, and commands that run outside the agent sandbox, and secrets pasted into the chat (with residual risk R-07).
- The `secrethandoff run` shell command is removed. The MCP tool `run_with_secret` replaces it.
- Gates split into phases, so that local mode can ship before the relay changes.

### Revision 1 (2026-10-07)

- First draft. The service relayed every request, and the request link was in the transcript in all cases.
