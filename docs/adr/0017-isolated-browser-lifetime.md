# ADR 0017: Isolated browser reuse and lifetime

- Status: Accepted for local implementation
- Date: 2026-10-21
- Extends ADR 0009 and ADR 0012; supersedes session-end-only profile cleanup

## Context

Forcing a new window for every request creates clutter. On macOS a browser
can remain running after all its windows close. Temporary profiles also start
with Chrome's password-saving offer enabled, despite autocomplete being off.

## Decision

Keep one temporary Chromium profile per MCP process. New requests open tabs in
that profile's existing window; never share profiles between agent sessions or
reuse the owner's normal profile. Keep extensions and sync disabled, retain
the visible address bar and macOS mock keychain, and use incognito mode to avoid
persisting handoff tab history or restoring tabs. Write only fixed password
manager preferences into the private temporary profile before launch: saving
and automatic sign-in are disabled. No URL, token, or secret is written there
by the binary. These preferences never modify the owner's browser settings.

Each local page keeps an authenticated WebSocket open to the loopback server.
The existing request token is offered as a WebSocket subprotocol in a request
header, never in the connection URL. Only the fixed presence protocol is
negotiated back. Require an exact Host and Origin, existing token lookup, the
fetch-site check, and the agent-browser refusal before accepting a connection.
The socket accepts no application messages and grants no claim or approval.
It carries no secret value and does not change the request state machine.
WebSockets avoid exhausting HTTP/1's per-origin connection limit across tabs.

When the last page disconnects, allow 30 seconds for reload or reconnection,
then stop only the browser processes launched by this MCP process and delete
their temporary profile after reaping them. A new launch or page connection
invalidates an older cleanup timer. A launch whose page never connects is
also retired after this grace period. Session shutdown, including interrupt
and SIGTERM, still closes the browser immediately. Uncatchable termination
cannot guarantee cleanup. Default-browser opt-outs are never terminated.

## Consequences

Closing the last Secret Handoff tab retires the isolated browser, including
other tabs manually opened within that disposable instance. Closing a window
does not forget secrets already held in MCP memory or change pending requests.
A later new request starts a fresh profile. A connection outage lasting longer
than the grace period can retire a still-visible isolated window; brief reloads
and reconnects preserve it. Background tabs keep the connection without relying
on JavaScript heartbeat timers. No browser automation or debugging port is used.

Validate multiple tabs, final-state pages, reload/reconnect, invalid credentials,
origin/Host refusal, no token echo, stopped-timer races, new profiles after
retirement, launcher failure, real process reaping, and value-free leak tests.
