# Codex command approval check

> Update: ADR 0014 supersedes the fresh-human-click requirement for owner-selected Codex mode. The earlier investigation below remains historical. See the new acceptance section at the end.

- Date: 2026-10-09
- Installed runtime: `codex-cli 0.155.1`
- Source examined: OpenAI Codex tag `rust-v0.155.1`
- Result: no verified human-only approval adapter for our local stdio plugin.
  Keep the browser gate. No command approval button was added.

## Ordinary approvals

Codex exposes server and per-tool `approval_mode` settings, including `prompt`.
These settings do not force a human decision: automatic review and
`PermissionRequest` hooks can authorize an operation without a user prompt.
Tool annotations guide host behavior; they do not replace server authorization.
An app-only approval tool would also not prove a human gesture.

The installed version's `codex-mcp/src/elicitation.rs` confirms another unsafe
shortcut: an ordinary MCP confirmation form with no schema properties can be
automatically accepted by `can_auto_accept_elicitation`. A card button or form
acceptance must not replace our browser approval grant.

## Biometric verification exists, but excludes this plugin

The generated app-server protocol includes `openai/userVerification` elicitation
and local `userVerification/status`, `enroll`, `verify`, and `delete` methods.
The proof contains a credential identifier and a P-256 signature over the exact
challenge. This is a distinct mechanism, not ordinary confirmation elicitation.

The source establishes two prerequisites for MCP access:

1. Trusted host activation enables the `openai/elicitation` extension's
   `userVerification` route (`codex-mcp/src/elicitation.rs`, `make_sender`).
2. `codex-mcp/src/user_verification_elicitation.rs`, `route`, requires
   `is_host_owned_apps`. Otherwise it returns `Cancel` without proof content.

`codex-mcp/src/catalog.rs`, `McpServerSource::is_host_owned_apps`, requires the
runtime's reserved apps server, a local execution environment, and a
`Compatibility` registration or an explicitly host-owned `Extension`.
`Plugin`, `SelectedPlugin`, and `Config` registrations do not qualify. Changing
our server's name cannot change its registration authority. Secret Handoff is
a local stdio plugin and does not meet this check.

This restriction is decisive even if the owner enrolls a biometric credential.
Do not enroll one, imitate the reserved server, or switch to hosted delivery to
work around the check. The current distribution and trust boundary remain the
ones accepted in ADR 0009 and ADR 0013.

## Local checks and limits

- Generated the installed runtime's experimental TypeScript protocol with
  `codex app-server generate-ts --experimental --out <temporary-directory>`.
- Queried only `userVerification/status` through an initialized, temporary
  stdio app-server. It reported `credentialMissing`. The credential identifier
  was not printed. No enrollment, signing, biometric prompt, agent turn,
  command execution, or approval acceptance was attempted.
- Examined the matching tagged source's route and catalog predicates above.
  This is source evidence for local-plugin exclusion, not a live desktop
  rendering or approve/deny test.
- The public MCP extension specification and SDK documentation reviewed here
  do not publish a supported third-party verification adapter.
- No binary approval behavior or global Codex approval configuration changed.

## Claude plugin refresh

Reinstalled `secrethandoff@secrethandoff` with the Claude CLI's uninstall/install
commands. Verified its cached `hooks/card.tsx`, `assets/icon.svg`, skill, and
`.mcp.json` against the local integrations source; the plugin is enabled.
Start a fresh Claude session to load it. The shared installed binary was already
updated in this chat.

Reran `scripts/check_claude_approval.py`. Its harmless control again stopped on
unavailable authentication; no probe invocation or permission denial occurred.
This is inconclusive about native approval. Reauthenticate through Claude's own
flow before the probe and interactive dummy-value acceptance check. Leave native
command approval off until those checks pass.

After the owner subsequently completed `claude auth login`, the same automated
probe passed the control and all three flagged-tool denial cases on Claude Code
2.1.284. See [the updated host check](host-command-approval-check.md) for the
results and owner-run interactive test. The owner later reported that the test
worked and supplied a screenshot verifying the native Deny / Allow once prompt.
The installed plugin still defaults to browser approval. This Claude evidence
does not change the Codex local-plugin exclusion described above.

## Revisit when

Codex exposes verification to local plugin registrations, or documents another
per-call human gate that cannot be satisfied by automatic approval, hooks, a
remembered grant, or agent-supplied input. Before an adapter is enabled, validate
the exact command, absolute folder, secret bindings, timeout, one-time grant,
decline/cancel, concurrent calls, and redacted results. Keep secret entry in the
isolated browser.

## Sources

- [Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
- [Codex approval reviewers](https://learn.chatgpt.com/docs/config-file/config-reference)
- [PermissionRequest hooks](https://learn.chatgpt.com/docs/hooks#permissionrequest)
- [MCP server authorization requirements](https://developers.openai.com/plugins/build/mcp-server)
- [OpenAI MCP extensions specification](https://github.com/openai/mcp-extensions/blob/main/docs/spec.md)
- [Versioned elicitation routing](https://github.com/openai/codex/blob/rust-v0.155.1/codex-rs/codex-mcp/src/elicitation.rs)
- [Versioned verification route](https://github.com/openai/codex/blob/rust-v0.155.1/codex-rs/codex-mcp/src/user_verification_elicitation.rs)
- [Versioned registration authority](https://github.com/openai/codex/blob/rust-v0.155.1/codex-rs/codex-mcp/src/catalog.rs)
- [Versioned proof transport validation](https://github.com/openai/codex/blob/rust-v0.155.1/codex-rs/rmcp-client/src/user_verification.rs)

## Owner-policy opt-in acceptance, 2026-10-09

The owner explicitly accepted automatic authorization through their own settings.
ADR 0014 enables `SECRETHANDOFF_COMMAND_APPROVAL=codex` for `codex-mcp-client`
0.155.1 and later patches in the 0.155 series, with a clean absolute directory.
It does not use `openai/userVerification`, generic elicitation, or card buttons.
Native approval belongs to Codex and can be satisfied by the owner's policy.

The harmless live CLI probe (`scripts/check_codex_approval.py` in integrations)
passed on Codex 0.155.1:

| Owner tool policy | CLI approval policy | Delivered tools/call | Host denial |
| --- | --- | --- | --- |
| approve | never | Yes | No |
| prompt | never | No | Yes |

The probe used no secret, executed no command, and disabled other MCP servers,
plugins, and hooks only in its child invocation. It captured only public client
name/version and delivery markers. Both calls used the real host's policy path;
the denied call did not reach the mock. This verifies allow/deny delivery, not
human prompt rendering, a hook's correctness, or execution in the desktop app.

Go vet, race and binary leak tests passed in all three modes. Complete execution
results cover success, nonzero exit, timeout, truncation, and startup failure in
Codex mode. Browser fallback includes unset/unknown mode, wrong client, old/future
version, prerelease version, and implicit/relative/noncanonical directory. An
agent-supplied approval argument is rejected. Browser grants remain single-use.
Lint, TypeScript, production tests, fresh-D1 security integration, offline plugin
validation, and both card logic suites passed.

Reload uses `codex plugin add secrethandoff@secrethandoff`, then the owner-authorized
`configure_codex_approval.py codex --plugin-dir <installed-cache>` helper. The
cached launch files get only `SECRETHANDOFF_COMMAND_APPROVAL=codex`; approval settings,
reviewer, and hooks stay unchanged. Reinstallation resets that cached opt-in.
The installed-plugin launch check also passed: a temporary PATH wrapper recorded
only the nonsecret startup mode `codex`, delegated to the installed binary, and
the real plugin completed `list_secrets` in a new empty session. The initial check
caught that Codex loads Agent Plugins from `mcp.json`, not the legacy `.mcp.json`.
The helper now validates and configures both before writing either. Four helper
tests cover preserving unrelated entries, restoring browser mode, and refusing
unexpected launchers, alternate manifest paths, and symlinks. Neither launch
check requested a secret or executed a secret-bearing command.

Start a fresh desktop chat for the owner dummy test below. The old MCP process
in this chat cannot be replaced merely by copying the plugin.

### Test prompt

> Test Secret Handoff's Codex approval mode. Change no files and do not run init.
> Request TEST_TOKEN with reason "Codex native approval test. Enter any dummy value."
> and policy {"hosts":["api.github.com"],"methods":["GET"]}. If pending, use
> wait_for_secret. When ready, call run_with_secret with command ["python3","-c",
> "import os; assert os.environ.get('TEST_TOKEN'); print('Dummy credential received.')"],
> secrets ["TEST_TOKEN:TEST_TOKEN"], dir "/tmp". Follow my existing approval settings;
> do not alter them or press an approval for me. Then forget TEST_TOKEN, including
> if the command is denied. Report the presentation, authorization, exit code,
> redacted output, and whether any value appeared. Never ask for the value in chat.

Secret entry still opens the isolated browser. Command authorization uses the
native host policy; automatic settings may approve without showing a prompt.
Owner desktop acceptance remains outstanding until this fresh-chat test.

Guidance evals after mock refresh: project rules 22/22; MCP only 19/22, below
its 90% threshold. The latter retained two missing request calls and one existing
no-paste regex false positive. Both arms passed the command/directory and waiting
cases. See integrations `evals/RESULTS.md`; each arm ran once. These mock evals do
not establish desktop acceptance.


## Exact desktop compatibility, 2026-10-15 (ADR 0015)

The owner desktop test used browser command approval despite both cached launch
files selecting `codex`. Read-only inspection confirmed that desktop-launched
Secret Handoff processes inherited that mode. The desktop's actual bundled
executable was Codex `0.162.0-alpha.17.2`; the unrelated terminal CLI remained
`0.155.1`. The installed binary's stable-0.155/canonical-version check rejected
the desktop build. The explicit `/tmp` directory was valid.

ADR 0015 adds only this exact desktop version, retaining the stable 0.155 series
and all owner opt-in, client identity, directory, and fallback requirements.
Neighboring alpha builds, additional suffixes, and stable 0.162 remain unverified
and use browser approval. No tool schema or agent guidance changed in this step.

The integrations probe now accepts `--codex-bin /absolute/path/to/codex`, derives
the expected identity from that executable's version, and requires the MCP
handshake to match. Against the desktop bundled executable, both checks passed:

| Probe tool policy | Probe CLI approval policy | Delivered tools/call | Host denial |
| --- | --- | --- | --- |
| approve | never | Yes | No |
| prompt | never | No | Yes |

The captured identity was `codex-mcp-client` / `0.162.0-alpha.17.2`. These were
mock calls without any credential or command. Overrides were confined to those
probe child invocations; no saved owner settings were changed. The real cached
plugin also passed its empty-store launch check on this executable, with startup
mode `codex`.

Go vet and the complete race suite passed, including desktop transport cases
for success and browser fallback, complete success/nonzero/timeout/truncation/
startup-failure results, and the binary leak suite in browser, Claude, stable
Codex, and desktop Codex modes. Lint, TypeScript, all 23 production-build tests,
and fresh-local-D1 security integration passed. The Node 24 arm64 runtime could
not load this checkout's x64 native build dependencies; production and D1 checks
therefore used the existing x64 Node 25.2.1 runtime without dependency changes.
Offline plugin contracts and all four cached-launch helper tests passed. The
full online schema validator was unavailable because its optional review Python
dependencies were not installed; this is not publication validation.

The tested candidate was installed locally with the previous binary retained
in a temporary rollback file. Existing MCP processes keep their original image.
The owner dummy test runs in a fresh ephemeral session of the exact bundled
Codex executable, with the existing cached plugin and no approval-policy,
reviewer, hook, or plugin-launch overrides. It uses only request/wait/run/forget
Secret Handoff tools and the owner's exact dummy command; the agent never fills
the page or presses approval. This verifies the desktop runtime and host-policy
path; it is not evidence of a fresh UI prompt if owner policy approves silently.


The owner filled the isolated browser request during the rerun. The real
Secret Handoff tool results in the fresh desktop-runtime session were:

| Operation | Result |
| --- | --- |
| request_secret | `pending`, `browser_page` |
| wait_for_secret | `ready`, `browser_page` |
| run_with_secret | `command_finished`, `client_policy`, `host_policy`, executed |
| Command exit | `0`; not cancelled or timed out |
| Redacted stdout | `Dummy credential received.` |
| Stderr | Empty |
| forget_secret | `forgotten` |

No credential value or fill link appeared in tool results or chat. The agent
did not enter the value, operate the entry page, or press an approval. The fresh
Codex test session exited 0. This verifies the actual bundled desktop runtime's
host-policy execution path; the current chat's pre-existing MCP connection still
needs a fresh connection to load the replacement binary. No desktop-native
prompt-rendering claim is made. Saved `config.toml` and both cached MCP launch
files retained identical SHA-256 checksums throughout installation and rerun.

Concurrent unrelated group-entry changes arrived in the shared checkout after
the tested candidate had been built. They were preserved and were not included
in this locally installed candidate; validation above applies to the tested
candidate, not to those later edits.
