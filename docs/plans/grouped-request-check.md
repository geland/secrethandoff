# Grouped local request check

Implementation: [ADR 0016](../adr/0016-grouped-local-requests.md).

`request_secrets` accepts 2–8 fields, one policy and request deadline. Combined
values are limited to 32 KiB within a 64 KiB encoded submission. One local browser
form masks every field; all members publish atomically. Use each member by name.
Waiting accepts the group name. Forgetting the group or any member erases the
whole group. Groups currently do not support phone or headless relay fill.

## Owner test prompt

Start a fresh chat after the plugin reload, then send:

> Test grouped Secret Handoff. Change no files and do not run init or commands.
> Call request_secrets with name TEST_LOGIN, secrets [{"name":"TEST_USERNAME",
> "label":"Username"},{"name":"TEST_PASSWORD","label":"Password"}], reason
> "Grouped credential UI test. Enter dummy values only.", and policy
> {"hosts":["api.example.com"],"methods":["POST"],"paths":["/login"]}.
> If pending, call wait_for_secret with name TEST_LOGIN. When ready, list the
> secret names, then forget TEST_LOGIN. Never ask for values in chat, reveal them,
> or send a network request. Report whether both were ready and then removed.

Expect one separate Secret Handoff browser page with Username and Password.
Both are masked initially, and one button submits both. Secret entry remains
outside chat. The test invokes no command approval and leaves native approval
settings to the concurrent approval work.

## Validation recorded 2026-10-15

- Go vet and race suite passed, including real-binary raw stdout/stderr/structured
  leak assertions for both values, group bounds and cancellation, replacement
  page safety, atomic store visibility, and two-secret command redaction.
- Lint, TypeScript, production tests and fresh-D1 security integration passed.
- Built-in grouped form tests and both card suites passed. Synthetic Chrome
  desktop/mobile QA passed; no protected fill link or real credential was used.
- The new grouped-login case passed in both Codex evaluation arms. Full raw
  scores were 20/23 with rules and 18/23 MCP-only. Older literal single-tool
  assertions reject valid grouped request calls, and some MCP-only cases still
  miss handoffs. See integrations `evals/RESULTS.md` for unadjusted results.
- Installed binary and plugin cache were refreshed. Existing Codex approval-mode
  launch overrides, user policies, reviewer, hooks, and concurrent approval source
  were preserved. Claude's changed skill/card assets were also refreshed.
- Official online schemas and owner interactive acceptance are not established
  by these local checks. No public release, commit, or init was performed.
