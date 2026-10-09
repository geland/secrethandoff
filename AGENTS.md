# Contributor guidance

Read CONTRIBUTING.md, SECURITY.md, and accepted decisions under docs/adr before
changes to trust boundaries. Preserve the local and relay invariants in the
threat model. Never include real secrets, credentials, local fill/pickup tokens,
or live handoff links in source, fixtures, logs, tool results, or screenshots.

Run from packages/cli-go: `go vet ./...` and `CI=1 go test -race ./...` with
Node 24 on PATH. Human use policy and per-command approval remain mandatory.
No secret may enter model-visible output. Do not edit historical decisions to
conceal a boundary change; add a new decision and tests instead.
