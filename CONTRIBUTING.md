# Contributing

Discuss behavior changes in an issue before preparing a patch. Report security
issues privately using SECURITY.md. Use synthetic fixtures only.

Build and run `go vet ./...` and `CI=1 go test -race ./...` from
`packages/cli-go`, with Node 24 on PATH. The leak suite is mandatory. Changes to
cryptography, persistence, approval, token lifetime, or abuse boundaries need a
new decision record and regression coverage. Keep tool output free of secrets,
request tokens, and local fill links. Secrets and private keys remain in memory.

No administrator rights, system service, trust-store changes, or telemetry may be
introduced into normal setup. Human policy and command approval must remain
mandatory. The isolated browser and loopback protections are product requirements.

Public patches do not automatically enter a release. The maintainer reviews code
and release workflow changes before merging. Do not run untrusted pull requests
with signing keys or write permissions.
