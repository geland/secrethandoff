# Publication review, October 9, 2026

This review checks what is exposed by this repository. It is not an independent
cryptography review, penetration test, or public binary release approval.

## Scope and provenance

A fresh repository contains an allowlisted committed source snapshot, the
required browser HPKE module and installer fixtures, security documentation,
MIT license, and CLI-specific CI/release workflow. The source revision and
original file hashes are in SOURCE-SNAPSHOT.json; publication adjustments are
listed separately. There is no imported Git history, branch, tag, or Git remote
from the originating private repository. New commits use a GitHub noreply address.

The export omits infrastructure, Terraform state/variables, D1/Worker deployment
configuration and identifiers, hosted API implementation, environment files,
local caches, screenshots, request captures, and generated binary artifacts.
Uncommitted development work was not exported.

## Review and validation

- Reviewed the export inventory, file types, URLs, identity metadata, signing
  script, workflow permissions, test fixtures, and required cross-repository paths.
- No real credentials, live secret/receipt/request links, production resource
  configuration, private signing material, or personal workstation paths found.
- Gitleaks v8.24.2 with default rules initially flagged three synthetic fixtures
  and a SHA-256 inventory entry. The exact fixtures were reviewed. The checked-in
  scanner configuration has narrow exceptions, not a blanket test-file exemption.
  A subsequent scan passed.
- Additional pattern checks for private keys, personal home paths, production
  resource configuration, credential formats, and live handoff links found only
  a clearly named synthetic MCP fixture and a fixed synthetic relay-link test.
- The standalone export passed `CI=1 go test -race ./...`, including the leak
  suite and browser/Go interoperability check; `go vet ./...`; and a native build.
- Release cross-compilation passed for macOS, Linux, and Windows on amd64/arm64.
- Public PR CI uses read permissions and has no signing material. The release
  workflow is tag/manual only; tagged releases fail closed without macOS signing.

## Remaining release work

No approved public binary release exists. Independent phone/remote protocol
review, signing setup, artifact verification, clean-machine installation, and
fresh installed-client acceptance remain separate gates. Website installer and
catalog routing must target the new public release location before a binary
launch. Separate agent-plugin publication is also outstanding.

The threat model and decision records intentionally expose security boundaries,
residual risks, and open review gates. Hiding these is not a publication control.

## Release-preparation update

The next committed snapshot includes request lifecycle/cancellation fixes,
structured command results with redaction, owner-selected Claude Code command
approval, and binary-only website installers. ADRs 0012 and 0013 and their
host-validation notes are included in the reviewed export. File hashes match the
committed snapshot except for the recorded contribution-guide link adjustment.

Standalone vet, full race/leak/interoperability tests, six target builds, and a
redacted Gitleaks scan passed. Both macOS architectures were also signed and
accepted by Apple in local candidate validation, with subsequent online
notarization verification. This does not establish a GitHub-built release or
clean-machine installation acceptance.

The release workflow now requires signing for manual candidates as well as tags,
uses the protected `apple-signing` environment, and explicitly checks Apple's
accepted status. PR checks have no access to that environment. Source merging,
a reviewed GitHub signing run, final artifact verification, and publication are
still separate steps. No tag or release is created by this update.
