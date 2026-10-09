# Secret Handoff

Give your agent access with a sealed secret.

The local `secrethandoff` tool lets an AI agent use ad hoc secrets without receiving
their values in chat. A private browser page asks you to fill a secret and approve
where it can be used. The agent receives a reference; the tool applies the value
inside approved requests and redacts returned values.

**Status: source available for inspection; no public binary release yet.** This is
an unreleased source checkpoint, not an independent security audit or a release
approval. The independent phone/remote protocol review and clean-machine/client
release checks remain open. Do not assume that every client in the design matrix
has passed acceptance.

## Build and test

The module lives in `packages/cli-go` so the browser/Go interoperability and
installer regression tests keep their original paths. Go 1.27.1 is selected by
`go.mod`; an older Go launcher may download that toolchain. Use Node 24 for the
mandatory browser/Go interoperability test.

```sh
git clone https://github.com/geland/secrethandoff.git
cd secrethandoff/packages/cli-go
go vet ./...
CI=1 go test -race ./...
CGO_ENABLED=0 go build -trimpath -o secrethandoff .
./secrethandoff doctor
```

The Node test uses the published browser HPKE module in `app/lib/sealed.ts`. No
website server or npm dependencies are needed to build or test this tool.

## Use and security boundaries

[CLI commands and setup](packages/cli-go/README.md) ·
[Security model](docs/security/sealed-request-threat-model.md) ·
[Report a vulnerability](SECURITY.md) · [Website](https://secrethandoff.com)

Local fill writes no secrets to disk and sends no telemetry. Filled values have
no automatic timer: forget them explicitly or end the tool process. An approved
API receives the value and can retain it. Individually approved commands receive
it and can leak it. Same-user processes are outside a hard isolation boundary.
Phone and remote modes contact the encrypted relay and have additional trust
boundaries documented in the threat model.

Agent plugins are maintained separately. Their availability is a separate gate;
building the binary does not establish plugin installation or host acceptance.

## Source checkpoint and releases

This repository starts with a reviewed, allowlisted snapshot and a fresh Git
history. `SOURCE-SNAPSHOT.json` records the original committed source revision and
SHA-256 hashes of exported files. It excludes hosted-service implementation,
infrastructure, deployment configuration, credentials, build output, and the
original repository history. Publication documentation and CI were added here.
Uncommitted development work was not exported.

Decision records and implementation plans preserve historical design and gate
status. The CLI README describes the exported implementation. References to the
website or separate integrations are not a claim that those components are
included here. The recorded threat model is not a completed independent audit.

The release workflow supports six targets, checksums, provenance attestations,
and macOS signing/notarization. No release tag is created by publishing source.
Do not distribute workflow artifacts as approved releases. Reproducibility of
signed/notarized artifacts has not been established.

The CLI and the browser HPKE interoperability module are licensed under MIT.
See [LICENSE](LICENSE).
