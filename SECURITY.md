# Security policy

## Report privately

Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/geland/secrethandoff/security/advisories/new).
Do not include credentials, real secret values, live handoff links, or captured
request bodies. Use synthetic examples and describe affected versions, expected
behavior, and reproduction steps. Please do not file vulnerabilities as public
issues before coordination with the maintainer.

## Supported versions

There is no approved public binary release yet. This repository is published for
source inspection. Reports against the default branch are welcome; no response
SLA or security certification is promised. Do not rely on a source publication
or a passing CI check as a completed independent review.

## Security model

Read [the threat model](docs/security/sealed-request-threat-model.md), particularly
residual risks and the release gates. The local process runs under the owner's
account. Approved destinations and commands receive the value. Local memory
lifetime, remote pairing and confirmation, and browser trust have different
boundaries.
