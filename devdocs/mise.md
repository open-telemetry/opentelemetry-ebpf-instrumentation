# Mise tool installation

Mise is an optional way to install the repository's Go and golangci-lint
versions. It does not define or migrate Make tasks: existing Make commands and
their Docker-based tool environments remain unchanged.

The versions in `mise.toml` are install pins, not independent version
authorities. Keep the Go pin aligned with the root `go.mod` toolchain and the
`golang` image in `dependencies.Dockerfile`; keep the golangci-lint pin aligned
with `internal/tools/go.mod`. CI checks this parity and tests detection of
mismatches. Regenerate `mise.lock` after intentional pin changes, without
changing the canonical declarations as a side effect.

To install the tools, [install Mise](https://mise.jdx.dev/installing-mise.html),
then run `mise install --locked` from the repository root.
