# Upgrading the Go Version

When upgrading the Go version:

- Update the `go` version in [mise.toml](../mise.toml).
- Update the `go` directive in all `go.mod` files that require the new version.
- Update any container build files that compile Go code, if they pin a Go image.
- Search the codebase for remaining references to the previous version and update
  them where appropriate.
- Run `mise run verify` and `mise run build`, then open a PR with the changes.
