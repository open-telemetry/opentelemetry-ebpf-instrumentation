# Mise build and development tasks

Mise is the repository's tool-version manager and task runner. The general root
Makefile has been removed; use `mise run <task>` for development, validation,
generation, integration, packaging, and release tasks. Run `mise tasks` to
list tasks and `mise tasks validate` to check their definitions. Tool versions
are pinned in `mise.toml` and resolved by `mise.lock`.

## eBPF generation

`mise run generate` delegates this one task to `bpf/Makefile`. This is an
intentional exception to the Mise task migration: Make directly includes the
dependency files emitted by bpf2go (`*_bpfel.go.d`), so changed C/header inputs
rebuild only the affected generated package and architecture. Reimplementing
that dynamic dependency graph in a Mise task would mean maintaining custom
Make-like logic, which was less clear and harder to trust. `BPF_TARGETS`
accepts `amd64`, `arm64`, or both (default); amd64 outputs use the bpf2go `x86`
suffix. Other architectures are rejected.

On an initial checkout, or when dependency metadata is missing, Make generates
all BPF packages. `mise run generate/all` forces full generation; use it after
adding/removing a bpf2go directive or changing generator tools/flags, which are
not themselves represented by bpf2go's C/header depfiles. The generator image
installs Make and uses the same `bpf/Makefile`, with the image's pinned Go,
bpf2go, and LLVM toolchain.

The Mise discussion about dynamically consuming generated dependency files is
[open as #14234](https://github.com/jdx/mise/discussions/14234). The maintainer
said this appears out of scope, so the narrow Make exception is the practical
choice for now rather than keeping a custom dependency parser or assuming Mise
task `sources`/`outputs` can represent bpf2go's changing include graph.

## Common tasks

| Task | Purpose |
| --- | --- |
| `mise run format-go` | Format Go code and imports. |
| `mise run lint-go` | Run Go lint prerequisites and golangci-lint. |
| `mise run test-go` | Run short, race-enabled Go tests and coverage. |
| `mise run compile` | Compile the `obi` binary; `CMD`, `GOOS`, `GOARCH`, version, and source-file overrides are supported. |
| `mise run verify` | Run prerequisites, module tidy, lint, tests, and license-header checks in order. |
| `mise run build` | Generate eBPF code, verify, then compile. |
| `mise run integration-test` | Prepare, run, collect coverage, and clean up integration tests. |
| `mise run release` | Build and validate the release archive, then write checksums. |

The previous root Make targets are represented by Mise tasks, including
release, notices, schema, Java, Python requirements, integration/OATS, VM, and
test-matrix operations. Some tasks still intentionally use container tools for
containerized build/test environments; tool-version management for development
tools lives in Mise. The only image pin kept outside Mise is the BusyBox
runtime payload used by test helpers, in `internal/test/runtime-images.env`.
