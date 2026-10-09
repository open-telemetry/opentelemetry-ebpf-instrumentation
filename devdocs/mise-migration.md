# Mise build and development tasks

Mise is the repository's tool-version manager and task runner. The root
Makefile has been removed; use `mise run <task>` for development, validation,
generation, integration, packaging, and release tasks. Run `mise tasks` to
list tasks and `mise tasks validate` to check their definitions. Tool versions
are pinned in `mise.toml` and resolved by `mise.lock`.

## eBPF generation

`mise run generate` performs incremental bpf2go generation. It reads the
dependency files emitted by bpf2go (`*_bpfel.go.d`) and regenerates only
packages whose C/header inputs are newer than their generated outputs. It also
checks that every selected architecture has its expected Go, object, and
dependency files, and records a local fingerprint of the directives, tool
module, compiler, and flags. The fingerprint is runtime state under `.mise/`,
not a checked-in input. `BPF_TARGETS` accepts `amd64`, `arm64`, or both
(default); amd64 outputs use the bpf2go `x86` suffix. Other architectures are
rejected.

On an initial checkout, or when generated outputs or dependency metadata are
missing, all BPF packages are generated. `mise run generate/all` forces that
full generation. The `clang` and `llvm-tools` Mise tools provide the pinned
LLVM 22 compiler and `llvm-strip`; the reproducible generator container uses
the same LLVM major and passes its compiler/flags to the generation script.

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
