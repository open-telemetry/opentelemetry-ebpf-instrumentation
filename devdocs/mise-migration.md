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

This is not yet as maintainable as Make's dependency tracking. The generator
script implements its own Make-like checks over bpf2go dependency files. A
prototype using Mise task `sources` and `outputs` avoided that script logic for
11 package tasks, but Mise does not dynamically read bpf2go's `.d` files. The
prototype matched the observed incremental cases only with source lists
statically populated from the current dependency files; a newly added include
edge would be missed until its task's source list was updated. Broad source
globs avoid that stale-list risk but can rerun more packages than necessary.

In one local run, the prototype skipped all tasks on a no-change run (0.251s),
rebuilt only both generictracer architectures after a generictracer C change
(21.228s), rebuilt common, generictracer, gotracer, and tpinjector for both
architectures after a `common.h` change (49.299s), and rebuilt both
generictracer architectures when an output was deleted (21.021s). These are
single-run indicative timings, not a benchmark. The task-output approach looks
promising for speed, but it does not provide Make-equivalent dynamic dependency
tracking; the current script has the same fundamental maintenance gap.

**Possible upstream Mise discussion:** Could file tasks support dependency
files emitted by tools such as bpf2go as dynamic `sources` (or equivalent
dependency metadata), so task outputs can retain precise incremental rebuilds
without duplicating a build system's dependency logic?

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
