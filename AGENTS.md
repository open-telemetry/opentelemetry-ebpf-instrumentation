# AGENTS.md

## Purpose

This repository provides eBPF-based application instrumentation and integrates
with OpenTelemetry. Produce small, correct, reviewable changes that respect the
existing architecture and development workflow.

Use [devdocs/pipeline-map.md](devdocs/pipeline-map.md) for architecture and data
flow. The
[DeepWiki repository page](https://deepwiki.com/open-telemetry/opentelemetry-ebpf-instrumentation)
may provide additional context when available. When repository files do not
answer a question, consult these primary references:

- [eBPF reference documentation](https://docs.ebpf.io/linux/)
- [OpenTelemetry documentation and specifications](https://opentelemetry.io/docs/)

Repository code and local documentation take precedence over external sources.

## Task-oriented starting points

- **Understand how data flows through OpenTelemetry eBPF Instrumentation (OBI):** start with [devdocs/pipeline-map.md](devdocs/pipeline-map.md), then follow the named components into `pkg/` and `pkg/internal/`.
- **Change or investigate network, application, or stats metrics:** read [devdocs/metrics.md](devdocs/metrics.md); for eBPF map and probe metrics, also read [devdocs/bpf-metrics-collection.md](devdocs/bpf-metrics-collection.md).
- **Work on a protocol or runtime:** check the relevant documentation under [devdocs/protocols/](devdocs/protocols/) or [devdocs/runtimes/](devdocs/runtimes/) and trace the implementation from there.
- **Change configuration:** follow the [Config v1 to v2 migration guide](devdocs/config/version-2.0/migration.md); Config v1 is frozen.
- **Work on eBPF code:** inspect the subsystem under `bpf/` and its loader under `pkg/internal/ebpf/`; do not edit generated bindings or `bpf/bpfcore/` files.
- **Use a coding agent:** read [devdocs/ai-tooling.md](devdocs/ai-tooling.md) for setup-specific notes. The repository rules in this file remain authoritative.

## Repository Layout

```
bpf/               eBPF C programs, maps, and shared headers
  bpfcore/         vmlinux.h and BPF core helpers
  common/          Shared headers (scratch_mem.h, pin_internal.h, …)
  maps/            Map definitions shared across programs
  <subsystem>/     One directory per eBPF program (generictracer, gotracer, tpinjector, …)
cmd/               Go binary entry points (obi, k8s-cache, …)
pkg/               Public Go packages
pkg/internal/      Internal Go packages; ebpf/ subdirectory holds per-subsystem loaders
internal/          Integration test infrastructure
  test/integration/ Integration tests
configs/           Example and default configuration files
```

Generated files (never edit manually):

- `*_bpfel.go`, `*_bpfeb.go` — Go bindings produced by `bpf2go` from eBPF C source
- `*_bpfel.o`, `*_bpfeb.o` — Compiled eBPF bytecode
- `bpf/bpfcore/` — Copied and auto-generated files; do not edit anything in this directory

## Rules

- Keep changes scoped; do not include unrelated cleanup or formatting.
- Follow surrounding patterns and package boundaries. Refactor only when it is
  directly relevant to the task.
- Search for and reuse existing helpers, dependencies, and patterns before
  introducing a new implementation or abstraction.
- Prefer simple, explicit logic, focused functions, and early returns where
  they improve readability.
- Name constants or derive values from existing types instead of using magic
  numbers.
- Add comments only for necessary context or non-obvious kernel, verifier, or
  ABI constraints.
- Ask for clarification when a material ambiguity would change the result.

## GitHub Communication

Write issue and pull request descriptions, reviews, and comments for human
readers. Keep them concise, specific, and easy to scan. Lead with the relevant
point, use short paragraphs or lists when helpful, and include only the context
needed to understand or act on the message. Do not post generated wall-of-text
reports, exhaustive restatements of the code, or a play-by-play of the work.

## AI-assisted contributions

Agents may author implementation code, documentation, tests, and GitHub
communication. Their output must follow the same repository, validation, and
communication requirements as any other contribution.

When preparing work for submission, agents must:

- Distinguish verified facts from assumptions.
- Report the validation they ran and any validation they could not run.
- Include the disclosure required by `AI-POLICY.md` for non-trivial Generative
  AI assistance.
- Leave assertions of human review, understanding, and acceptance of
  responsibility to the contributor.

## Validation

Run validation proportionate to the change. Preferred targets:

- `make verify` for the main validation flow
- `make build` when generation and compilation are also required
- `make generate` or `make docker-generate` when any `.c` file in `bpf/` is added or modified

Use `make lint`, `make test`, and `make compile` for targeted iteration. For
Markdown-only changes, run `make lint-markdown`.

C code must be formatted and linted before proposing changes. Run `make install-hooks` to install pre-commit hooks that enforce this automatically, or run `make docker-clang-format` and `make docker-clang-tidy` manually to use the same LLVM version as CI (`make clang-format` and `make clang-tidy` use the local tools).

Integration tests live in `internal/test/integration/`:

```
go test -v -run <TestName> -timeout 10m ./internal/test/integration/
```

Report checks that could not run or failures unrelated to the change. Do not
claim validation passed when it did not.

## Telemetry schema

OBI publishes its OpenTelemetry schema under `site/schemas/obi/` and emits its
`schema_url` from `OBISchemaURL`. `make prerelease` automates new versions and
URL updates through `make generate-schema-next`; `make check-schema-files`
verifies consistency.

`make generate-schema-docs` renders the registry into `site/docs/`, and
`make prerelease` also runs it. Run and commit it between releases whenever the
registry changes; CI does not verify these docs.

Record emitted attribute or metric renames under "Pending transformations" in
`devdocs/telemetry-schema.md`. Record removals and Prometheus-specific changes,
which the schema format cannot express, under "Pending release notes". Release
preparation moves these entries into the new version.

## Go Guidelines

- Prefer concrete types and direct code. Introduce interfaces only for an
  existing boundary, multiple implementations, or tests.
- Respect existing package boundaries and responsibilities.

## eBPF / C Guidelines

- Prefer `const` correctness wherever possible.
- Use the narrowest appropriate integer type. Prefer unsigned types for sizes, counts, indexes, bitfields, and values that cannot be negative. Use signed types only when signed semantics are required.
- Prefer enums over macros for constants. Avoid macros unless they are strictly necessary.
- Use `sizeof(*ptr)` when it improves correctness and maintainability.
- Prefer deriving sizes with `sizeof` over introducing separate size constants when the size can be obtained directly from the object or type.
- Buffers and raw memory chunks must use `unsigned char *`, not `u8 *`.
- Initialize variables as locally as possible and keep their lifetime narrow.
- Maps that are not explicitly pinned for external use must default to `OBI_PIN_INTERNAL` (defined in `bpf/common/pin_internal.h`).
- Use `SCRATCH_MEM`, `SCRATCH_MEM_TYPED`, and `SCRATCH_MEM_SIZED` for scratch memory patterns instead of introducing ad hoc temporary buffers (defined in `bpf/common/scratch_mem.h`).
- For tail calls, prefer `bpf_tail_call_static(...)`. Define tail call program arrays in the eBPF C code unless there is a clear reason not to.
- Use `bpf_probe_read_kernel` for kernel memory, `bpf_probe_read_user` for user memory, and default to `bpf_probe_read` only when writing genuinely generic code that must handle both cases.
- OBI requires kernel 5.8 or higher with BTF enabled. RHEL-based distributions (RHEL8, CentOS 8, Rocky8, AlmaLinux8) are supported via kernel 4.18 with backported eBPF patches. Do not use helpers or features unavailable in the minimum supported kernel unless gated by a runtime check.
- Keep programs simple and predictable to limit verifier complexity and
  preserve kernel compatibility.
