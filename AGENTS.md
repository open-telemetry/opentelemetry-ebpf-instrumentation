# AGENTS.md

## Purpose

This repository provides eBPF-based instrumentation for applications and integrates with OpenTelemetry.

Agents operating on this repository must produce small, correct, and reviewable changes that respect the existing architecture and development workflow.

For an overview of the data pipeline and component relationships, see [devdocs/pipeline-map.md](devdocs/pipeline-map.md).

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
  test/integration/ Integration tests (build tag: //go:build integration)
configs/           Example and default configuration files
```

Generated files (never edit manually):

- `*_bpfel.go`, `*_bpfeb.go` — Go bindings produced by `bpf2go` from eBPF C source
- `*_bpfel.o`, `*_bpfeb.o` — Compiled eBPF bytecode
- `bpf/bpfcore/` — Copied and auto-generated files; do not edit anything in this directory

Do not assume boundaries can be changed without explicit instruction.

## Rules

- Keep changes minimal and scoped to the task.
- Do not include unrelated edits, formatting changes, or cleanup.
- Follow existing code patterns and structure.
- Prefer consistency with surrounding code over stylistic changes.
- Do not introduce unnecessary abstractions.
- Refactors are allowed only when they are directly relevant to the task.

If the task is unclear or underspecified, ask for clarification before making changes.

## Validation

Before proposing changes, ensure the repository generates required artifacts, passes validation, and compiles successfully.

Preferred validation targets:

- `make verify` for the main validation flow
- `make build` when generation and compilation are also required
- `make generate` or `make docker-generate` when any `.c` file in `bpf/` is added or modified

Use `make lint`, `make test`, and `make compile` for targeted iteration when a full validation run is unnecessary.

C code must be formatted and linted before proposing changes. Run `make install-hooks` to install pre-commit hooks that enforce this automatically, or run `make clang-format` and `make clang-tidy` manually.

Integration tests live in `internal/test/integration/` and require the `integration` build tag:

```
go test -v -tags integration -run <TestName> -timeout 10m ./internal/test/integration/
```

Do not propose changes that fail local validation.

## Code Guidelines

These rules apply to all code in the repository.

- Clarity is paramount. Code must be easy to read and reason about.
- Prefer simple, explicit logic over clever or compact code.
- Design code to be orthogonal. Changes in one area must not introduce side effects in unrelated parts of the system.
- Avoid overlapping responsibilities. Each component should do one thing and do it well.
- Prefer composition of small, independent pieces over tightly coupled logic.
- Do not introduce hidden coupling between components.
- Functions must be small and focused. Split large functions when needed.
- Maintain clear structure and naming. Prioritize readability over brevity.
- Prefer early returns when they improve readability and reduce indentation depth.
- Use vertical spacing to separate logical blocks and improve readability. Do not compress unrelated logic into a dense block of code.
- Do not use magic numbers. Name constants or derive sizes from existing types and objects when possible.
- Do not introduce new implementations when equivalent functionality already exists in the repository or its dependencies. Search for and reuse existing utilities, helpers, or patterns — including those provided by external libraries already in use. Extend or adapt existing code instead of duplicating functionality.

Comments must be minimal:

- Do not add comments that restate the code.
- Prefer clearer code over explanatory comments.
- Add comments only when they provide necessary context, explain non-obvious behavior, or document verifier, kernel, or ABI constraints.

## Go Guidelines

- Avoid unnecessary interfaces. Do not introduce interfaces unless they are needed for an existing design boundary, multiple implementations, or tests.
- Avoid over-abstraction. Prefer concrete types and straightforward code.
- Do not introduce new layers, wrappers, or indirection without a clear need.
- Respect existing package boundaries and responsibilities.

## eBPF / C Guidelines

- Apply modern C best practices with readability and maintainability as the priority.
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
- Respect verifier limitations and kernel compatibility.
- Avoid patterns that increase verifier complexity or risk rejection.
- Keep programs simple and predictable.
