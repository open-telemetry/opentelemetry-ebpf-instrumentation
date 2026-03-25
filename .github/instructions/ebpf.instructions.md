---
applyTo: "bpf/**/*.c,bpf/**/*.h"
---

# eBPF C Code Instructions

When working on eBPF C code in this repository, follow these rules strictly.

Prioritize clarity, correctness, and verifier-friendly code over cleverness or compactness.

General rules:

- Prefer simple, explicit logic over clever code.
- Keep functions small and focused. Split large functions into smaller helpers when needed.
- Prefer early returns when they improve readability and reduce indentation depth.
- Use vertical spacing to separate logical blocks. Do not compress unrelated logic into dense code.
- Do not use magic numbers. Name constants or derive sizes from existing types and objects when possible.
- Do not add comments that restate the code. Prefer clearer code over explanatory comments.
- Add comments only when they provide necessary context, explain non-obvious behavior, or document verifier, kernel, or ABI constraints.
- Reuse existing utilities, helpers, maps, and patterns in the repository instead of introducing duplicate implementations.

Type and memory rules:

- Prefer const correctness wherever possible.
- Use the narrowest appropriate integer type.
- Prefer unsigned types for sizes, counts, indexes, bitfields, and values that cannot be negative.
- Use signed types only when signed semantics are required.
- Buffers and raw memory chunks must use `unsigned char *`, not `u8 *`.
- Use `sizeof(*ptr)` when it improves correctness and maintainability.
- Prefer deriving sizes with `sizeof` over introducing separate size constants when possible.
- Initialize variables as locally as possible and keep their lifetime narrow.

Preprocessor and constants:

- Prefer enums over macros for constants.
- Avoid macros unless they are strictly necessary.

Repository-specific eBPF rules:

- Maps that are not explicitly pinned for external use must default to `OBI_PIN_INTERNAL`.
- Use `SCRATCH_MEM`, `SCRATCH_MEM_TYPED`, and `SCRATCH_MEM_SIZED` for scratch memory patterns instead of introducing ad hoc temporary buffers.
- For tail calls, prefer `bpf_tail_call_static(...)`.
- Define tail call program arrays in the eBPF C code unless there is a clear reason not to.
- Use `bpf_probe_read_kernel` for kernel memory.
- Use `bpf_probe_read_user` for user memory.
- Use `bpf_probe_read` only when writing genuinely generic code that must handle both cases.

Verifier and kernel constraints:

- Respect verifier limitations and kernel compatibility.
- Avoid patterns that increase verifier complexity or risk rejection.
- Keep programs simple and predictable.

When reviewing eBPF C changes, flag code that violates these rules and ask for a repository-specific rationale when a deviation appears intentional.
