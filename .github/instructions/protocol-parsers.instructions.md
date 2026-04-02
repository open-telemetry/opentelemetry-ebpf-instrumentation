---
applyTo: "pkg/ebpf/common/*detect_transform*.go,pkg/ebpf/common/*detect_transform*_test.go"
---

# Protocol Parser Instructions

When working on or reviewing protocol parser code in this repository, be especially strict about reuse, clarity, and established parser patterns.

- Compare new parser logic against nearby protocol implementations before accepting it.
- Prefer the repository's `LargeBuffer` API, including direct typed helpers and `LargeBufferReader`, over generic Go buffer handling.
- Avoid `UnsafeView()` when `LargeBuffer` helpers or readers can access the data directly; use it only when a raw slice is genuinely needed. See the SQL protocol implementation for the expected style and tradeoffs.
- Prefer non-allocating `[]byte` parsing and matching as long as possible, and convert to `string` only at the edges where the API actually needs a string result.
- Flag parser code that reimplements logic already present in nearby protocol parsers or related helpers instead of reusing or extracting common behavior.
- Flag awkward or mechanical logic patterns that reduce clarity, such as convoluted length checks, repeated branch bodies, unnecessary conversions, or obvious missed simplifications.
- Flag unnecessary allocations, especially mindless `[]byte` to `string` conversions, and unnecessary `unsafe` usage.
- Flag choices that drift from more reliable established patterns already used elsewhere in the repository unless the PR explains why this protocol genuinely needs a different approach.
- Check whether branch-heavy validation and error paths are covered by tests, not just the happy path.
- Prefer parser code that is easy to reason about under malformed input, partial buffers, and protocol edge cases.
