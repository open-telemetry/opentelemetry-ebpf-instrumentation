# Java TLS IOCTL Security Notes

This note documents the final shape of the Java TLS `ioctl(2)` fix in
[bpf/generictracer/java_tls.c](../bpf/generictracer/java_tls.c).

## Final Shape

The current `java_tls.c` path does three security-relevant things before it
hands the payload to the shared protocol handlers:

1. It reads the Java TLS metadata fields with `bpf_probe_read_user`.
2. It clamps the claimed payload length to `k_ioctl_max_payload_len`.
3. It verifies the first and last payload byte with `bpf_probe_read_user`.

After those checks, it calls `handle_buf_with_connection(...)` using the
existing generic tracer buffer flow.

## Why We Chose This Form

An earlier branch introduced a broader "buffer source tracking" refactor that
threaded user-vs-generic buffer provenance through shared protocol code. That
refactor was intentionally removed.

The review conclusion for this advisory was narrower:

- this Java TLS `ioctl` path receives one flat contiguous user pointer
- the security concern is whether OBI can be tricked into reading non-user
  memory through that pointer
- reviewer feedback preferred a localized fix in `java_tls.c` over a broader
  shared-path refactor

The resulting patch keeps the fix local to the Java TLS entry point.

## Security Reasoning

The main question we investigated was whether an attacker could craft a Java
program so that this one contiguous payload pointer would cause OBI to read
privileged memory.

The important conclusions were:

- A contiguous user pointer range cannot start in ordinary user virtual memory,
  pass through kernel virtual addresses in the middle, and then return to user
  virtual memory.
- Other users' private process memory also does not get interleaved into an
  attacker's contiguous user buffer range under the normal Linux process memory
  model.
- Because of that, the realistic security boundary in this path is
  "user-accessible memory vs. non-user memory", not segmented or mixed-source
  buffer ownership.

That is why the narrow fix checks the start and end of the payload with
`bpf_probe_read_user` and leaves the rest of the generic parser path unchanged.

## What This Fix Does Not Claim

The start/end checks are **not** a general-purpose proof that every byte in the
range is readable. They are narrower than full range validation.

That distinction matters for robustness, but it was not enough to show a
remaining privileged-memory disclosure path in this Java TLS flat-buffer model.
For this advisory, the conclusion was that the localized non-user-memory
boundary check was the relevant security property.

## Maintenance Guidance

This reasoning is specific to the current Java TLS path because it passes one
flat payload pointer plus a length.

Do not reuse this pattern blindly for future paths that accept:

- segmented buffers
- descriptor arrays
- `iovec`-style metadata
- handles that the kernel resolves into backing pages

Those shapes have different security properties and would need their own review.
