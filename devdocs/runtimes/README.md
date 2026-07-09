# Runtime metrics

Developer documentation for the `application_runtime` feature. This feature
emits OpenTelemetry runtime semantic-convention metrics for instrumented
services without requiring runtime SDK changes in the target process.

## Supported runtimes

- [Go](go.md): BPF-based snapshots for the currently implemented Go runtime
  metrics.
- [JVM](jvm.md): HotSpot memory-pool probes for JVM memory
  metrics.
