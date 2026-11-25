# Rust runtime instrumentation

OBI tracks spawned Tokio tasks on Linux amd64 and arm64 with stable rustc
1.97.x through 1.100.x. OBI reads the compiler version from the executable.
If the version string is absent, OBI can identify the compiler from a known
standard-library commit. The executable must retain the Tokio function symbols
used for poll and task creation or deallocation. Debug information is optional.

A worker can switch between unrelated tasks. OBI follows the task across polls
and copies its parent when it spawns another task. It checks alternative hooks
for optimized builds and keeps generic capture available when hooks are missing.
Threads that never poll a Tokio task, such as `std::thread` or rayon workers,
keep per-thread request tracking. A task spawned from such a thread inherits the
request that thread is serving.

## Enabling

Tokio task tracking is off by default. Enable it in Config v2:

```yaml
extensions:
  obi:
    capture:
      runtimes:
        rust:
          enabled: true
```

The switch exists only in Config v2, and Config v2 does not read `OTEL_EBPF_*`
environment variables, so a Config v1 deployment has to migrate first: see the
[Config v1 to v2 migration guide](config/version-2.0/migration.md). When the
switch is off, OBI attaches no Tokio probe, shrinks the Rust maps to one entry
at load, and traces a Rust service like any other native binary.

## Log enrichment

When log enrichment and Tokio task tracking are both enabled for a Rust
service, OBI can add the current task’s trace and span IDs to logs written to
stdout or stderr. A task can yield and resume on another worker and still log
with the same context. OBI looks up the context when the write occurs, so a
logger that queues records for a dedicated writer thread loses the originating
task’s context.
See [trace-log correlation](trace-log-correlation.md#rust-tokio-task-polls).
