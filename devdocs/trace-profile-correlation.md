# Correlating Profiles to OBI Traces

This document introduces a standard communication channel and a specification for correlating profiles to OBI traces.

## Table Of Contents

- [Motivation](#motivation)
- [Design Notes](#design-notes)
  - [Communication Channel](#communication-channel)
  - [Data Model](#data-model)
    - [eBPF Map Specification](#ebpf-map-specification)

## Motivation

Currently, OBI traces and profiles operate independently, making it difficult to attribute profiling data to specific traces or spans. By establishing a standard kernel-resident communication channel, this document enables:

- Correlating profiles with their corresponding traces or spans
- End-to-end observability workflows without requiring application-level instrumentation

## Design Notes

### Communication Channel

The communication channel between OBI and the profiler is implemented via an eBPF map pinned at `$PINPATH/otel/traces_ctx_v1`.

`$PINPATH` will default to bpffs (`/sys/fs/bpf`) but there must be options to specify an alternative location. If set, the user-configured location in OBI must match the one set in the profiler.

On startup, both OBI and the profiler will create the map and pin it if it doesn't exist.

Keeping the map aligned with the request each thread is serving costs OBI a refresh on every async context switch of the instrumented process, so OBI only populates it when something reads it. A profiler is not visible to OBI, so it must be declared:

```yaml
ebpf:
  populate_trace_context: true
```

or `OTEL_EBPF_BPF_POPULATE_TRACE_CONTEXT=true`. Without it the pin exists but stays empty, and every profile sample looks like it ran outside a span. See [When the map is populated](trace-log-correlation.md#when-the-map-is-populated).

### Data Model

The shared eBPF map uses a minimal structure to store correlation data. OBI will be responsible for removing entries in order to avoid keeping stale contexts.

#### eBPF Map Specification

```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct trace_context);
    __uint(max_entries, 1 << 14);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} traces_ctx_v1 SEC(".maps");
```

- **Key:** `(u64) pid_tgid`
- **Value:**

```c
struct trace_context {
    u8 trace_id[16];
    u8 span_id[8];
};
```
