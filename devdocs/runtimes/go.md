# Go runtime metrics

With `application_runtime` enabled, OBI collects Go runtime values from
instrumented Go services and exports the following metric set.

Go runtime metrics require the binary's symbol table. Stripped builds, including
builds using `-ldflags=-s`, are not supported.

## Metrics

| OTel metric | Prometheus metric | Available since | Runtime source | Export behavior |
| --- | --- | --- | --- | --- |
| `go.memory.limit` | `go_memory_limit_bytes` | Go 1.19 | `runtime.gcController.memoryLimit` | Emits positive runtime memory limits; treats `math.MaxInt64` as the runtime's unset sentinel. |
| `go.memory.gc.cycles` | `go_memory_gc_cycles_total` | Go 1.17 | `runtime.memstats.numgc` | Emits the total completed GC cycle count. |
| `go.memory.used` | `go_memory_used_bytes` | Go 1.23 | `runtime.memstats.heapStats` and runtime sys stats | Emits `go.memory.type=stack` and `go.memory.type=other` values. |
| `go.memory.allocated` | `go_memory_allocated_bytes_total` | Go 1.23 | `runtime.memstats.heapStats` and Go size-class table | Emits cumulative allocated heap bytes. |
| `go.memory.allocations` | `go_memory_allocations_total` | Go 1.23 | `runtime.memstats.heapStats` | Emits the cumulative heap allocation count. |
| `go.cpu.time` | `go_cpu_time_seconds_total` | Go 1.23 | `runtime.work.cpuStats` | Emits cumulative CPU seconds with `go.cpu.state` and, where applicable, `go.cpu.detailed_state`. |
| `go.processor.limit` | `go_processor_limit` | Go 1.17 | `runtime.gomaxprocs` | Emits the current `GOMAXPROCS` value. |
| `go.config.gogc` | `go_config_gogc_percent` | Go 1.17 | `runtime.gcController.gcPercent` | Emits non-negative `GOGC` percentages; a negative runtime value represents `GOGC=off`. |

OBI reads absolute runtime values from the target process.

## Collection path

Go runtime metrics flow through the Go tracer's BPF programs, the shared event
ring buffer, and the runtime metrics export queue:

1. During Go process discovery, userspace resolves the runtime metadata needed
   by the BPF probe.
2. Userspace writes process-scoped addresses and executable-scoped field offsets
   to BPF maps.
3. For Go 1.23 and newer, a BPF entry probe on
   `runtime.(*scavengeIndex).nextGen` runs during GC mark termination after
   accounting is updated and while the Go world is stopped. This prevents Go's
   heap-stat ring from rotating during a memory snapshot. Older Go versions use
   the `runtime.gcMarkDone` return probe for the legacy metric set. The probe
   reads scalar runtime values with `bpf_probe_read_user` and submits a runtime
   snapshot through the shared BPF event ring buffer.
4. The Go tracer converts runtime snapshot events into userspace
   `RuntimeMetricSnapshot` values and forwards them through the runtime metrics
   queue.
5. OTEL and Prometheus exporters consume queued snapshots at their export
   cadence, join them to current Go service metadata, apply metric export
   semantics, and emit the metrics.

## Snapshot cadence

Snapshots update when the version-appropriate GC probe fires. A newly started
process emits runtime metrics after it completes a GC cycle. Changes to `GOGC`,
`GOMEMLIMIT`, `GOMAXPROCS`, CPU counters, and memory counters appear in exported
metrics after the next completed GC.
