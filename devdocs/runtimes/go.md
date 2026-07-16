# Go runtime metrics

With `application_runtime` enabled, OBI collects Go runtime values from
instrumented Go services and exports the following metric set.

## Metrics

| OTel metric | Prometheus metric | Runtime source | Export behavior |
| --- | --- | --- | --- |
| `go.memory.limit` | `go_memory_limit_bytes` | `runtime.gcController.memoryLimit` | Emits positive runtime memory limits; treats `math.MaxInt64` as the runtime's unset sentinel. |
| `go.memory.gc.cycles` | `go_memory_gc_cycles_total` | `runtime.memstats.numgc` | Emits the total completed GC cycle count. |
| `go.cpu.time` | `go_cpu_time_seconds_total` | `runtime.work.cpuStats` | For Go 1.23 and newer, emits cumulative CPU seconds with `go.cpu.state` and, where applicable, `go.cpu.detailed_state`; omitted for older versions. |
| `go.processor.limit` | `go_processor_limit` | `runtime.gomaxprocs` | Emits the current `GOMAXPROCS` value. |
| `go.config.gogc` | `go_config_gogc_percent` | `runtime.gcController.gcPercent` | Emits non-negative `GOGC` percentages; a negative runtime value represents `GOGC=off`. |

OBI reads absolute runtime values from the target process.

## Collection path

Go runtime metrics flow through the Go tracer's BPF programs, the shared event
ring buffer, and the runtime metrics export queue:

1. During Go process discovery, userspace resolves the runtime metadata needed
   by the BPF probe.
2. Userspace writes process-scoped addresses and executable-scoped field offsets
   to BPF maps.
3. A BPF return probe on `runtime.gcMarkDone` runs at GC completion. The probe
   looks up the registered metadata, reads scalar runtime values with
   `bpf_probe_read_user`, and submits a runtime snapshot through the shared BPF
   event ring buffer.
4. The Go tracer converts runtime snapshot events into userspace
   `RuntimeMetricSnapshot` values and forwards them through the runtime metrics
   queue.
5. OTEL and Prometheus exporters consume queued snapshots at their export
   cadence, join them to current Go service metadata, apply metric export
   semantics, and emit the metrics.

## Snapshot cadence

Snapshots update when the GC-completion probe fires. A newly started process
emits runtime metrics after it completes a GC cycle. Changes to `GOGC`,
`GOMEMLIMIT`, `GOMAXPROCS`, and CPU counters appear in exported metrics after
the next completed GC. CPU counters are available only for services built with
Go 1.23 or newer.
