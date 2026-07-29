# Go runtime metrics

With `application_runtime` enabled, OBI collects Go runtime values from
instrumented Go services and exports the following metric set.

Go runtime metrics require the binary's symbol table. Stripped builds, including
builds using `-ldflags=-s`, are not supported.

## Metrics

| OTel metric | Prometheus metric | Available since | Runtime source | Export behavior |
| --- | --- | --- | --- | --- |
| `go.memory.limit` | `go_memory_limit_bytes` | Go 1.19 | `runtime.gcController.memoryLimit` | Emits positive runtime memory limits; treats `math.MaxInt64` as the runtime's unset sentinel. |
| `go.memory.gc.goal` | `go_memory_gc_goal_bytes` | Go 1.17 | Exact committed heap goal | Reads `runtime.gcController.heapGoal` when its offset is available; otherwise captures the second argument of `runtime.gcPaceScavenger` when that symbol is available. If neither source is available, OBI omits the metric. Emits only positive values that fit in `int64`. |
| `go.memory.gc.cycles` | `go_memory_gc_cycles_total` | Go 1.17 | `runtime.memstats.numgc` | Emits the total completed GC cycle count. |
| `go.memory.used` | `go_memory_used_bytes` | Go 1.23 | `runtime.memstats.heapStats` and runtime sys stats | Emits `go.memory.type=stack` and `go.memory.type=other` values. |
| `go.memory.allocated` | `go_memory_allocated_bytes_total` | Go 1.23 | `runtime.memstats.heapStats` and Go size-class table | Emits cumulative allocated heap bytes. |
| `go.memory.allocations` | `go_memory_allocations_total` | Go 1.23 | `runtime.memstats.heapStats` | Emits the cumulative heap allocation count. |
| `go.cpu.time` | `go_cpu_time_seconds_total` | Go 1.23 | `runtime.work.cpuStats` | Emits cumulative CPU seconds with `go.cpu.state` and, where applicable, `go.cpu.detailed_state`. |
| `go.goroutine.count` | `go_goroutine_count` | Capability-based | `runtime.allglen`, `runtime.sched`, and `runtime.allp` | Emits the current goroutine count using the same free-list subtraction as `/sched/goroutines:goroutines`. |
| `go.processor.limit` | `go_processor_limit` | Go 1.17 | `runtime.gomaxprocs` | Emits the current `GOMAXPROCS` value. |
| `go.config.gogc` | `go_config_gogc_percent` | Go 1.17 | `runtime.gcController.gcPercent` | Emits non-negative `GOGC` percentages; a negative runtime value represents `GOGC=off`. |

OBI reads absolute runtime values from the target process.

Goroutine counting starts with `runtime.allglen`, subtracts both scheduler
`gFree` list sizes and every `runtime.allp` processor's `gFree` list size, then
clamps the result to at least one. Before Go 1.26 it also subtracts
`runtime.sched.ngsys`, matching the target runtime's exclusion of system
goroutines; from Go 1.26 onward, system goroutines are included.
The metric is capability-based because OBI enables it only when the target Go
version, runtime symbols, and all required scheduler/free-list offsets resolve.
The supported per-list size layout first appears in Go 1.25, so older targets
omit this metric without affecting other runtime metrics.
OBI scans at most 256 processors to keep the BPF verifier bound fixed. When
`runtime.allp` exceeds that bound, or any pointer or memory read fails, the
snapshot omits `go.goroutine.count` instead of exporting a partial count.

## Collection path

Go runtime metrics flow through the Go tracer's BPF programs, the shared event
ring buffer, and the runtime metrics export queue:

1. During Go process discovery, userspace resolves the runtime metadata needed
   by the BPF probe.
2. Userspace writes process-scoped addresses and executable-scoped field offsets
   to BPF maps.
3. If the `runtime.gcController.heapGoal` field offset is available, OBI reads
   that field at snapshot time. Otherwise, when `runtime.gcPaceScavenger`
   resolves, an entry probe caches its second argument, which is the exact heap
   goal passed by `runtime.gcControllerCommit`. This fallback assumes the Go
   1.19+ signature (`memoryLimit`, `heapGoal`, `lastHeapGoal`); Go 1.17–1.18
   resolve the `heapGoal` field instead. If neither source is available, OBI
   omits only `go.memory.gc.goal`; it never estimates the goal from other runtime
   fields.
4. For Go 1.23 and newer, a BPF entry probe on
   `runtime.(*scavengeIndex).nextGen` runs during GC mark termination after
   accounting is updated and while the Go world is stopped. This prevents Go's
   heap-stat ring from rotating during a memory snapshot. Older Go versions use
   the `runtime.gcMarkDone` return probe for the legacy metric set. The probe
   reads scalar runtime values with `bpf_probe_read_user` and submits a runtime
   snapshot through the shared BPF event ring buffer.
5. The Go tracer converts runtime snapshot events into userspace
   `RuntimeMetricSnapshot` values and forwards them through the runtime metrics
   queue.
6. OTEL and Prometheus exporters consume queued snapshots at their export
   cadence, join them to current Go service metadata, apply metric export
   semantics, and emit the metrics.

## Snapshot cadence

Snapshots update when the version-appropriate GC probe fires. A newly started
process emits runtime metrics after it completes a GC cycle. A GC goal captured
from `runtime.gcPaceScavenger` is exported by the next GC-cadence snapshot; a
goal backed by `runtime.gcController.heapGoal` is read during that snapshot.
Changes to `GOGC`, `GOMEMLIMIT`, `GOMAXPROCS`, CPU counters, goroutine count,
and memory counters appear in exported metrics after the next completed GC.
