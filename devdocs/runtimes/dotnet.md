# .NET runtime metrics

With `application_runtime` enabled, OBI collects runtime metrics from
.NET 8+ processes on Linux through their diagnostic Unix sockets.

| OTel metric | Prometheus metric | Unit |
| --- | --- | --- |
| `dotnet.gc.collections` | `dotnet_gc_collections_total` | `{collection}` |
| `dotnet.process.cpu.count` | `dotnet_process_cpu_count` | `{cpu}` |
| `dotnet.process.cpu.time` | `dotnet_process_cpu_time_seconds_total` | `s` |
| `dotnet.process.memory.working_set` | `dotnet_process_memory_working_set_bytes` | `By` |
| `dotnet.gc.last_collection.heap.size` | `dotnet_gc_last_collection_heap_size_bytes` | `By` |
| `dotnet.gc.last_collection.heap.fragmentation.size` | `dotnet_gc_last_collection_heap_fragmentation_size_bytes` | `By` |
| `dotnet.gc.last_collection.memory.committed_size` | `dotnet_gc_last_collection_memory_committed_size_bytes` | `By` |
| `dotnet.thread_pool.thread.count` | `dotnet_thread_pool_thread_count` | `{thread}` |
| `dotnet.thread_pool.queue.length` | `dotnet_thread_pool_queue_length` | `{work_item}` |
| `dotnet.timer.count` | `dotnet_timer_count` | `{timer}` |
| `dotnet.assembly.count` | `dotnet_assembly_count` | `{assembly}` |
| `dotnet.gc.heap.total_allocated` | `dotnet_gc_heap_allocated_bytes_total` | `By` |
| `dotnet.gc.pause.time` | `dotnet_gc_pause_time_seconds_total` | `s` |
| `dotnet.jit.compiled_il.size` | `dotnet_jit_compiled_il_size_bytes_total` | `By` |
| `dotnet.jit.compiled_methods` | `dotnet_jit_compiled_methods_total` | `{method}` |
| `dotnet.jit.compilation.time` | `dotnet_jit_compilation_time_seconds_total` | `s` |
| `dotnet.thread_pool.work_item.count` | `dotnet_thread_pool_work_item_count_total` | `{work_item}` |
| `dotnet.monitor.lock_contentions` | `dotnet_monitor_lock_contentions_total` | `{contention}` |
| `dotnet.exceptions` | `dotnet_exceptions_total` | `{exception}` |

For GC collection counts, `dotnet.gc.heap.generation` identifies `gen0`, `gen1`, and `gen2`.
Counts are exclusive: a full gen2 collection adds one to gen2, while gen0 and
gen1 remain unchanged.

Heap size reports bytes after the latest collection, including fragmentation,
with `dotnet.gc.heap.generation` values `gen0`, `gen1`, `gen2`, `loh`, and `poh`.
The five generation-size EventCounters supply these values on .NET 8, 9, and 10.
Each value can increase or decrease and remains unchanged until another GC.
The runtime polls each generation separately; a GC during polling can span two
collection states. Missing values are omitted from that sampling round.

Heap fragmentation reports `FragmentationAfterBytes` for the same five generation
labels. OBI subscribes to CLR GC events and sums the free-list and free-object
bytes from every heap in the latest completed collection. Values remain
unavailable until a complete collection is observed after attachment or reconnect.
OBI does not request a GC. Complete values persist across sampling rounds and
can increase or decrease.

CPU time has separate `cpu.mode=user` and `cpu.mode=system` series. CPU count
reports the runtime's `Environment.ProcessorCount`, including its processor-count
override, container CPU quota, and processor affinity.

Exception counts are available on .NET 8+, including caught throws and
rethrows. On .NET 8, OBI subscribes to CLR `ExceptionThrown_V1` events through
EventPipe and counts each received throw by its short exception type name in
`error.type`. On .NET 9 and newer, OBI subscribes to the built-in
`System.Runtime` Meter's `dotnet.exceptions` instrument through
`System.Diagnostics.Metrics` EventPipe events. The Meter counts first-chance
exceptions and supplies the short type name. Counts start at attachment and
retain published totals across reconnects.

OBI retains at most 128 distinct names of at most 1,024 bytes each across
reconnects. Additional or overlong names count under `_OTHER`. The decoder reads
the exception type and skips the message in the native event payload.
On .NET 8, each throw produces an event that OBI aggregates. On .NET 9 and newer,
the runtime aggregates measurements and sends interval deltas. OBI publishes
counts with each completed counter polling round.

The Meter subscription tracks at most 128 time series per session. The runtime
omits additional types and OBI logs the limit. Runtime Meter instrumentation
adds per-throw work and allocations.

The Meter provider permits one exclusive diagnostics subscription at a time.
If another client owns it, OBI logs the conflict and omits exception updates for
that session while collecting other runtime metrics. Reconnection retries the
subscription. In-process MeterListeners can coexist with this subscription.

Enable .NET runtime metrics through the shared runtime metrics feature:

```yaml
metrics:
  features:
    - application_runtime
```

`dotnet_runtime_metrics.sampling_interval` controls `System.Runtime` EventCounter
polling, exception Meter refresh, and the delay before reconnecting after a
collection session ends. The runtime clamps Meter refresh intervals below
100 ms to 100 ms.
`dotnet_runtime_metrics.timeout` bounds diagnostic IPC setup and the final
EventPipe shutdown and drain.

```yaml
dotnet_runtime_metrics:
  sampling_interval: 1s
  timeout: 10s
```

Both settings must be positive. Their environment variables are
`OBI_DOTNET_RUNTIME_METRICS_SAMPLING_INTERVAL` and
`OBI_DOTNET_RUNTIME_METRICS_TIMEOUT`.

## Collection path

.NET runtime metrics flow through diagnostic IPC and EventPipe to the shared
runtime metrics export queue:

1. Discovery starts one collector for each selected .NET process.
2. A stable process handle provides the namespace PID and access to the target's
   temporary directory (`TMPDIR`, or `/tmp`).
3. `ProcessInfo2` verifies the socket's PID and confirms that the CLR version is
   .NET 8+.
4. The collector starts an EventPipe session and decodes its NetTrace stream.
   The `ProcessorCount` event supplies the CPU count retained for that session.
   CLR GC events are ordered using NetTrace watermarks, then grouped by collection
   and emitting thread. Fragmentation requires the completion event and every
   expected heap record; overlapping full and ephemeral collections are tracked
   separately.
5. Sampling rounds containing GC counts, cumulative counters, and available
   current values enter the runtime metrics queue and reach the OTLP and
   Prometheus exporters.

Before publishing each round, OBI reads user and system CPU ticks from
`/proc/<pid>/stat` through the stable process handle and converts them to seconds.
These are process-lifetime totals sampled at publication time. A failed read
omits CPU time from that round while the other available metrics still publish.

The first sample for each generation establishes a baseline. Exported totals
therefore cover collection after attachment, rather than the process lifetime.
The runtime polls generation counters separately, so sampling boundaries are
approximate. OBI defers inconsistent or decreasing exclusive totals until a
later complete round catches up.

Allocation bytes, GC pause time, JIT compilation time, completed work items,
and monitor lock contentions also cover collection after attachment. Each
counter's first increment establishes its baseline; later increments accumulate
in the collector. GC pause and JIT compilation durations use seconds.
Compiled IL bytes and compiled method counts use the runtime's absolute
process-lifetime totals, including their first observed values.

An unavailable counter is omitted from that sampling round and retains its
baseline. Each exporter tracks the last published value per process and adds
its increase to the shared service counter. A process exit preserves the
exported cumulative total, and a replacement process establishes its own
baseline. Current-value metrics reflect the latest available process values.

On stream loss, OBI reconnects while the process is alive and preserves the last
published attachment-relative totals. Increments during the gap are unavailable;
CPU time and the two absolute JIT counters continue to report process-lifetime values.
Process removal cancels collection; shutdown sends `StopTracing` while draining
the stream.

## Requirements and limitations

This collector accepts .NET 8+. Integration coverage targets .NET 8, 9,
and 10. Later versions can attempt collection, but compatibility is not guaranteed.
CLR versions below 8 are skipped.

OBI must be able to access the target process through `/proc`, including its
root filesystem, and connect to its diagnostic socket. Socket lookup uses the
application's absolute `TMPDIR`, or `/tmp` when unset, inside that filesystem.

Keep the application's default diagnostic port enabled.
`DOTNET_EnableDiagnostics=0` disables collection.

The implementation requests a 16 MiB EventPipe buffer per process. Detected
event loss discards unpublished counts and triggers reconnection. Exceptions
during the gap are unavailable, and late loss reports cannot retract previously
published counts.

Fragmentation collection buffers at most 4,096 decoded GC events and accepts up
to 4,096 heaps per collection. Malformed or ambiguous GC histories, event loss,
or capacity limits end the session and trigger reconnection. The new session
waits for fresh GC history. Native payload versions are checked; 32-bit layouts
have unit coverage, while live coverage uses Linux amd64.
