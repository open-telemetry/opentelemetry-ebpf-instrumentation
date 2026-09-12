# .NET runtime metrics

With `application_runtime` enabled, OBI collects GC collection counts from
.NET 8 and newer processes on Linux through their diagnostic Unix sockets.

| OTel metric | Prometheus metric | Unit |
| --- | --- | --- |
| `dotnet.gc.collections` | `dotnet_gc_collections_total` | `{collection}` |

The `dotnet.gc.heap.generation` attribute identifies `gen0`, `gen1`, and `gen2`.
Counts are exclusive: a full gen2 collection adds one to gen2, while gen0 and
gen1 remain unchanged.

Enable .NET runtime metrics through the shared runtime metrics feature:

```yaml
metrics:
  features:
    - application_runtime
```

`dotnet_runtime_metrics.sampling_interval` controls `System.Runtime` EventCounter
polling and the delay before reconnecting after a collection session ends.
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
   .NET 8 or newer.
4. The collector starts an EventPipe session and decodes its NetTrace stream.
5. Complete GC sampling rounds enter the runtime metrics queue and reach the
   OTLP and Prometheus exporters.

The first sample for each generation establishes a baseline. Exported totals
therefore cover collection after attachment, rather than the process lifetime.
The runtime polls generation counters separately, so sampling boundaries are
approximate. OBI defers inconsistent or decreasing exclusive totals until a
later complete round catches up.

On stream loss, OBI reconnects while the process is alive and preserves the last
published totals. Collections during the gap are unavailable. Process removal
cancels collection; shutdown sends `StopTracing` while draining the stream.

## Requirements and limitations

This collector accepts .NET 8 and newer. Integration coverage targets .NET 8, 9,
and 10. Later versions can attempt collection, but compatibility is not guaranteed.
CLR versions below 8 are skipped.

OBI must be able to access the target process through `/proc`, including its
root filesystem, and connect to its diagnostic socket. Socket lookup uses the
application's absolute `TMPDIR`, or `/tmp` when unset, inside that filesystem.

Keep the application's default diagnostic port enabled.
`DOTNET_EnableDiagnostics=0` disables collection.

The implementation requests a 16 MiB EventPipe buffer per process and rejects
detected event loss instead of accumulating incomplete counter deltas.
