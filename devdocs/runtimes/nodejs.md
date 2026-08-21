# Node.js runtime metrics

With `application_runtime` enabled, OBI collects event-loop, garbage-collection
and heap metrics from instrumented Node.js services and exports the following
metric set.

The values are the runtime's own `perf_hooks` and `v8` readings, reported by a
small JavaScript agent that OBI injects through the Node.js inspector — the
exported numbers match what the application itself would measure.

## Metrics

| OTel metric | Prometheus metric | Runtime source | Export behavior |
| --- | --- | --- | --- |
| `nodejs.eventloop.time` | `nodejs_eventloop_time_seconds_total` | `performance.eventLoopUtilization()` | Counter of cumulative loop time, attribute `nodejs.eventloop.state` = `idle` \| `active`. |
| `nodejs.eventloop.utilization` | `nodejs_eventloop_utilization_ratio` | `performance.eventLoopUtilization()` | Gauge in [0, 1]: active share of the last sampling interval, derived from the deltas of the cumulative idle/active times. |
| `nodejs.eventloop.delay.min` | `nodejs_eventloop_delay_min_seconds` | `monitorEventLoopDelay()` | Gauge; histogram minimum over the last sampling interval. |
| `nodejs.eventloop.delay.max` | `nodejs_eventloop_delay_max_seconds` | `monitorEventLoopDelay()` | Gauge; histogram maximum over the last sampling interval. |
| `nodejs.eventloop.delay.mean` | `nodejs_eventloop_delay_mean_seconds` | `monitorEventLoopDelay()` | Gauge; histogram mean over the last sampling interval. |
| `nodejs.eventloop.delay.stddev` | `nodejs_eventloop_delay_stddev_seconds` | `monitorEventLoopDelay()` | Gauge; histogram standard deviation over the last sampling interval. |
| `nodejs.eventloop.delay.p50` | `nodejs_eventloop_delay_p50_seconds` | `monitorEventLoopDelay()` | Gauge; 50th percentile over the last sampling interval. |
| `nodejs.eventloop.delay.p90` | `nodejs_eventloop_delay_p90_seconds` | `monitorEventLoopDelay()` | Gauge; 90th percentile over the last sampling interval. |
| `nodejs.eventloop.delay.p99` | `nodejs_eventloop_delay_p99_seconds` | `monitorEventLoopDelay()` | Gauge; 99th percentile over the last sampling interval. |
| `v8js.gc.duration` | `v8js_gc_duration_seconds` | `PerformanceObserver` `'gc'` entries | Histogram of per-cycle GC durations, attribute `v8js.gc.type` = `major` \| `minor` \| `incremental` \| `weakcb`; one observation per collection. |
| `v8js.memory.heap.limit` | `v8js_memory_heap_limit_bytes` | `v8.getHeapSpaceStatistics()` `space_size` | UpDownCounter (Prometheus gauge), attribute `v8js.heap.space.name`. |
| `v8js.memory.heap.used` | `v8js_memory_heap_used_bytes` | `v8.getHeapSpaceStatistics()` `space_used_size` | UpDownCounter (Prometheus gauge), attribute `v8js.heap.space.name`. |
| `v8js.memory.heap.space.available_size` | `v8js_memory_heap_space_available_size_bytes` | `v8.getHeapSpaceStatistics()` `space_available_size` | UpDownCounter (Prometheus gauge), attribute `v8js.heap.space.name`. |
| `v8js.memory.heap.space.physical_size` | `v8js_memory_heap_space_physical_size_bytes` | `v8.getHeapSpaceStatistics()` `physical_space_size` | UpDownCounter (Prometheus gauge), attribute `v8js.heap.space.name`. |

Enable Node.js runtime metrics through the shared runtime metrics feature:

```yaml
metrics:
  features:
    - application_runtime
```

The agent samples at a fixed 1 s interval, independently of the exporter
interval; there is no sampling-interval configuration because the interval is
compiled into the injected script. GC durations are the exception: they are
observed per collection cycle, not sampled. The GC histogram boundaries
default to the semconv advisory values and can be overridden through the
exporter `buckets.v8js_gc_duration_histogram` option.

The `application_runtime` feature alone enables the injection — traces are not
required. The metrics are produced by the injected agent running inside the
application, so enabling the feature starts injecting the agent into every
Node.js process OBI discovers, and each injection is logged with
`trigger=runtime metrics`. `nodejs.enabled` (default `true`) is the global
opt-out: setting it to `false` disables the injection entirely — runtime
metrics included — and OBI logs a warning when `application_runtime` is
enabled at the same time.

## Collection path

The injected agent reports in-process readings over an eBPF side channel:

1. During discovery, the Node.js injector opens the inspector (sending
   `SIGUSR1` if it is not already listening) and evaluates the OBI agent
   (`fdextractor.js`) through a single `Runtime.evaluate` message.
2. Every second the agent reads `performance.eventLoopUtilization()`
   (cumulative idle/active nanoseconds) and the `monitorEventLoopDelay()`
   histogram (reset after each read, so delay values are per-interval), and
   encodes the ten values as fixed-width hex into a synthetic path:
   `fs.accessSync("/dev/null/obi-rt/<10 × 16 hex chars>")`. On the same tick
   it walks `v8.getHeapSpaceStatistics()` and emits one
   `/dev/null/obi-v8/h…` record per heap space (four fixed-width values,
   the engine-defined space name last). GC cycles are pushed as they are
   observed: a `PerformanceObserver` emits one `/dev/null/obi-v8/g…` record
   per collection (kind and duration).
3. The generic tracer's `uv_fs_access` uprobe decodes the payloads
   (rejecting any malformed record — exact-length, hex and name-length
   validation), stamps kernel time and the calling thread's namespaced pid,
   and submits `EVENT_NODEJS_EVENTLOOP`, `EVENT_NODEJS_GC` and
   `EVENT_NODEJS_HEAP_SPACE` events through the shared BPF event ring
   buffer.
4. Userspace converts raw events into `RuntimeMetricSnapshot` values and
   forwards them through the runtime metrics queue.
5. OTEL and Prometheus exporters consume queued snapshots, apply per-service
   `application_runtime` feature gating, compute counter deltas and the
   utilization ratio, and emit the metrics.

## Requirements and limitations

- Node.js 14.10+ (`eventLoopUtilization` API) for the event-loop time and
  utilization metrics; the delay gauges additionally need Node.js 16.14+
  (`Histogram.count`). On 14.10–16.13 the agent reports a zero sample count,
  so the delay gauges are absent while ELU metrics keep working.
- The GC kind is read from `PerformanceNodeEntry.detail` (Node.js 16+), with a
  fallback to the pre-16 `entry.kind` accessor, so `v8js.gc.duration` works
  from the same 14.10 floor as the rest.
- Only the well-known `v8js.heap.space.name` values are exported
  (`new_space`, `old_space`, `code_space`, `map_space`,
  `large_object_space`). Semconv allows custom values, but the extra spaces
  V8 reports (`read_only_space`, `shared_space`, ...) are
  engine-version-dependent, so they are dropped before export
  (debug-logged) to keep the series set stable.
- The inspector must be reachable: injection is skipped when the application
  registers its own `SIGUSR1` handler, and fails when the environment blocks
  the inspector (e.g. seccomp) — in both cases the metrics are silently
  absent (an error is logged).
- **Main-thread event loop only**: `perf_hooks` are per-thread and the agent
  runs on the main isolate, so `worker_threads` loops are not measured (the
  same scope as the standard OTel Node.js SDK). See the design notes for
  options to extend coverage.
- Injection is single-shot per discovered process; a transient failure at
  process startup is not retried.
- The inspector port (9229) is per network namespace, so among processes that
  share one — `cluster` workers, for instance — only the first to bind it is
  injected; the others log an attach error and report no metrics.
- An interval in which the event loop never yielded (fully blocked) reports
  zero delay samples; the exporters keep the previous window's delay values.
