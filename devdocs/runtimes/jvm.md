# JVM runtime metrics

With `application_runtime` enabled, OBI collects memory, class loading, thread,
and CPU values from instrumented Java services and exports the following metric
set.

## Metrics

| OTel metric | Prometheus metric | Runtime source | Export behavior |
| --- | --- | --- | --- |
| `jvm.memory.used` | `jvm_memory_used_bytes` | HotSpot `hotspot:mem__pool__gc__*` USDT probes | Emits current used memory per JVM memory pool. |
| `jvm.memory.committed` | `jvm_memory_committed_bytes` | HotSpot `hotspot:mem__pool__gc__*` USDT probes | Emits current committed memory per JVM memory pool. |
| `jvm.memory.limit` | `jvm_memory_limit_bytes` | HotSpot `hotspot:mem__pool__gc__*` USDT probes | Emits configured maximum memory per JVM memory pool when HotSpot reports a finite value. |
| `jvm.memory.used_after_last_gc` | `jvm_memory_used_after_last_gc_bytes` | HotSpot `hotspot:mem__pool__gc__end` USDT probe | Emits per-pool used memory after GC completion. |
| `jvm.class.loaded` | `jvm_class_loaded_total` | Java `ClassLoadingMXBean` | Emits the cumulative number of classes loaded since the JVM started. |
| `jvm.class.unloaded` | `jvm_class_unloaded_total` | Java `ClassLoadingMXBean` | Emits the cumulative number of classes unloaded since the JVM started. |
| `jvm.class.count` | `jvm_class_count` | Java `ClassLoadingMXBean` | Emits the current number of loaded classes. |
| `jvm.thread.count` | `jvm_thread_count` | Java `ThreadMXBean` | Emits current daemon and non-daemon platform thread counts, distinguished by `jvm.thread.daemon`. |
| `jvm.cpu.time` | `jvm_cpu_time_seconds_total` | Java `OperatingSystemMXBean` | Emits cumulative process CPU time when the JVM exposes it. |
| `jvm.cpu.count` | `jvm_cpu_count` | Java `OperatingSystemMXBean` | Emits the number of processors available to the JVM. |
| `jvm.cpu.recent_utilization` | `jvm_cpu_recent_utilization_ratio` | Java `OperatingSystemMXBean` | Emits recent process CPU utilization when the JVM exposes it. |

OBI emits standard JVM memory metric names. Heap and non-heap totals are
computed by summing `jvm.memory.used` series by `jvm.memory.type`.

Enable JVM runtime metrics through the shared runtime metrics feature:

```yaml
metrics:
  features:
    - application_runtime
```

`jvm_runtime_metrics.sampling_interval` controls HotSpot memory event sampling
and Java agent class, thread, and CPU collection.

```yaml
jvm_runtime_metrics:
  sampling_interval: 1s
```

`javaagent.enabled` (default `true`) controls the injected Java agent. Setting
it to `false` disables the agent-backed class, thread, and CPU metrics. HotSpot
memory metrics continue through their USDT probes, independently of the agent.
OBI logs a warning when `application_runtime` is enabled while the Java agent
is disabled.

## Collection path

JVM runtime metrics flow through the generic tracer's HotSpot probes and the
injected Java agent. Both paths use the shared event ring buffer and runtime
metrics export queue:

1. During Java process discovery, userspace attaches USDT probes to
   `hotspot:mem__pool__gc__begin` and `hotspot:mem__pool__gc__end`.
2. Userspace parses `.note.stapsdt` metadata, writes USDT argument specs to BPF
   maps, and enables HotSpot semaphores for the attached probes.
3. The BPF probes sample according to `jvm_runtime_metrics.sampling_interval`,
   read HotSpot event arguments, and submit JVM runtime events through the shared
   BPF event ring buffer.
4. When the Java agent is enabled, OBI starts its runtime sampler during agent
   attachment. The sampler reads the JVM management beans according to
   `jvm_runtime_metrics.sampling_interval` and sends class, thread, and CPU
   snapshots through the agent ioctl channel.
5. The generic tracer converts both raw JVM event types into `RuntimeMetricSnapshot`
   values and forwards them through the runtime metrics queue.
6. OTEL and Prometheus exporters consume queued snapshots, apply per-service
   `application_runtime` feature gating, and emit the metrics.

## Snapshot cadence

Memory snapshots update when HotSpot emits memory-pool GC probe events, subject
to `sampling_interval`. Class, thread, and CPU snapshots update at the same
configured interval after Java agent attachment.

Intervals shorter than the 1 second default increase management-bean CPU and
allocation costs proportionally. The Java agent contains a JMH benchmark for
measuring collection cost on the target JVM before selecting a shorter interval.
