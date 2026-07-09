# JVM runtime metrics

With `application_runtime` enabled, OBI collects HotSpot JVM memory values from
instrumented Java services and exports the following metric set.

OBI currently covers JVM memory metrics only. The attached HotSpot probes expose
memory-pool events; additional JVM runtime areas would need separate probe
support.

## Metrics

| OTel metric | Prometheus metric | Runtime source | Export behavior |
| --- | --- | --- | --- |
| `jvm.memory.used` | `jvm_memory_used_bytes` | HotSpot `hotspot:mem__pool__gc__*` USDT probes | Emits current used memory per JVM memory pool. |
| `jvm.memory.committed` | `jvm_memory_committed_bytes` | HotSpot `hotspot:mem__pool__gc__*` USDT probes | Emits current committed memory per JVM memory pool. |
| `jvm.memory.limit` | `jvm_memory_limit_bytes` | HotSpot `hotspot:mem__pool__gc__*` USDT probes | Emits configured maximum memory per JVM memory pool when HotSpot reports a finite value. |
| `jvm.memory.used_after_last_gc` | `jvm_memory_used_after_last_gc_bytes` | HotSpot `hotspot:mem__pool__gc__end` USDT probe | Emits per-pool used memory after GC completion. |

OBI emits standard JVM memory metric names. Heap and non-heap totals are
computed by summing `jvm.memory.used` series by `jvm.memory.type`.

Enable JVM runtime metrics through the shared runtime metrics feature:

```yaml
metrics:
  features:
    - application_runtime
```

JVM runtime metrics use `jvm_runtime_metrics.sampling_interval` only as a
sampling control. There is no separate JVM enable flag.

```yaml
jvm_runtime_metrics:
  sampling_interval: 1s
```

## Collection path

JVM runtime metrics flow through the generic tracer's HotSpot probes, the shared
event ring buffer, and the runtime metrics export queue:

1. During Java process discovery, userspace attaches USDT probes to
   `hotspot:mem__pool__gc__begin` and `hotspot:mem__pool__gc__end`.
2. Userspace parses `.note.stapsdt` metadata, writes USDT argument specs to BPF
   maps, and enables HotSpot semaphores for the attached probes.
3. The BPF probes sample according to `jvm_runtime_metrics.sampling_interval`,
   read HotSpot event arguments, and submit JVM runtime events through the shared
   BPF event ring buffer.
4. The generic tracer converts raw JVM events into `RuntimeMetricSnapshot`
   values and forwards them through the runtime metrics queue.
5. OTEL and Prometheus exporters consume queued snapshots, apply per-service
   `application_runtime` feature gating, and emit the metrics.

## Snapshot cadence

Snapshots update when HotSpot emits memory-pool GC probe events. A newly started
Java process emits JVM runtime metrics after the relevant HotSpot GC probes fire.
