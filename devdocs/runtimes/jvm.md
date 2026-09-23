# JVM runtime metrics

With `application_runtime` enabled, OBI collects memory, garbage-collection,
class loading, thread, and CPU values from instrumented Java services and
exports the following metric set.

## Metrics

| OTel metric | Prometheus metric | Runtime source | Export behavior |
| --- | --- | --- | --- |
| `jvm.memory.used` | `jvm_memory_used_bytes` | HotSpot `hotspot:mem__pool__gc__*` USDT probes | Emits current used memory per JVM memory pool. |
| `jvm.memory.committed` | `jvm_memory_committed_bytes` | HotSpot `hotspot:mem__pool__gc__*` USDT probes | Emits current committed memory per JVM memory pool. |
| `jvm.memory.limit` | `jvm_memory_limit_bytes` | HotSpot `hotspot:mem__pool__gc__*` USDT probes | Emits configured maximum memory per JVM memory pool when HotSpot reports a finite value. |
| `jvm.memory.used_after_last_gc` | `jvm_memory_used_after_last_gc_bytes` | HotSpot `hotspot:mem__pool__gc__end` USDT probe | Emits per-pool used memory after GC completion. |
| `jvm.gc.duration` | `jvm_gc_duration_seconds` | Java `GarbageCollectionNotificationInfo` | Histogram of per-cycle GC durations, with `jvm.gc.name` and `jvm.gc.action`; one observation per collection. |
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
and Java agent class, thread, and CPU collection. GC durations are observed per
collection and are not subject to this interval.

```yaml
jvm_runtime_metrics:
  sampling_interval: 1s
```

The GC histogram boundaries default to the semconv advisory values and can be
overridden through the exporter `buckets.jvm_gc_duration_histogram` option.

`javaagent.enabled` (default `true`) controls the injected Java agent. Setting
it to `false` disables the agent-backed GC duration, class, thread, and CPU
metrics. HotSpot memory metrics continue through their USDT probes,
independently of the agent. OBI logs a warning when `application_runtime` is
enabled while the Java agent is disabled.

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
4. When the Java agent is enabled, OBI starts its runtime sampler and registers
   GC notification listeners during agent attachment. The sampler reads the JVM
   management beans according to `jvm_runtime_metrics.sampling_interval`. The
   listeners report each completed collection. Both paths send their values
   through the agent ioctl channel.
5. The generic tracer converts the raw JVM events into `RuntimeMetricSnapshot`
   values and forwards them through the runtime metrics queue.
6. OTEL and Prometheus exporters consume queued snapshots, apply per-service
   `application_runtime` feature gating, and emit the metrics.

## Attach refusals

The Java agent is attached over HotSpot's dynamic attach handshake, which
starts by sending `SIGQUIT` to the JVM. HotSpot reserves that signal and
rejects an application-level handler for it outright (`Signal already used by
VM or OS: SIGQUIT`), so a JVM normally answers with a thread dump rather than
dying. OBI still withholds the signal unless the kernel confirms it cannot
terminate the process, and logs one reason when it does:

- `SigCgt`/`SigIgn` in the process status file show `SIGQUIT` neither caught
  nor ignored, so sending it would terminate the process. This is what `-Xrs`
  produces, and what native code restoring the default disposition produces. A
  JVM is also briefly in this state between `exec` and `Threads::create_vm`
  installing the handler, so OBI waits for it to settle before giving up;
- the process status file could not be read;
- the process is an OpenJ9 VM that has not started its attach listener, for
  example under `-Dcom.ibm.tools.attach.enable=no`. OpenJ9 attaches through a
  file and semaphore handshake and never in response to a signal, so an OpenJ9
  VM whose listener is running is attached that way and is never signalled;
  one without a listener would only write a javacore;
- the process runs with `-XX:+DisableAttachMechanism`. The option sources are
  read in the order HotSpot applies them, so a command line turning the
  mechanism back on is honored. Such a JVM catches `SIGQUIT` and survives it,
  but never starts the attach listener, so the signal only buys a thread dump in
  the application's own output.

A JVM started with `-Xrs` is therefore left uninstrumented rather than killed.
There is no option to force the signal, because the alternative is terminating
the application. Two configurations make such a JVM instrumentable again:
removing `-Xrs`, or adding `-XX:+StartAttachListener`, which makes HotSpot
create the attach socket during startup — OBI then finds it already listening
and attaches without signalling at all.

The wait for a runtime to install its handler is bounded, and a JVM still
without one when it elapses is refused for the rest of its lifetime: injection
is attempted once per process and is not retried. A JVM whose startup is slow
enough to exceed the wait — a large heap under `-XX:+AlwaysPreTouch`, or a
CPU-throttled container — can be refused this way even though nothing is wrong
with it.

`-XX:+DisableAttachMechanism` is detected from the command line and from
`JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS` and `_JAVA_OPTIONS`, each read from the
environment because the launcher expands them after `exec` and they never reach
the command line. Only the arguments HotSpot parses as VM options are read: the
scan stops at the main class, or at the argument after `-jar`, so a launcher
passing the flag on to a child JVM does not read as the flag of the process
holding it.

A JVM that sets the option through a flags file, or through a quoted value in
one of those variables, is not detected, and still receives one `SIGQUIT` and
writes one thread dump.

`JDK_JAVA_OPTIONS` is only read by the JDK 9+ launcher, but OBI honours it on
any JDK: a JDK 8 process in an environment that sets it is left alone even
though its own launcher ignored the option. That follows the operator's stated
intent to disable attach, at the cost of not instrumenting a JVM that would in
fact have answered.

## Snapshot cadence

Memory snapshots update when HotSpot emits memory-pool GC probe events, subject
to `sampling_interval`. Class, thread, and CPU snapshots update at the same
configured interval after Java agent attachment. GC duration observations are
event-driven and update after every collection reported by the JVM.

Intervals shorter than the 1 second default increase management-bean CPU and
allocation costs proportionally. The Java agent contains a JMH benchmark for
measuring collection cost on the target JVM before selecting a shorter interval.
