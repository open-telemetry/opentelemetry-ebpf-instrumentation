# BPF metrics collection

The BPF metrics collector reports execution statistics for eBPF programs and
entry counts for eBPF LRU hash maps loaded on the host.

Which programs the collector covers depends on the
[collection path](#collection-paths):

- The Prometheus collector describes the node. Every collection walks the
  kernel's complete program ID namespace from the beginning, so it captures all
  existing programs, including programs that were not loaded by OBI. A later
  collection also discovers programs loaded after the collector started.
- The internal collector describes OBI. It reports only the programs OBI holds
  a file descriptor for, directly or through a link, as listed in
  `/proc/self/fdinfo`.

Map metrics are host-wide on both paths.

## Supported kernel objects

Both collectors report programs of every eBPF program type.

The collector reports entry counts only for `LRUHash` maps. Other map types are
still encountered during the host-wide walks, but they are not emitted as
metrics.

## Collection paths

BPF metrics can be collected through either of these paths:

- The Prometheus BPF collector is active when a Prometheus endpoint is enabled
  and the `ebpf` metrics feature is selected.
- The internal metrics collector is active when
  `internal_metrics.bpf_metric_scrape_interval` is greater than zero. The
  configured internal reporter exports the collected values through
  Prometheus or OpenTelemetry.

If both paths are active, each path owns a separate collector.

### Prometheus collector metrics

| Metric | Type | Labels |
| --- | --- | --- |
| `bpf_probe_latency_seconds` | Histogram | `bpf_probe_id`, `bpf_probe_type`, `bpf_probe_name` |
| `bpf_map_entries` | Gauge | `bpf_map_id`, `bpf_map_name`, `bpf_map_type` |
| `bpf_map_max_entries` | Gauge | `bpf_map_id`, `bpf_map_name`, `bpf_map_type` |

### Internal metrics

| Prometheus metric | OpenTelemetry metric | Value |
| --- | --- | --- |
| `obi_bpf_probe_executions_total` | *(none: see `obi.bpf.probe.latency` count)* | Probe executions |
| `obi_bpf_probe_latency_seconds_total` | `obi.bpf.probe.latency` | Probe latency distribution in seconds |
| `obi_bpf_map_entries` | `obi.bpf.map.entries` | Current map entry count |
| `obi_bpf_map_max_entries` | `obi.bpf.map.max_entries` | Configured maximum map entries |
| `obi_bpf_ringbuf_writes_total` | `obi.bpf.ringbuf.writes` | Attempted ring buffer writes by map name |
| `obi_bpf_ringbuf_write_failures_total` | `obi.bpf.ringbuf.write.failures` | Failed ring buffer writes by map name |

Probe metrics use the program ID, type, and function name as attributes or
labels. Map metrics use the map ID, type, and name. Both endpoints take these
from one declaration, so the OTLP attribute key and the Prometheus label name
cannot drift apart.

## Program discovery and statistics

The collector enables kernel BPF runtime statistics for its lifetime so that
accounting continues between collections. Each collection lists the program
IDs of its path and reads `Stats()` from every reported program. Metadata is
cached when a program is first observed. Each reported program is opened
temporarily to read its statistics and closed before collection continues.

The kernel accounts executions and runtime only to the program it enters. A
program reached through a tail call keeps zero executions, and its runtime is
included in the program that made the tail call.

The runtime is spent in the context that runs the program. A kprobe or
tracepoint adds it to every process that calls the probed kernel function,
because process filtering happens inside the program. A uprobe adds it to the
processes that run the probed binary. An iterator adds it only to the process
that reads it, which for OBI's TCP iterators is OBI itself.

The collector reports execution-count and runtime changes between collections
and derives probe latency by dividing the runtime change by the execution-count
change. The kernel exposes only these two totals, so all executions between two
collections are counted in the latency bucket of their average. The Prometheus
histogram exposes these counts as cumulative `le` buckets over every bound in
`imetrics.BpfLatenciesBuckets`. Runtime statistics are disabled when the
collector shuts down.

## Map discovery and entry counting

Each collection walks every map ID and caches metadata for newly observed maps.
For each `LRUHash` map, it opens a temporary handle, iterates the entries to
count them, and closes the handle. Missing metadata entries are removed after a
complete ID walk.
