# BPF metrics collection

The BPF metrics collector reports execution statistics for eBPF programs and
sizes and entry counts for eBPF maps loaded on the host.

Which programs and maps the collector covers depends on the
[collection path](#collection-paths):

- The Prometheus collector describes the node. Every collection walks the
  kernel's complete program and map ID namespaces from the beginning, so it
  captures all existing programs and maps, including those that were not loaded
  by OBI. A later collection also discovers objects loaded after the collector
  started.
- The internal collector describes OBI. It reports only the programs and maps
  OBI holds a file descriptor for, as listed in `/proc/self/fdinfo`; a program
  can also be held through a link. These are the descriptors of the whole
  process: when OBI runs as a Collector receiver, the internal collector also
  reports the programs and maps of other components in the same Collector, such
  as the eBPF profiler.

## Supported kernel objects

Both collectors report programs of every eBPF program type. On the Prometheus
path this includes per-container programs, such as the cgroup device program
that container runtimes load for every container on cgroup v2. The number of
series then follows the number of containers on the node, and a restarted
container appears under a new program ID.

The internal collector does not list programs that only an OBI program array
keeps alive, such as the `uprobe_multi` copies of tail-call targets: the loader
places them in the array and keeps no descriptor for them. As tail-call targets
they never count executions, so the internal metrics lose no data.

Both collectors report the maximum entries of every map type, except
global-data maps. They report entry counts for `Hash`, `LRUHash`, `PerCPUHash`
and `LRUCPUHash` maps only. The count comes from walking the map's keys, and for
other types that walk does not count the entries in use: the walk of an array
returns every index, and ring buffers and storage maps have no keys. LPM tries
are not counted because walking a large trie on every collection is expensive,
and hash-of-maps hold inner maps rather than entries. The entries of a program
array are its filled tail-call slots; they are not counted yet.

The maximum entries are not always an entry count: for a ring buffer they are
the buffer size in bytes, for a program array the number of slots, and for a
perf event array usually one slot per CPU. Comparing entries with maximum
entries is meaningful for the hash maps only.

Global-data maps hold a program's global variables: one-slot arrays whose size
never changes. Loaders name them after their ELF section, `.rodata` with
cilium/ebpf and `<object>.rodata` with libbpf, and the collector recognises
them as arrays whose name contains `.rodata`, `.data`, `.bss` or `.kconfig`. A
loader that names them otherwise shows them as maps with one entry. On kernels
before 5.2 object names cannot contain a dot, cilium/ebpf drops it, and these
maps are reported as well.

The internal collector does not list maps that only OBI's programs keep alive.
On OBI these are global-data maps, whose descriptors the loader closes after
loading and which are not reported anyway.

Map names are the kernel names, cut to 15 characters, so two maps can share a
name, such as OBI's `python_exception_procs` and `python_exception_pending`;
`bpf_map_id` tells them apart. Maps that OBI shrinks for disabled features
report one maximum entry.

## Collection paths

BPF metrics can be collected through either of these paths:

- The Prometheus BPF collector is active when a Prometheus endpoint is enabled
  and the `ebpf` metrics feature is selected.
- The internal metrics collector is active when
  `internal_metrics.bpf_metric_scrape_interval` is greater than zero. The
  configured internal reporter exports the collected values through
  Prometheus or OpenTelemetry.

If both paths are active, each path owns a separate collector. Their program and
map walks never overlap: the Prometheus walks briefly hold descriptors of
programs and maps OBI did not load, and the internal collector must not read
them from `/proc/self/fdinfo` as OBI's own.

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

A Config v2 Collector receiver does not collect these, because collecting them
enables the kernel BPF stats host-wide.

Probe metrics use the program ID, type, and function name as attributes or
labels. Map metrics use the map ID, type, and name. Both endpoints take these
from one declaration, so the OTLP attribute key and the Prometheus label name
cannot drift apart.

## Program discovery and statistics

The collector enables kernel BPF runtime statistics for its lifetime so that
accounting continues between collections. Each collection lists the program
IDs of its path and reads `Stats()` from every reported program. Metadata is
cached when a program is first observed. Each reported program is opened
temporarily to read its statistics and closed before collection continues, so
each Prometheus collection opens every program on the node once.

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

Each collection lists the map IDs of its path and caches metadata for newly
observed maps. For each hash map, it opens a temporary handle, iterates the
entries to count them, and closes the handle. If the count fails, that
collection reports the map's maximum entries without an entry count. Missing
metadata entries are removed only after a complete list.
