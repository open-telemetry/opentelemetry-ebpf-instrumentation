# Go runtime metrics

With `application_runtime` enabled, OBI collects Go runtime values from
instrumented Go services and exports the following metric set.

OBI resolves runtime globals from ELF object symbols when they are available.
Linux `amd64` also has a machine-code fallback for stripped Go binaries. The
fallback recovers the three mandatory globals: `runtime.gomaxprocs`,
`runtime.memstats`, and `runtime.gcController`. It also recovers `runtime.work`
for CPU statistics, the size-class table for allocation metrics, and
`runtime.sched` for histograms. It recovers `runtime.allglen` and `runtime.allp`
for goroutine counting.

## Stripped global recovery

Go retains function metadata in `.gopclntab` after `-ldflags=-s` removes the ELF
object symbols. The fallback parses this metadata to locate runtime functions
and read their bounded instruction ranges.

### Processor limit

The resolver locates
`runtime.procresize`, whose processor-count validation reads `runtime.gomaxprocs`.

On `amd64`, the resolver decodes `procresize` and matches this sequence:

```text
MOV  register, [RIP+displacement]
TEST register, register
JL   invalidArg
```

The `MOV` reads the four-byte `gomaxprocs` global. Its target ELF address is the
instruction address plus its length and signed displacement. The resolver
requires the complete, aligned four-byte candidate to belong to a readable and
writable `PT_LOAD` memory range. It uses the segment's in-memory size so globals
in zero-initialized BSS are valid, and rejects matches that identify different
addresses.

After validation, the resolver adds the executable's process load bias. The
resulting process address is the value that the BPF runtime metrics collector
uses to read `gomaxprocs` from the target process.

### Memory statistics

The resolver locates `runtime.(*mcache).refill` and
`runtime.(*consistentHeapStats).acquire` through the same Go function metadata.
Inside `refill`, Go calls:

```go
stats := memstats.heapStats.acquire()
```

On `amd64`, the receiver is passed in RAX. The resolver matches the instructions
that prepare the receiver and call the identified method:

```text
LEA  RAX, [RIP+displacement]  // Address of memstats.heapStats
CALL acquire                // Destination must match acquire's entry address
```

The LEA gives the incoming receiver's address. Subtracting its generated field
offset recovers the containing global:

```text
memstats base = heapStats address - heapStats field offset
```

The field offset is 5960 bytes for Go 1.17/1.18 and zero for Go 1.19 through 1.27.1.
The resolver rejects missing metadata, conflicting addresses, invalid alignment,
storage ranges, and arithmetic overflow. It then adds the process load bias
to obtain the base address in the target process.

### GC controller

Inside `runtime.gcinit`, the resolver matches the receiver passed to
`runtime.(*gcControllerState).init`. Go 1.18 inlines this method, so the resolver
also accepts its remaining call to `runtime.(*gcControllerState).setGCPercent`.
Both calls identify `&gcController` through the same LEA/CALL pattern used for
memory statistics, allowing NOP padding between the instructions.

Matches must agree on one address. The resolver checks its eight-byte alignment
and that its first eight bytes fit readable, writable storage, then adds the
process load bias.

### CPU statistics

Inside `runtime.putfull`, Go calls `work.full.push(&b.node)` to enqueue a full
GC work buffer. The resolver matches the receiver passed to
`runtime.(*lfstack).push`, then subtracts the generated `runtime.workType.full`
field offset to recover the `work` base.

Field metadata is available from Go 1.23, matching CPU metric support. The
resolver validates alignment, storage, and address arithmetic. If recovery fails,
the work address remains zero and CPU collection is skipped; the three mandatory
globals remain available.

### Allocation sizes

The size-class table is a global array of allocation sizes, named
`runtime.class_to_size` on older Go versions and
`internal/runtime/gc.SizeClassToSize` on newer versions. The collector combines
these sizes with `memstats.heapStats` allocation counts to calculate
`go.memory.allocated`. OBI enables it together with `go.memory.allocations`.

The resolver inspects `runtime.mallocgc` and `runtime.lockVerifyMSize`. In the
latter, an inlined `roundupsize` lookup reads `gc.SizeClassToSize[classIndex]`:

```text
LEA   RCX, [RIP+displacement]  // Calculate the global array's address.
MOVZX EAX, WORD PTR [RCX+RAX*2] // Read the uint16 entry indexed by RAX.
```

The matcher requires adjacent instructions, a shared base register, and a
two-byte indexed read with scale two. It validates readable, file-backed storage
for 68 entries: a reserved zero followed by strictly increasing multiples of
eight, starting at 8 and ending at 32768. Valid matches must agree on one address.
The resolver adds process load bias once; failure leaves allocation metrics
disabled while preserving the mandatory globals.

Address recovery has been checked against stripped compiler fixtures from
Go 1.17 through 1.27, including empty-main builds, and current-Go executable and
PIE builds. Allocation metrics require Go 1.23 or newer. Functional export
validation for stripped allocation metrics is still pending.

### Scheduler histograms

The global `runtime.sched` contains `timeToRun` for `go.schedule.duration` and
`stwTotalTimeGC` for `go.memory.gc.pause.duration`. The resolver locates this
structure through the goroutine-ID update in `runtime.oneNewExtraM`:

```go
gp.goid = sched.goidgen.Add(1)
```

It matches an address calculation immediately followed by an eight-byte atomic
update through the same register:

```text
LEA  RDX, [RIP+displacement]  // Address of sched.goidgen.
LOCK XADD QWORD PTR [RDX], RCX // Atomically update the eight-byte field.
```

The width check distinguishes this access from the four-byte `sched.ngsys`
update in the same function. Valid matches must agree on one aligned, readable
and writable field address. Subtracting the generated `runtime.schedt.goidgen`
offset recovers the structure's base; the resolver then adds process load bias.
Recovery failure leaves histograms disabled while preserving other metrics.
Functional export validation for stripped histograms is still pending.

### Goroutine list length

The global `runtime.allglen` records the length of the runtime's goroutine list,
including finished goroutines kept for reuse. The collector uses this total
with scheduler free-list counts to calculate `go.goroutine.count`.
The resolver locates the atomic length store in `runtime.allgadd`:

```go
atomic.Storeuintptr(&allglen, uintptr(len(allgs)))
```

It matches three adjacent instructions with consistent value and address registers:

```text
MOV  RCX, QWORD PTR [RIP+displacement] // Load len(allgs).
LEA  RDX, [RIP+displacement]           // Address of allglen.
XCHG QWORD PTR [RDX], RCX             // Atomically store the length.
```

The preceding global load distinguishes this sequence from the nearby `allgptr`
exchange. Valid matches must agree on one aligned address with eight readable
and writable bytes. The resolver adds process load bias to that address.
Recovery failure leaves goroutine counting disabled while preserving other metrics.

Address recovery passed exact-symbol comparisons for Go 1.17 through 1.27 fixtures,
including empty programs, and current-Go executable and PIE builds. Functional
export validation for stripped goroutine counting is pending.

### Scheduler processor list

The global `runtime.allp` is a slice of pointers to scheduler processors (Ps).
Each P holds a free list of finished goroutines. The collector reads these list
sizes and subtracts them, along with the scheduler's free-list counts, from
`allglen` to calculate `go.goroutine.count`.

The resolver uses the loop in `runtime.preemptall`:

```go
for _, pp := range allp {
```

Recovery follows three checks:

1. Identify eight-byte global loads of the backing-array pointer and slice length.
   The compiled sequence saves the pointer on the stack between these loads.
2. Follow the loaded registers to the loop's length comparison and indexed read.
   The matcher allows bounded setup instructions that preserve both registers.
   The comparison and read must use the same index, with an eight-byte stride.
3. Calculate the global field addresses. The length must sit eight bytes after
   the pointer, and the full 24-byte slice header must fit aligned, readable and
   writable storage. All valid candidates must agree on one header address.

The recovered address identifies the global slice header. Its pointer field leads
to the separate backing array. Process load bias is added once after recovery.
A missing address disables goroutine counting while preserving other metrics.
The existing field-offset and counting-mode checks also apply to stripped binaries.

Address recovery passed exact-symbol comparisons for Go 1.17 through 1.27 fixtures,
including empty programs, and current-Go executable and PIE builds. These checks
validate address recovery; functional export validation is still pending.

## Metrics

| OTel metric | Prometheus metric | Available since | Runtime source | Export behavior |
| --- | --- | --- | --- | --- |
| `go.memory.limit` | `go_memory_limit_bytes` | Go 1.19 | `runtime.gcController.memoryLimit` | Emits positive runtime memory limits; treats `math.MaxInt64` as the runtime's unset sentinel. |
| `go.memory.gc.goal` | `go_memory_gc_goal_bytes` | Go 1.17 | Exact committed heap goal | Reads `runtime.gcController.heapGoal` when its offset is available; otherwise captures the second argument of `runtime.gcPaceScavenger` when that symbol is available. If neither source is available, OBI omits the metric. Emits only positive values that fit in `int64`. |
| `go.memory.gc.cycles` | `go_memory_gc_cycles_total` | Go 1.17 | `runtime.memstats.numgc` | Emits the total completed GC cycle count. |
| `go.memory.gc.pause.duration` | `go_memory_gc_pause_duration_seconds` | Go 1.22 | `runtime.sched.stwTotalTimeGC` (`/sched/pauses/total/gc:seconds`) | Emits cumulative stop-the-world GC pause durations as a histogram. |
| `go.memory.used` | `go_memory_used_bytes` | Go 1.23 | `runtime.memstats.heapStats` and runtime sys stats | Emits `go.memory.type=stack` and `go.memory.type=other` values. |
| `go.memory.allocated` | `go_memory_allocated_bytes_total` | Go 1.23 | `runtime.memstats.heapStats` and Go size-class table | Emits cumulative allocated heap bytes. |
| `go.memory.allocations` | `go_memory_allocations_total` | Go 1.23 | `runtime.memstats.heapStats` | Emits the cumulative heap allocation count. |
| `go.cpu.time` | `go_cpu_time_seconds_total` | Go 1.23 | `runtime.work.cpuStats` | Emits cumulative CPU seconds with `go.cpu.state` and, where applicable, `go.cpu.detailed_state`. |
| `go.goroutine.count` | `go_goroutine_count` | Capability-based | `runtime.allglen`, `runtime.sched`, and `runtime.allp` | Emits the current goroutine count using the same free-list subtraction as `/sched/goroutines:goroutines`. |
| `go.processor.limit` | `go_processor_limit` | Go 1.17 | `runtime.gomaxprocs` | Emits the current `GOMAXPROCS` value. |
| `go.config.gogc` | `go_config_gogc_percent` | Go 1.17 | `runtime.gcController.gcPercent` | Emits non-negative `GOGC` percentages; a negative runtime value represents `GOGC=off`. |
| `go.schedule.duration` | `go_schedule_duration_seconds` | Go 1.20 | `runtime.sched.timeToRun` (`/sched/latencies:seconds`) | Emits cumulative runnable-to-running goroutine latency as a histogram. |

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
   the `runtime.gcMarkDone` return probe as the fallback collection point. The
   probe reads scalar runtime values with `bpf_probe_read_user` and submits a
   runtime snapshot through the shared BPF event ring buffer. Each available
   histogram is submitted as a separate event because its population array is
   much larger than the scalar snapshot.
5. The Go tracer converts runtime snapshot events into userspace
   `RuntimeMetricSnapshot` values and forwards them through the runtime metrics
   queue.
6. OTEL and Prometheus exporters consume queued snapshots at their export
   cadence, join them to current Go service metadata, apply metric export
   semantics, and emit the metrics.

## Histogram representation and export

The runtime histograms are already cumulative and pre-aggregated; OBI exports
their bucket populations rather than replaying individual observations. Go's
finite `timeHistogram` boundaries are 0, 64, 128, and 192 nanoseconds, followed
by `2^k + j*2^(k-2)` nanoseconds for `k=8..46` and `j=0..3`, and finally
`2^47` nanoseconds. OBI preserves those exact partitions as 161 finite explicit
bounds. For adjacent runtime boundaries `b[i]` and `b[i+1]`, the exported
upper-inclusive bound is `Nextafter(b[i+1], b[i])`; the infinite endpoints stay
in the underflow and overflow populations.

Go does not retain a histogram sum. OBI estimates a finite lower bound by
multiplying each population by its finite lower bucket boundary, treating the
underflow population as zero and the overflow population as its finite lower
boundary. The OTEL path exposes the cumulative explicit histogram through an
SDK `Producer`. The Prometheus path builds a const histogram from the same
counts, bounds, count, and estimated sum.

Histogram collection supports only Go 1.20's `timeHistogram` layout and
newer. Scheduler latency is available from Go 1.20; the GC pause field is
available from Go 1.22. OBI enables each histogram only when the required
runtime symbol and field offsets resolve, so unsupported versions are skipped
automatically.

## Snapshot cadence

Snapshots update when the version-appropriate GC probe fires. A newly started
process emits runtime metrics after it completes a GC cycle. Changes to `GOGC`,
`GOMEMLIMIT`, `GOMAXPROCS`, CPU counters, and memory counters appear in exported
metrics after the next completed GC. Scheduler latency observations accumulate
continuously but are captured only at this GC cadence, and a direct
`runtime/metrics` read is not atomic with the probe snapshot. The exported
histogram can therefore lag the service value or differ slightly because of
read skew until a later GC snapshot.
The GC goal captured from `runtime.gcPaceScavenger` is exported by the next
GC-cadence snapshot; a goal backed by `runtime.gcController.heapGoal` is read
during that snapshot. Goroutine count appears after the next completed GC.
