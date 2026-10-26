# Java HttpClient async validation

The transport regression validates HTTPS HTTP/1.1 propagation and cleanup on
native amd64 and arm64 with Temurin 11.0.32.1, 17.0.20.1, and 21.0.12.1.
The sustained workload also reproduces sparse missing-header, parent-link, and
export gaps in the merged synchronous baseline. These results do not establish
unconditional trace continuity or support for other JDK vendors and releases.

## Revisions and reproduction

- Historical synchronous baseline: `dcb3f3dda1c23845530299be7f9fedb80071f404`.
- Upstream base: `9cb407e69b9417bbaf6a3ac668b032ba4dc0f62c`.
- Measured production implementation: `85bc6bac6`; binary SHA-256
  `6afb84612afc90edf92bfd782b0c486e948da391d75a9956b674d722e9785b44`.
- Baseline binary SHA-256:
  `8db8dc2bd9729e18b44f50f7f0ea0c4424a5988faca992c5e844beac8ec0675f`.
- Embedded agent SHA-256:
  `183cd9d9438151c4ff979bad607d04cea01d24571349e0b7af8a90c5fd99a591`.

Both binaries use `CGO_ENABLED=0` and matching build flags. Both JNI libraries
are byte-identical to the baseline. Subsequent fixture, diagnostics-test, CI,
and documentation commits do not change the measured production code.
[results.json](results.json) records binary, image, tool, kernel, runtime,
CPU-placement, and per-run identities. `measurement_checkout_revision` is the
runner's checkout revision; the binary hash identifies the measured executable.

Use the [load fixture instructions](../../../internal/test/integration/components/java_httpclient_traceparent/load/README.md).
The recorded run used a shared amd64 AMD EPYC 7R32 host with 16 logical CPUs,
Linux `7.0.0-1014-aws`, Temurin `21.0.12.1`, TLS 1.3, and
`TLS_AES_128_GCM_SHA256`. CPU sets for application, OBI, peer/downstream, and
driver were respectively `0,1,8,9`, `2,3,10,11`, `4,5,12,13`, `6,7,14,15`.
The application used a 512 MiB heap, G1, and four active processors.

Each measured run follows a 30-second warmup and lasts at least 120 seconds.
Concurrency 32 has three rounds of baseline sync, final sync, final async, and
final async with headers disabled; the second round reverses order. Separate
concurrency-128 runs compare baseline sync, final async, and disabled async.
The source's 64 handler threads mean concurrency 128 also measures queueing.
Incoming connections remain pooled; the source has no application SDK or
outgoing fixture header. The proxy records actual headers and forwards them
to a downstream using the standard OpenTelemetry Java agent 2.21.0.

## Sustained results

Counts are totals across the three C32 runs, or the single C128 run.
Missing headers apply only to enabled modes. Missing server, client, and
intermediate exports are independent counters.

| Concurrency / case | Requests | Missing header | Parent-link failure | Missing server | Missing client |
| --- | ---: | ---: | ---: | ---: | ---: |
| 32 / baseline sync | 2,829,895 | 3 | 3 | 3 | 4 |
| 32 / final sync | 2,819,062 | 5 | 5 | 5 | 5 |
| 32 / final async | 2,554,229 | 5 | 5 | 4 | 3 |
| 32 / async disabled | 2,551,977 | 0 | 2 | 2 | 5 |
| 128 / baseline sync | 972,818 | 1 | 1 | 1 | 1 |
| 128 / final async | 866,635 | 3 | 3 | 3 | 1 |
| 128 / async disabled | 856,903 | 0 | 2 | 1 | 4 |

Across all runs, HTTP errors, invalid/duplicate/wrong-trace received headers,
header/client-ID mismatches with a client export, downstream-parent mismatches,
missing downstream exports, duplicate spans, and ancestry cycles are zero.

Performance values below are medians of the C32 runs; C128 has one sample.

| Concurrency / case | Requests/s | p50 ms | p99 ms | Application CPU µs/request | OBI CPU µs/request |
| --- | ---: | ---: | ---: | ---: | ---: |
| 32 / baseline sync | 7,887.82 | 3.62 | 13.91 | 464.23 | 97.76 |
| 32 / final sync | 7,833.38 | 3.63 | 14.07 | 465.13 | 98.28 |
| 32 / final async | 7,087.49 | 4.10 | 16.64 | 532.11 | 98.94 |
| 32 / async disabled | 7,111.74 | 4.03 | 15.62 | 534.58 | 98.10 |
| 128 / baseline sync | 8,101.39 | 14.50 | 37.14 | 458.12 | 98.18 |
| 128 / final async | 7,216.35 | 16.30 | 40.59 | 526.82 | 99.44 |
| 128 / async disabled | 7,133.85 | 16.22 | 41.05 | 539.61 | 98.46 |

Across paired C32 async enabled/disabled controls, header propagation changes
throughput by -0.80% to +1.39%, application CPU per request by
-2.05% to -0.12%, OBI CPU per request by +0.38% to +1.01%,
and p99 latency by +5.39% to +9.53%. These are observed ranges, not confidence intervals.

Across all runs, heap after requested GC ranges from 18.55 to 24.00 MiB;
direct-buffer memory ranges from 0.52 to 0.54 MiB.

Missing-header samples have no header on the wire and a root client in another
trace despite an exported source server. The exact historical baseline has the
same pattern. Missing server exports are separate samples; equal counter totals
do not imply they describe the same requests. Capture acknowledgement and the
reason for each skipped injection are not observable in this fixture. These
failures remain failures; no counter is normalized into a successful correlation.

Header/client identity and downstream-parent checks apply to received headers.
A missing client export leaves identity unverified. Parent checks follow OBI
INTERNAL spans; missing intermediate exports are counted independently.
All per-run counters and representative failure records are in `results.json`.
The driver's all-zero response echo means no header was received; it is not an
all-zero `traceparent` injected onto the wire.

After a 12-second export drain, every run has Java state `0:0`, zero occupied
native reservation slots, and zero connection-index entries. The native arrays
and index still reserve about 2.24 MiB, including with propagation disabled.
Java counters do not measure kernel occupancy. Heap after requested GC and
direct-buffer memory, RSS, and process CPU are recorded separately.

TLS tracing stays enabled in the disabled-header control. Process CPU includes
user and system time; OBI process CPU excludes eBPF work charged elsewhere.
RSS includes committed heap. Live-thread allocation deltas do not measure total
allocation. Shared-host load, JIT, collector cost, and closed-loop queueing limit
performance conclusions; these measurements establish neither a general
overhead bound nor equivalence between sync and async API costs.

## Correctness and repository checks

- Java agent suites pass on JDK 8, 11, 17, and 21. The local JDK 8 suite has
  three expected skips because that runtime lacks the JDK HttpClient API.
- [Native transport CI](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/actions/runs/40414492610)
  passes all six JDK/architecture combinations, for both sync and async modes.
  The immediate Expect-Continue `417` case is explicitly skipped on JDK 11;
  unchanged baseline and uninstrumented controls hang with the same response,
  consistent with [JDK-8286171](https://github.com/openjdk/jdk/pull/9093).
- Lifecycle tests cover original-future ownership, callback races, cancellation,
  nested scopes, exceptional completion, and bounded abandoned tracking.
  Transport checks cover timeout, cancellation after headers, writes, TLS and
  connection failures, retry, redirect, authentication, pooled distinct parents,
  immutable reuse, supplied headers/flags, HTTP/2 exclusion/fallback, and recovery.
- The Java capacity transport case fills 10,000 identities with one synthetic
  unfinished exchange, then checks real HTTPS fail-open behavior and recovery.
  It does not represent 10,000 simultaneous TLS connections. Seven privileged
  `TestJavaHTTP1*` regressions independently pass native capacity, ownership,
  delayed cleanup, unsupported atomics, sequence exhaustion, and TCP-option checks.
- A startup-agent control without the OBI native control path preserves HTTPS
  success and connection errors, injects no header, and drains Java state.
- `make java-docker-build`, `make docker-generate`, `make compile`, `make verify`,
  focused Go checks, and Markdown lint pass. Generated files use repository
  tooling. Java bootstrap bytecode remains Java 8 compatible.

One earlier Java 21 HTTP/2 run could not locate a client export in the incoming
trace. Its failure is retained. Subsequent baseline and final controls each
passed 100 pooled HTTP/2 requests, followed by full local and six-platform CI
passes; the isolated failure's cause is not established.

## Evidence and environment limits

[raw-artifacts.json](raw-artifacts.json) lists sizes and SHA-256 checksums for
the raw receiver records, original per-run metadata, and container logs retained
under `testoutput/java-httpclient-async-validation/` in the validation workspace.
Those large files are untracked. Committed results retain failure examples and
all counters; the fixture and commands allow fresh reproduction.

Docker commands required sandbox escalation because this environment cannot
start its normal loopback sandbox. Markdown and schema lint used the host UID because the
default container user cannot read this checkout. The first completed baseline
was preserved while switching to faster raw-record compression; compression
and serialization occur after measurement. No completed timed run was discarded.
Some startup attach attempts logged a closed control socket despite the agent
loading. Warmup waited for the agent's version and capability properties;
receiver headers and exports were checked independently afterward.

The original amd64 CI failures also reproduced on upstream: Ubuntu 26.04 moved
[bpftool into a standalone package](https://packages.ubuntu.com/en/resolute/devel/bpftool),
and jq 1.8.1 changed the
filter expression's binding behavior. Narrow fixes install the standalone
package and bind the schema diagnostic before its predicates. Schema fixtures
pass both jq 1.7 and 1.8.1; unrelated diagnostics still fail lint.
