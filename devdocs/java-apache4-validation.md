# Apache HttpClient 4 validation evidence

Apache 4.5.14 synchronous JSSE HTTPS/HTTP/1.1 propagation passed the native
runtime matrix below and repeated sustained-concurrency checks. Supplied context,
unsupported writes, Expect exclusions, failure recovery, and ownership cleanup
are covered by the canonical transport suite.

## Revisions and reproduction

The load candidate is `c6cb7d42b6abe445d24aff1e1f2dacb6bd6c815d`, based on
main `1d6df6a4ce8db0de39c5924da14eb1bc20667013`, including #3798 and #3941.
Candidate SHA-256:
`d85b9ef181ac21031d7c306aa0fd349d0ddedf0e9b1c90b0b0cfb70df38dd29c`.
Main control SHA-256:
`5ad664ca949b5724f4c140dccce0315a7362c191e8e45586a8d6017bf637de32`.
The control used base-generated BPF and a Go overlay restoring the only changed
production Go files and embedded JAR to that base; input hashes are recorded.
An earlier negative Apache control on this same main binary received no injected
headers in 36,833 measured requests.

CI tested merge `8f957d705d828c4db184f0d6e2b1431d9c3e3897` of PR head
`e20172ece9e9dbd37abd7faf5a33351ee0e7206f` onto newer main
`b107b7cd8ce6a02eedee4c562ed93ae6323c7f2f` (the black-box timing fix #3982).
The matched local measurements keep both binaries on the earlier frozen base.
Later changes record documentation, evidence, and the measured Apache test weight;
production code is unchanged.

[Commands and fixture](../internal/test/integration/components/java_apache_httpclient/validation/README.md)
reproduce the OBI-only source, uninstrumented TLS proxy, and standard OpenTelemetry
downstream. [Machine-readable evidence](java-apache4-validation.json) preserves
per-run metadata, counts, bounded anomaly examples, tool/binary hashes, and raw
archive hashes. Full synthetic archives remain at their recorded local paths;
they are not committed. Historical prototype and pre-body-fix load results are
not counted here.

## Native runtime matrix

All jobs passed Apache enabled/disabled cases. JDK 11/17/21 jobs also passed
existing JDK sync, async, cancellation, reentrant, HTTP/2, and fallback regressions.
These are native GitHub runners, separately from dual-architecture generation.
CI kernels were `7.0.0-1017-azure`; full build strings are in the JSON.

| Temurin runtime | amd64 | arm64 |
| --- | --- | --- |
| 8u504-b01 | [Pass](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/actions/runs/40936931084/job/123673555246) | [Pass](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/actions/runs/40936931084/job/123673555158) |
| 11.0.32.1+1 | [Pass](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/actions/runs/40936931084/job/123673555140) | [Pass](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/actions/runs/40936931084/job/123673555179) |
| 17.0.20.1+1 | [Pass](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/actions/runs/40936931084/job/123673555275) | [Pass](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/actions/runs/40936931084/job/123673555196) |
| 21.0.12.1+1-LTS | [Pass](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/actions/runs/40936931084/job/123673555143) | [Pass](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/actions/runs/40936931084/job/123673555258) |

Java 8 therefore has runtime evidence for this Apache path, beyond the Java 8
bytecode target. Other Apache versions, JDK layouts, and kernels require their
own runtime validation and existing capability gates.

## Sustained correctness

Each C32 case ran three times with fresh processes, 30-second warmups, 120-second
measurements, 128-byte custom-header values, and alternating case order. Each C128
case ran once with the same durations. C128 exceeds the 64 source handlers and
exercises queueing; forced Java-limit and native one-slot tests cover capacity
exhaustion separately. No application SDK or fixture header injection is used in
the source. Every measured egress request negotiated HTTP/1.1 and TLS 1.3 with
`TLS_AES_128_GCM_SHA256`. TCP-option propagation was disabled.

All measured cases had zero application errors; wrong-trace, malformed, duplicate,
or unexpected disabled headers; header/client identity mismatches; downstream
parent mismatches; source-header parent mismatches; cyclic ancestry; and duplicate
source, client, downstream, or span-ID exports. Missing exports leave identities
unverified and are not counted as successful identity checks.

Counts below are independent and may overlap. C/S/D means missing client/source
server/downstream exports. Parent gaps include missing intermediate INTERNAL spans
and uninjected generic roots; these are not counted as successful ancestry.

| Case | Requests | Uninjected | Missing C/S/D | Unverified header IDs | Parent gaps | Wrong-trace clients |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| Main JDK sync C32 | 2,910,593 | 7 | 4/7/0 | 4 | 7 | 7 |
| Apache enabled C32 | 3,253,178 | 5 | 1/5/0 | 1 | 5 | 5 |
| Apache disabled C32 | 3,437,104 | expected | 15/9/0 | — | 10 | 10 |
| Main JDK sync C128 | 1,020,845 | 0 | 0/0/0 | 0 | 0 | 0 |
| Apache enabled C128 | 1,121,520 | 2 | 1/2/0 | 1 | 2 | 2 |
| Apache disabled C128 | 1,182,066 | expected | 6/3/0 | — | 3 | 3 |

Disabled cases received no headers. In enabled cases, wrong-trace client records
occurred only in uninjected calls; every received header had the known incoming
trace ID, and every available header-bearing client export matched its parent-id.
Skipped calls can leave the downstream on a separate trace.

The matched main controls also show missed capture/export/ancestry records. These
observations are consistent with the existing bounded-state limitations accepted
in #3855; individual evictions are not instrumented, so their cause is not proven
per request. They are kept separate from injected-header corruption. Per-check
examples and all independent counters are retained in the JSON.

Each Apache warmup had 32 calls at C32 or 64 at C128 outside first-write
counter coverage, all without injected headers. These are recorded separately and excluded
from the measurement period; path availability does not guarantee coverage of
calls around attachment. All seven measured Apache skips were counted as
unavailable parent/reservation state.

Apache preparation counters include warmup and measurement. The unavailable bucket
combines parent-capture and reservation failures; the unchanged Java ioctl
contract does not distinguish individual decline reasons. Normal load had no
unsupported-header, application-owned, or Expect skips. Prepared does not prove
network delivery.

## Performance and retained state

Local load ran on amd64 Linux `7.0.0-1014-aws`, Temurin `21.0.12.1+1-LTS`,
with `-Xms512m -Xmx512m`, G1, and four active processors per JVM. Disjoint logical
CPU sets were source `0,1,8,9`, OBI `2,3,10,11`, peer `4,5,12,13`, and driver
`6,7,14,15`. OBI used `GOMAXPROCS=4`. Ranges below span the three C32 runs;
C128 has one observation per case. CPU units are process microseconds/request.

| Case | Requests/s | p50 ms | p99 ms | Source CPU | OBI CPU |
| --- | ---: | ---: | ---: | ---: | ---: |
| Main JDK sync C32 | 8060–8112 | 3.51–3.56 | 11.47–11.59 | 444.6–451.1 | 98.1–99.0 |
| Apache enabled C32 | 9021–9048 | 2.98 | 11.21–11.39 | 350.9–351.3 | 98.4–99.2 |
| Apache disabled C32 | 9518–9568 | 2.81–2.83 | 10.20–10.35 | 323.6–324.1 | 98.4–98.6 |
| Main JDK sync C128 | 8501 | 13.71 | 35.91 | 426.8 | 98.3 |
| Apache enabled C128 | 9339 | 12.05 | 37.05 | 338.5 | 99.8 |
| Apache disabled C128 | 9847 | 11.38 | 35.33 | 312.1 | 100.0 |

At C32 the enabled median throughput was 5.4% lower than disabled.
These are shared-host observations, not an isolated causal overhead estimate or
a significance test. Cross-client performance differences also include the JDK
and Apache implementations. OBI process CPU excludes eBPF work charged elsewhere;
RSS includes committed memory. Live-thread allocation counters are not used as
allocation estimates.

After every drain, Java tracked requests/retained reservations were `0:0`, and
native reservation slots and connection-index entries were zero. In candidate
cases, active Apache executions and native Java write scopes were also zero.
After requested GC, source heap
was at most 21.3 MiB and direct buffers at most 0.54 MiB. Full before/after,
GC, peak RSS, and fixed map-memory measurements are retained per run. The native
body guard adds one 8-byte owner ID per existing HTTP record; at this fixture's
30,000-entry capacity the HTTP-map accounting increased by 240,000 bytes.

## Regression and validation checks

A pre-fix TLS reproduction flushed headers, waited 200 ms, then wrote a body
beginning `GET /__body_probe__ HTTP/1.1`. The native parser incorrectly exported
that body as a second request. The canonical regression now passes with bytes
preserved. The small native owner scope retains plaintext observation without
misclassifying that body; matching-ID release cannot clear a newer request.
Eight privileged tests also check ownership, capacity, unsupported atomics,
request-ID exhaustion, and TCP-option independence using actual kernel programs.

Validation passed: 178 agent tests on JDK 8/11/17/21; both embedded JNI
architectures; dual-architecture BPF generation; pinned LLVM 22.1.8 formatting and
lint; native BPF unit tests on amd64/arm64; compilation; main and collector
lint/race suites; the runtime matrix above; and Markdown lint.

Local verification used `GOMAXPROCS=4 GOFLAGS=-p=2 make verify -o install-hooks`.
The linked-worktree hook installer assumes a `.git` directory; staged C formatting
and schema checks ran through the existing hook, using the pinned LLVM wrapper.
Markdown lint used the pinned repository image with the workspace UID. Docker
provided Java/Gradle and LLVM. Required checks were completed through these
workarounds; no runtime claim is based solely on compilation.

The generic CI shard initially reached its 40-minute package timeout during
Kafka Compose startup after Apache passed in 1,129.6 seconds. The new suite had
the default 20-second weight. Its weight is now generated from that passing
report (1,130 seconds), preserving all existing test weights and coverage.
