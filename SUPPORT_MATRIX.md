# OBI Support Matrix

This document defines the environments and artifact platforms that OBI documents as supported.

While OBI remains in Development, this matrix is informational and does not yet create a stable `v1`
compatibility contract. After OBI declares `v1`, the entries documented here become part of the
support matrix described in [VERSIONING.md](./VERSIONING.md).

## Release Artifacts

OBI publishes the following release artifacts for supported runtime platforms:

| Artifact | Supported platforms |
|:---------|:--------------------|
| `obi` binary archive | Linux `amd64`, Linux `arm64` |
| `k8s-cache` binary archive | Linux `amd64`, Linux `arm64` |
| `otel/ebpf-instrument` container image | Linux `amd64`, Linux `arm64` |
| `otel/ebpf-instrument-k8s-cache` container image | Linux `amd64`, Linux `arm64` |

Other operating systems and architectures may compile selected packages or stub implementations, but are not part
of the supported runtime matrix for OBI.

## Runtime Requirements

OBI supports Linux environments that meet all of the following requirements:

| Requirement | Supported |
|:------------|:----------|
| Kernel | Linux `5.8+` |
| RHEL-based kernel exception | Linux `4.18+` for RHEL-based distributions with required eBPF backports |
| BTF | Kernel must expose BTF information |
| CPU architecture | `amd64`, `arm64` |
| Privileges | Root, or the Linux capabilities required by the enabled OBI features |

RHEL-based distributions in scope for the `4.18+` exception include RHEL 8, CentOS 8, Rocky Linux 8, AlmaLinux 8,
and compatible derivatives that provide the required eBPF backports and BTF support.

## Validation Coverage

The support contract is broader than CI coverage, but the following environments are explicitly validated in
repository automation today:

| Area | Validation currently present in repo |
|:-----|:------------------------------------|
| Release artifacts | Linux `amd64` and Linux `arm64` archives and container images |
| Cross-compilation | Full OBI support path compiled for Linux `amd64` and Linux `arm64` |
| BPF verifier coverage (`x86_64`) | Kernel `5.15.152` (`x86_64`) and kernel `6.10.6` (`x86_64`) |
| BPF verifier coverage (`arm64`) | `arm64` runner coverage |
| VM integration tests | Kernel `5.15.152` (`x86_64`) and kernel `6.10.6` (`x86_64`) |

This document should only claim support beyond these validation points when there is an explicit maintainer decision
to do so.

## Protocol Instrumentation

OBI currently documents the following protocol-level instrumentation support:

This section describes language-agnostic protocol instrumentation. Some context propagation support is only available
through language-specific library instrumentation documented later in this file.

| Protocol | Versions | Methods or operations | Secure | Context propagation | Limitations |
|:---------|:---------|:----------------------|:------:|:-------------------:|:------------|
| HTTP | `1.0/1.1` | All | Yes | Yes | None documented |
| HTTP | `2.0` | All | Yes | No | Context propagation for HTTP/2 is only through Go library instrumentation |
| gRPC | `1.0+` | All | Yes | No | Long-lived connections started before OBI may use `*` for method names |
| MySQL | All | All | Yes | No | Prepared statements created before OBI started may miss query text |
| PostgreSQL | All | All | Yes | No | Prepared statements created before OBI started may miss query text |
| MSSQL | All | All | Yes | No | Prepared statements created before OBI started may miss query text |
| Redis | All | All | Yes | No | Existing connections may miss database number and `db.namespace` |
| MongoDB | `5.0+` | `insert`, `update`, `find`, `delete`, `findAndModify`, `aggregate`, `count`, `distinct`, `mapReduce` | Yes | No | No support for compressed payloads |
| Couchbase | All | All | Yes | No | Bucket or collection may be unknown if negotiation happened before OBI started |
| Memcached | All | ASCII text subset excluding `quit` and meta commands | Yes | No | Only the first key is recorded for multi-key retrieval; payload bytes are not captured |
| Aerospike | All | `GET`, `EXISTS`, `PUT`, `TOUCH`, `OPERATE`, `DELETE`, `SCAN`, `QUERY`, `BATCH`, `UDF` | No | No | compressed (type-4) payloads are not parsed; only operation metadata (namespace, set, key) is captured, not record/bin values; scan/query duration measured to the first response frame |
| Kafka | All | `produce`, `fetch` | Yes | No | Topic name lookup may fail for newer fetch API versions (`>= 13`) |
| MQTT | `3.1.1/5.0` | `publish`, `subscribe` | No | No | Only the first topic filter is used for subscribe; payload not captured |
| AMQP | `1.0` | `publish`, `process` | No | No | Userspace heuristic only; only transfer performatives create spans |
| SunRPC (ONC RPC) | All | TCP CALL on common programs (portmapper, mount, nfs, …) | Yes | No | TCP only; kernel + userspace fallback; RPCSEC_GSS hides arguments; procedure names not mapped yet |
| GraphQL | All | All | Yes | No | None documented |
| Elasticsearch | `7.14+` | `/_search`, `/_msearch`, `/_bulk`, `/_doc` | Yes | No | None documented |
| Opensearch | `3.0.0+` | `/_search`, `/_msearch`, `/_bulk`, `/_doc` | Yes | No | None documented |
| AWS S3 | All | `CreateBucket`, `DeleteBucket`, `PutObject`, `DeleteObject`, `ListBuckets`, `ListObjects`, `GetObject` | Yes | No | None documented |
| AWS SQS | All | All | Yes | No | None documented |
| SQL++ | All | All | Yes | No | None documented |
| GenAI | All | All | Yes | No | Supported vendors are OpenAI, Anthropic, Google AI Studio (Gemini), AWS Bedrock, Qwen (DashScope), generic embedding providers (Voyage AI, Cohere, Jina AI), Cohere (Rerank), Jina AI (Rerank), Voyage AI (Rerank), Qwen (DashScope) (Rerank), Ollama (native /api/chat and /api/generate), OpenAI-compatible gateways (LiteLLM, vLLM, LocalAI, OpenRouter, Ollama /v1/), and vector retrieval providers (Pinecone, Qdrant, Milvus, Zilliz, Chroma, Weaviate) |

## Runtime, Server, And Library Instrumentation

OBI supports two different compatibility categories for application observability:

- Network-level protocol instrumentation, which is language-agnostic.
- Runtime, server, library, and statistical instrumentation for selected environments and features.

### Runtime And Server Baselines

The following runtime and server baselines are currently documented or enforced in the repository:

| Runtime or server | Baseline |
|:------------------|:---------|
| Go applications | Go `1.17+` for library-level instrumentation |
| Java applications | JDK `8+` |
| Node.js async-hooks context propagation | Node.js `8.0+` |
| Python asyncio context propagation | Python `3.9+` with `uvloop` |
| Ruby applications | Ruby `3.0.2+` when served by Puma `5.0+` |
| nginx | HTTP server and reverse-proxy tracing validated on nginx `1.27.5` and `1.29.7` |

Additional language families may be instrumented through network-level tracing, but are not listed here unless the
repository documents a concrete runtime or library compatibility baseline.

### Go Library Instrumentation

OBI currently documents the following Go library compatibility baselines:

| Library | Baseline |
|:--------|:---------|
| `net/http` | `>= 1.17` |
| `golang.org/x/net/http2` | `>= 0.12.0` |
| `github.com/gorilla/mux` | `>= v1.5.0` |
| `github.com/gin-gonic/gin` | `>= v1.6.0`, `!= v1.7.5` |
| `google.golang.org/grpc` | `>= 1.40` |
| `net/rpc/jsonrpc` | `>= 1.17` |
| `database/sql` | `>= 1.17` |
| `github.com/go-sql-driver/mysql` | `>= v1.5.0` |
| `github.com/lib/pq` | all versions |
| `github.com/redis/go-redis/v9` | `>= v9.0.0` |
| `github.com/segmentio/kafka-go` | `>= v0.4.11` |
| `github.com/IBM/sarama` | `>= 1.37` |
| `go.mongodb.org/mongo-driver` | `v1: >= v1.10.1; v2: >= v2.0.1` |

### Go Global Trace API And Auto SDK Activation

OBI v0.11.0 can automatically activate the OpenTelemetry Go Auto SDK for spans created through the global
`otel.Tracer` API when the application has not registered a `TracerProvider`. See the
[runnable Go Trace API example](examples/go-trace-api/README.md).

All three canonical, unreplaced modules must be present in the inspected executable:

| Module | Compatibility baseline |
|:-------|:-----------------------|
| `go.opentelemetry.io/auto/sdk` | `>= v1.1.0` |
| `go.opentelemetry.io/otel` | `>= v1.33.0` |
| `go.opentelemetry.io/otel/trace` | `>= v1.33.0` |

Each OBI release recognizes module versions that were available and validated when that release was built. OBI
v0.11.0 recognizes `go.opentelemetry.io/auto/sdk` `v1.1.0`, `v1.2.0`, and `v1.2.1`, plus the exact `.0` releases of
`go.opentelemetry.io/otel` and `go.opentelemetry.io/otel/trace` from `v1.33.0` through `v1.44.0`. A module version
released later requires a newer OBI release that recognizes its canonical checksum.

OBI checks the modules independently. A missing module or checksum, a noncanonical checksum, any replacement of one
of these module paths, invalid build information, or a version not recognized by that OBI release prevents Auto SDK
activation.

Activation also requires all of the following:

- A 64-bit Linux `amd64` (`ELF64`/`EM_X86_64`) or `arm64` (`ELF64`/`EM_AARCH64`) executable.
- OpenTelemetry API and Auto SDK data layouts that OBI v0.11.0 recognizes.
- Every global Trace API and Auto SDK symbol that OBI needs to be present in the executable.
- Permission for OBI to use `bpf_probe_write_user`.

If OBI cannot determine the required field offsets, find a required symbol, attach all required instrumentation,
support the executable's ABI or architecture, or use `bpf_probe_write_user`, it does not activate the Auto SDK. When
OBI can observe calls to the global Trace API, it may still construct a synthetic span. A synthetic span may contain
the span name, parent relationship, status, and some primitive attributes, but it does not contain the instrumentation
scope, events, or requested span kind. If an SDK `TracerProvider` is already registered, OBI defers to that provider
rather than activating the Auto SDK or creating a competing synthetic span.

On Linux 5.10 and later, OBI requires effective `CAP_SYS_ADMIN` and kernel lockdown mode `[none]` to use
`bpf_probe_write_user`. On earlier supported or backported kernels, support depends on whether the kernel permits the
helper. These permission conditions are additional to the general OBI kernel, BTF, Linux, and architecture
requirements above.

In OBI v0.11.0, each application-authored span must fit within a 16 KiB encoded payload. Spans whose payloads exceed
this limit are not exported, and v0.11.0 does not report this condition with a metric or warning.

The general Go `1.17+` library-instrumentation baseline elsewhere in this matrix does not widen this v0.11.0 Auto SDK
allowlist.

### Statistical Metrics

OBI currently documents the following statistical instrumentation support:

| Metric | Scope | Description | Limitations |
|:-------|:------|:------------|:------------|
| TCP RTT | Node-wide statistical metric collection | Calculated from the kernel TCP `srtt_us` field | `src.port` may be `0` on the RST-receiver side; see [devdocs/metrics.md](devdocs/metrics.md) |
| TCP Failed Connections | Node-wide statistical metric collection | Counts TCP failed connections between two endpoints | `src.port` may be `0` on the RST-receiver side; see [devdocs/metrics.md](devdocs/metrics.md) |
| TCP Retransmits | Node-wide statistical metric collection | Counts data-segment and client-SYN retransmits | Server-side SYN-ACK retransmits are a separate event and not counted |
| TCP IO | Node-wide statistical metric collection | Count bytes transferred at the socket layer. When enabled, the eBPF probes fire on every `tcp_sendmsg` and `tcp_cleanup_rbuf` call, so consider enabling it standalone with `stats_tcp_io` if overhead is a concern. | On kernels older than ~6.5, traffic sent via `sendfile()` is not captured because it went through `tcp_sendpage` rather than `tcp_sendmsg`; on kernels 6.5+ the splice path was unified and `sendfile()` traffic is captured. The internal accumulation map size can be increased via the `ebpf.*` configuration knobs on nodes with many concurrent connections. |

## Runtime Metrics

When the `application_runtime` metrics feature is enabled, OBI collects
language-runtime metrics for the following environments:

| Runtime | Metrics | Mechanism | Requirements | Limitations | Status |
|:--------|:--------|:----------|:-------------|:------------|:-------|
| Go | `go.memory.*`, `go.goroutine.*`, `go.processor.limit`, `go.config.gogc` | uretprobe on the Go runtime GC path, reading runtime structures | Go binaries with ELF symbols (or version-table fallback for struct offsets) | Values refresh once per GC cycle | Experimental |
| Java (HotSpot) | `jvm.memory.used`, `jvm.memory.committed`, `jvm.memory.limit`, `jvm.memory.used_after_last_gc` | USDT probes on the HotSpot DTrace probes in `libjvm.so` | HotSpot-based JVM with compiled-in DTrace probes | Values refresh on GC events, throttled by `jvm_runtime_metrics.sampling_interval` | Experimental |
| Node.js | `nodejs.eventloop.time`, `nodejs.eventloop.utilization`, `nodejs.eventloop.delay.*` | in-process readings (`perf_hooks`) from the injected OBI agent, delivered over a `uv_fs_access` side channel decoded in eBPF | `application_runtime` alone injects the agent through the inspector (traces not required); `nodejs.enabled` (`OTEL_EBPF_NODEJS_ENABLED`) is on by default, set it to `false` to opt out; Node.js `14.10+` (`eventLoopUtilization` API) | Main-thread event loop only (`worker_threads` loops are not measured); 1s in-process sampling interval; inspector must be reachable (custom `SIGUSR1` handling or seccomp may prevent injection) | Experimental |

## Context Propagation Frameworks

OBI currently documents the following asynchronous or runtime-specific context propagation support:

| Framework | Runtime | Baseline | Limitations | Status |
|:----------|:--------|:---------|:------------|:-------|
| Go goroutines | Go | Go `1.18+` | Up to 3 nested levels of goroutines | Stable |
| Go channel span links | Go | Go `1.17+` | Receiver-side links only; supports `runtime.chansend1`, `runtime.chanrecv1`, and `runtime.chanrecv2`; `select` paths are not supported; requires `runtime.hchan` offsets | Experimental |
| Node.js async hooks | Node.js | Node.js `8.0+` | Custom handling of `SIGUSR1` might interfere | Stable |
| Ruby Puma server | Ruby | Ruby applications served by Puma | Only works with Puma server | Stable |
| Java thread pool | Java | JDK `8+` | None documented | Stable |
| Java virtual threads | Java | JDK `21+` | Log enrichment is skipped for requests handled on virtual threads | Stable |
| Python asyncio | Python | Python `3.9+` with `uvloop` | Only works with the `uvloop` event loop | Stable |

## GPU Instrumentation

OBI currently documents the following GPU execution instrumentation support:

| Library | Baseline | Instrumented primitives | Limitations |
|:--------|:---------|:------------------------|:------------|
| `libcuda` | `>= 7.0` | `cudaLaunchKernel`, `cudaGraphLaunch`, `cudaMalloc`, `cudaMemcpy`, `cudaMemcpyAsync` | None documented |

## Explicitly Out Of Scope

The following environments are outside the documented OBI support matrix:

- Non-Linux operating systems
- Linux architectures other than `amd64` and `arm64`
- Linux environments without BTF support
- Kernel versions earlier than Linux `5.8`, except for the documented RHEL-based `4.18+` exception
- Any distro- or runtime-specific compatibility claim that is not explicitly documented in this file
