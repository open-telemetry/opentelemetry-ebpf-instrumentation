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
| Redis | All | All | Yes | No | Existing connections may miss database number and `db.namespace` |
| MongoDB | `5.0+` | `insert`, `update`, `find`, `delete`, `findAndModify`, `aggregate`, `count`, `distinct`, `mapReduce` | Yes | No | No support for compressed payloads |
| Couchbase | All | All | Yes | No | Bucket or collection may be unknown if negotiation happened before OBI started |
| Memcached | All | ASCII text subset excluding `quit` and meta commands | Yes | No | Only the first key is recorded for multi-key retrieval; payload bytes are not captured |
| Kafka | All | `produce`, `fetch` | Yes | No | Topic name lookup may fail for newer fetch API versions (`>= 13`) |
| MQTT | `3.1.1/5.0` | `publish`, `subscribe` | No | No | Only the first topic filter is used for subscribe; payload not captured |
| GraphQL | All | All | Yes | No | None documented |
| Elasticsearch | `7.14+` | `/_search`, `/_msearch`, `/_bulk`, `/_doc` | Yes | No | None documented |
| Opensearch | `3.0.0+` | `/_search`, `/_msearch`, `/_bulk`, `/_doc` | Yes | No | None documented |
| AWS S3 | All | `CreateBucket`, `DeleteBucket`, `PutObject`, `DeleteObject`, `ListBuckets`, `ListObjects`, `GetObject` | Yes | No | None documented |
| AWS SQS | All | All | Yes | No | None documented |
| SQL++ | All | All | Yes | No | None documented |
| GenAI | All | All | Yes | No | Supported vendors are OpenAI and Anthropic |

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

### Statistical Metrics

OBI currently documents the following statistical instrumentation support:

| Metric | Scope | Notes |
|:-------|:------|:------|
| TCP RTT | Node-wide statistical metric collection | Calculated from the kernel TCP `srtt_us` field |
| TCP Failed Connections | Node-wide statistical metric collection | Counts the TCP failed connections between 2 endpoints |

## Context Propagation Frameworks

OBI currently documents the following asynchronous or runtime-specific context propagation support:

| Framework | Runtime | Baseline | Limitations | Status |
|:----------|:--------|:---------|:------------|:-------|
| Go goroutines | Go | Go `1.18+` | Up to 3 nested levels of goroutines | Stable |
| Node.js async hooks | Node.js | Node.js `8.0+` | Custom handling of `SIGUSR1` might interfere | Stable |
| Ruby Puma server | Ruby | Ruby applications served by Puma | Only works with Puma server | Stable |
| Java thread pool | Java | JDK `8+` | None documented | Stable |
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
