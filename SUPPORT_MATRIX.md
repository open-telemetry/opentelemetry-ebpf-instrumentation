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
| BPF verifier coverage | Kernel `5.15.152` (`x86_64`), kernel `6.10.6` (`x86_64`), and `arm64` runner coverage |
| VM integration tests | Kernel `5.15.152` (`x86_64`) and kernel `6.10.6` (`x86_64`) |

This document should only claim support beyond these validation points when there is an explicit maintainer decision
to do so.

## Language And Library Instrumentation

OBI supports two different compatibility categories for application observability:

- Network-level protocol instrumentation, which is language-agnostic.
- Library-level instrumentation for selected runtimes and libraries.

### Language Runtime Baselines

The following runtime baselines are currently documented or enforced in the repository:

| Runtime | Baseline |
|:--------|:---------|
| Go applications | Go `1.17+` for library-level instrumentation |
| Java applications | JDK `8+` |
| Node.js async-hooks context propagation | Node.js `8.0+` |
| Python asyncio context propagation | Python `3.9+` with `uvloop` |

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
| `go.mongodb.org/mongo-driver` | `>= v1.10.1`, `>= v2.0.1` |

## Explicitly Out Of Scope

The following environments are outside the documented OBI support matrix:

- Non-Linux operating systems
- Linux architectures other than `amd64` and `arm64`
- Linux environments without BTF support
- Kernel versions earlier than Linux `5.8`, except for the documented RHEL-based `4.18+` exception
- Any distro- or runtime-specific compatibility claim that is not explicitly documented in this file
