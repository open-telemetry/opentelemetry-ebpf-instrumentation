# Rust context propagation

OBI uses uprobes to track Tokio tasks, request queues used by Hyper and reqwest,
and rustls for TLS traffic.

## Runtime and library window

The versions supported are listed below:

| Component | Minor releases | Pinned validation versions |
| --- | --- | --- |
| Tokio | 1.51 through 1.54 | 1.51.6, 1.52.4, 1.53.3, 1.54.1 |
| reqwest | 0.10 through 0.13 | 0.10.10, 0.11.27, 0.12.28, 0.13.5 |
| Hyper | 1.9 through 1.12 | 1.9.0, 1.10.1, 1.11.1, 1.12.0 |
| Rustls | 0.20 through 0.23 | 0.20.9, 0.21.12, 0.22.4, 0.23.46 |

## Kernel-dependent header scans

Rust runtime instrumentation follows OBI's kernel support requirements. On kernels
with `bpf_loop` support (normally Linux 5.17+), forwarded HTTP/1 header rewriting
scans up to 16 KiB. Older kernels use the bounded legacy scan, which checks the
first 350 possible header positions. Tokio tracking, Rustls capture, and other
Rust probes remain available on these kernels.

## Binary requirements

The executable must retain its ELF function symbols (i.e. not stripped)
and the probed functions must not be inlined. Since LLVM inlines aggressively,
we have multiple backup probes to mitigate if our main probe target is
inlined on all or some call paths.

Concrete Hyper queue types must be identifiable in Rust v0 symbols, which are
the default for the recorded rustc baseline (1.97+). Legacy rustc symbol mangling
omits those type identities and cannot be used to select the request queue probes.

Runtime instrumentation uses retained ELF function symbols and a checked-in
offset database. Customer binaries do not need DWARF. DWARF is used only on OBI's
build-time fixtures to generate and validate the database, as with Go and Python
runtime offsets. OBI identifies compiler and library versions from the binary's
read-only metadata and selects the recorded layout.

Rust support is enabled independently for task tracking, Hyper handoffs, HTTP/1,
HTTP/2, and Rustls plaintext capture. When a candidate probe cannot be attached,
OBI closes that candidate's links and tries the next available alternative.

If all decoded HTTP/2 dispatch hooks are absent, generic traces still extracts
incoming stream headers. Those socket reads cannot assign an async parent to a
particular handler, so clients started from these handlers remain root spans.

Version detection uses retained compiler comments and crate version paths. When
the compiler comment is missing, the standard library's source paths identify
the compiler release. Crate versions come from Cargo registry, versioned vendor,
and Bazel `rules_rust` (`<hub>__<crate>-<version>`) source paths, combined with
the registry packages that `cargo auditable` records in `.dep-v0`. That list also
identifies builds whose paths carry no versions, such as default `cargo vendor`
layouts.
Unknown or conflicting identities disable only the dependent private layouts.
For example, an unrecorded Rustls layout leaves validated HTTP and Tokio layouts
available. An unavailable Hyper callback layout can use the Tokio queue-slot
layout instead.

For example, the sampled amd64 layouts changed as follows:

| Field | Older layout | Newer layout |
| --- | --- | --- |
| h2 HEADERS stream ID | 240 bytes in h2 0.2 | 280 bytes in h2 0.3/0.4 |
| Rustls plaintext buffer | 72 bytes in 0.20–0.22 | 80 bytes in 0.23 |
| Hyper request callback pointer | 264 bytes with reqwest 0.10 | 272 bytes with reqwest 0.11–0.13 |

## Offset generation and CI

`make update-offsets` updates Go, Python, and Rust. The language-specific commands
are `make update-go-offsets`, `make update-python-offsets`, and
`make update-rust-offsets`.

The standalone Rust updater discovers the latest four stable compiler minors
from Rust release tags, installs their toolchains, and builds the pinned fixture
matrix in [rust_versions.json](../../configs/offsets/rust_versions.json). Both
amd64 and aarch64 architectures are analyzed. On an amd64 host, ARM64 extraction requires
`aarch64-linux-gnu-gcc`.

```sh
make update-rust-offsets
make update-rust-offsets RUST_OFFSETS_FLAGS="--offline --work-dir /tmp/obi-rust-offsets"
```

The updater reuses previous analysis results and merges new offsets without
removing historical ones. Cargo lockfiles are generated in the work directory and
reused for DWARF extraction and both target architectures.
Analysis hashes include the resolved dependency graph so a changed graph triggers a
new analysis. `--force` rebuilds cached combinations. `--refresh-locks` resolves
dependencies again in the work directory. `--toolchains`,
`--targets`, and repeated `--case` options select a subset. It extracts DWARF only
from OBI's build-time fixtures. The standalone inspector also accepts existing
binaries:

```sh
go run ./scripts/rust-offsets -binary /tmp/rustcontext-debug -output /tmp/rust-offsets.json
```

The scheduled [offset workflow](../../.github/workflows/update-offsets.yml)
updates the compiler window and opens the existing generated-offset PR. The
[Rust integration jobs](../../.github/workflows/pull_request_integration_tests.yml)
read that same compiler manifest and run native amd64 and arm64 tests for every
compiler. Direct library versions are pinned in the manifest. The consolidated
[dependency snapshot](../../configs/offsets/rust_dependencies.json) records each
fixture's complete Cargo resolution, shared by generation and CI. The updater
refreshes changed manifests automatically; use `--refresh-locks` to refresh
transitive dependencies and regenerate their measured layouts.

## Context ownership

Tokio can move a task between OS threads and poll unrelated tasks on the same
worker. OBI therefore stores the parent server context under the task's
`Header` address, scoped to the instrumented process lifetime.

| Hook | Purpose |
| --- | --- |
| `tokio::runtime::task::list::OwnedTasks::bind_inner` entry or `Cell::new` return | Copy the spawning task's server context before the new task can be scheduled |
| Tokio 0.2 `Shared::schedule` during `Spawner::spawn` | Copy the parent before publication when legacy task allocation is inlined, without overwriting it on later wakes |
| `tokio::runtime::task::raw::poll` entry and return | Enter and leave the task on its current worker |
| `tokio::runtime::task::raw::dealloc` | Remove the context before the allocation can be reused |
| Tokio mpsc `Block<hyper::client::dispatch::Envelope<...>>::write` closure | Save the sender's context under the message slot address before publishing the slot |
| The corresponding `read` closure | Adopt the context only after the receiver has found a ready message, then remove the slot binding |

Retained alternatives cover inlining at several boundaries:

| Operation | Alternatives |
| --- | --- |
| Task poll / deallocation | Raw task vtable functions, then `Harness` methods |
| Task creation | Owned-task binding, `Cell`/`RawTask` allocation, scoped spawn-to-schedule publication |
| Hyper request handoff | Queue-slot identities, callback identities at channel/list boundaries, request header-allocation identities at Hyper dispatch |
| Rustls connection binding | `ConnectionCore::process_new_packets`, `ConnectionCommon::process_new_packets`, socket I/O scoped to `write_tls` or its `ChunkVecBuffer::write_to` boundary |
| Rustls reads | Peek/consume, `ChunkVecBuffer::read`, `Reader::read` |
| HTTP/1 formatting | Normal, title-case, and original-case header writers |
| HTTP/2 driver | `Send` buffer/poll methods, then `Prioritize` buffer/poll methods |
| HTTP/2 server dispatch | `StreamRef::take_request`, then `Recv::take_request` |
| HTTP/2 wire insertion | HPACK scratch append, then encoded-frame append. Both use the header-encoding boundary |

Optimized builds use the retained queue `Tx::push` and `Rx::recv` boundaries,
or `Tx::find_block` and `Rx::pop` when `push` is inlined. The offset database
identifies the callback allocation or queue slot for each message. They
distinguish individual messages, including messages from different requests on a
pooled connection. An ownerless message or missing map entry
clears the driver's previous parent instead of borrowing it for another request.

New tasks receive context snapshots, so a child can retain its parent when the
spawning task finishes. A spawned task can also outlive its request, such as a
database connection driver started by its first caller, so the inherited parent
is conditional: the link is kept only for client calls that start before that
request ends. New allocations overwrite old bindings and deallocation
removes them. Shared address keys include the PID to keep processes independent.
When an HTTP/1 `traceparent` arrives in a later read than the request line, the
reading task's context switches to the adopted trace. Hyper dispatches the
handler only after the headers, so no child task holds the provisional trace.

When the executable's compiler and architecture have no recorded symbol profile, OBI
keeps using generic parent lookup and socket propagation. The same fallback
applies when the attached hooks cannot track tasks or capture protocol data.

Tokio workers can poll unrelated tasks. When Rust instrumentation is active, OBI
uses a task-owned parent or a server request matching the outgoing wire trace
ID for Tokio client requests. A missing layout for one library leaves the other
supported groups active.
Nested polls are tracked up to eight levels.
The future passed directly to `Runtime::block_on` has no Tokio task allocation, so
task-based propagation starts with spawned tasks. Futures multiplexed inside a
single task share that task's context.

## Protocol coverage and limitations

The hooks supply the parent context to OBI's existing generic protocol
instrumentation. Wire injection and extraction follow
[the existing context propagation rules](../context-propagation.md).

With exporter exclusion enabled and the tpinjector active, Rust
header writers check its live exporter PID filter before modifying HTTP/1 or
HTTP/2 headers. Detection takes effect on existing connections and leaves
application-supplied headers unchanged, including over TLS.

Rustls probes associate encrypted socket I/O with a `ConnectionCommon` and
observe only successfully read or written plaintext. Both the `Read` path used
by older tokio-rustls releases and the peek/consume path are instrumented.
Vectored writes use the generic tracer's bounded iovec capture. Rustls capture
turns on only when a connection-binding hook, a plaintext read hook, and a
plaintext write hook all attach. Otherwise the generic tracer keeps the
connection, so it never waits for plaintext that would arrive in only one
direction.

HTTP/2 request contexts are keyed by the connection's send state and the stream ID.
Taking an incoming HTTP/2 request restores its stream context from the decoded
request headers before Hyper dispatches its handler. This also avoids spending
the generic HPACK parser's tail-call budget on each incoming Rust stream. A
stream without a `traceparent` header keeps the parent which the generic tracer knows
for its connection, e.g. from a TCP option or a correlated local client.
HTTP/2 metadata reads are bounded to the available plaintext so short Rustls
buffers do not produce empty header records at page boundaries.

When header propagation is enabled, OBI inserts a new HTTP/1 header just after
Hyper writes the request line. If the buffer lacks space or the write faults,
OBI retries after Hyper formats the application headers. HTTP/2 injection
appends a literal without indexing to a complete HEADERS frame. Both paths preserve an existing
application `traceparent`, validate buffer capacity, and skip insertion when
space or framing checks fail. The client span adopts the span ID of an
application header, unless the header is the incoming request's header
forwarded unchanged (e.g. a forwarding proxy). In that case the client span keeps
a new span ID, so it does not reuse the caller's span and become its own server's parent.
For HTTP/1, OBI rewrites the serialized header to that client context. The user-memory
path uses the shared `bpf_loop` scanner on newer kernels to inspect up to 16 KiB
of the formatted header block in 1 KiB chunks. Older kernels use the 350-position
legacy scan. Both paths stop when the header is found and support Rustls HTTPS
before encryption. A forwarded TLS header beyond the legacy window remains
unchanged, so downstream context can bypass the Rust client span. Cleartext
requests can use the tpinjector's scan when user-memory rewriting is unavailable.
HeaderMap inspection visits at most
64 distinct names. Header writes use the existing
`context_propagation` setting and kernel capability/integrity checks.

Rust publishes request ownership and the pending client context in shared maps
consumed by `tpinjector`. HTTP/1 ownership follows the active Tokio connection
task, while HTTP/2 ownership follows the connection's sender and stream ID. Both are
scoped to the instrumented PID. Successful Rust insertion and
application-created span headers suppress socket insertion for that request.
Forwarded HTTP/1 headers instead let the tpinjector write the saved Rust
client span ID and sampling flags. Pending
requests let `tpinjector` insert the same span context into cleartext traffic
when user-memory writes are disabled, blocked, or fail. Other requests continue
through the generic scanner. Rust does not disable injection for a whole process
or connection.
Generic HTTP/1 capture reuses the validated Rust wire context even when large TLS
headers exceed its capture buffer. It consumes ownership once it observes the
request, while task allocation and deallocation clear HTTP/1 state so recycled
task addresses cannot revive it.

For HTTP/2 requests whose headers Rust has checked, `tpinjector` uses that
ownership information to avoid scanning HPACK a second time. Its tail-call
budget covers up to 14 such HEADERS frames in one send. Requests without Rust
ownership retain the generic four-frame limit. Rust and the tpinjector use
the same HPACK traceparent serializer. Existing TLS connection tracking keeps
the tpinjector away from encrypted traffic.

For TLS, OBI inserts the header before encryption with `bpf_probe_write_user`.
The helper can return `EFAULT` when the append reaches a page the application
has yet to write. The buffer length stays unchanged on failure. If both HTTP/1
attempts fault, the TLS request leaves without an injected header. Short requests
on a keep-alive connection can repeatedly hit the same page.

## Compatibility

This adds instrumentation coverage under the minor-release rules in
[VERSIONING.md](../../VERSIONING.md). Existing configuration and telemetry
identifiers are preserved; no telemetry rename or schema transformation is
introduced. Rust runtime support retains the experimental classification in
[SUPPORT_MATRIX.md](../../SUPPORT_MATRIX.md).
