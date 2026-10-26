# Java HttpClient HTTPS propagation

OBI can inject a W3C `traceparent` into Java 11+ `java.net.http.HttpClient.send()`
and both `sendAsync()` overloads over HTTPS with HTTP/1.1. Enable header propagation through the existing
`capture.engine.propagation.context_propagation: headers` setting in Config v2.
TCP-option propagation is independent and is not required.

The injected OBI Java agent must be enabled, and the kernel must support
`bpf_probe_write_user` under OBI's existing capability and lockdown checks.
The reservation path also requires the existing 64-bit `CMPXCHG` capability probe to pass.
On kernels that require it, OBI needs `CAP_SYS_ADMIN`. If those checks fail,
OBI leaves the request unchanged. No additional configuration is introduced.

## Injection and span identity

The agent tracks each API call through the identity of its internal request
copies, including redirects and retries. Concurrent calls using the same
immutable application request have separate internal owners. Synchronous
tracking ends when `send()` returns or throws.

For `sendAsync()`, the caller's previous scope is restored before the original
future returns. Cleanup observes the internal `MultiExchange.responseAsync(Executor)`
future rather than the application's cancellable dependent stage. Cancelling
or completing the public future therefore cannot release ownership still
needed by transport. Cleanup never installs request context on completion or
executor threads, and repeated cleanup cannot release another request's state.

The HTTP/1.1 header hook runs before TLS encryption. It obtains the connected
socket's addresses and asks eBPF to reserve an outbound client span identity.
At API entry, a separate control packet captures the current Java
server context before work moves to pooled workers. The captured parent is
retained within that request's lifetime, so concurrent calls, retries on another
worker, and new connections keep their own parent. Each attempt receives a fresh
client span ID using OBI's existing trace flags policy. An acknowledged empty
context starts a new trace; an unacknowledged capture skips injection.
If the existing server context is conflicting, invalid, or stale, capture is
left unacknowledged. OBI skips injection rather than turning a lost incoming
parent into a new root trace. This does not repair gaps in the underlying Java
server-context tracking, so sustained load can still produce uninjected calls.
The agent adds the resulting header to new serialized buffers, preserving
the application's immutable request and its headers.

An observed response with an unparsed status line also marks the server context
as having responded. Otherwise its next request on another connection would be
mistaken for a conflicting request on the same worker.

Before the socket write can send ciphertext to the peer, the Java TLS path
atomically claims its captured plaintext and reports it once. This ordering
prevents a fast response from completing `send()` and releasing the reservation
before the request notification. A write retry cannot reuse that plaintext
mapping to create another client span. Reporting an attempted write does not
prove the peer received it; application write failures still pass through unchanged.

When this observation path reports the plaintext request,
eBPF compares the injected value with the reservation and uses the reserved
identity for the emitted client span. The parser copies that identity directly
into the request record so concurrent changes to shared connection trace state
cannot replace it during the next parsing stage. The outgoing `traceparent` preserves the
incoming trace ID and sets its `parent-id` field to the outbound client span's ID.
This differs from the client span's own parent span ID, which points to the Java
server span when a current server context was captured. The incoming header's
`parent-id` identifies the upstream caller's span. A downstream service that
extracts the outgoing header creates a child of the outbound client span.

Java request tracking and retained native packets are each capped at 10,000
entries per JVM; capacity exhaustion skips injection without evicting active
requests. Reservations are keyed by PID and the full connection tuple. Preallocated slots and a bounded connection index do not evict active
reservations; unavailable capacity skips injection. Reservations are consumed on matching observation, released when the synchronous call
or internal async exchange ends, and removed when the socket closes. A mismatching plaintext notification
leaves the reservation for its owner to clean up.

An unfinished internal exchange retains bounded Java tracking even if its
public future is cancelled or abandoned. Failed completion-listener registration
disables propagation and retains unfinished ownership. There is no eviction of
live requests or expiry policy; a never-completing exchange can retain capacity
until JVM exit. Java tracking and native map occupancy are separate measurements.

### Reservation ownership

The reservation map holds the client span identity between header injection and
plaintext observation. The parser, cleanup when `send()` exits, and socket-close
handling can all try to remove the same entry. Ownership determines which of
these paths may delete it.

The danger comes from reusing a connection. Suppose cleanup for request A finds
A's reservation and pauses. The parser then consumes A, and request B reserves
the same connection. If A's cleanup resumes and deletes by connection key alone,
it deletes B's reservation. Comparing the traceparent before deletion does not
prevent this race: another operation can run between the comparison and deletion.
The Java monitor (a `synchronized` lock) protects one `send()` scope; separate
calls and eBPF programs on other CPUs can still run independently.

#### Ownership protocol

The [slot storage and ownership helpers](../bpf/generictracer/maps/java_http1_requests.h)
separate request identity from the connection used to find it. Cleanup carries
the original request ID in its native packet. The parser and socket-close path
read that ID from the connection index.

The context lives in preallocated array slots with stable addresses. A separate
preallocated hash map indexes the connection to its request ID; it never holds a
pointer to recyclable hash storage. Request IDs come from a monotonic counter and
also identify their array slot. The counter stops at its limit instead of wrapping.

Each slot has a state: free, readable under its request ID, or owned by that ID.
Reservation claims a free slot, fills its context, inserts the connection index
with `BPF_NOEXIST`, and then publishes the slot as readable. Cleanup atomically
claims that exact request ID before deleting the index and freeing the slot.
The parser copies and matches the context before making the same claim. If the
slot was reused during those reads, the claim fails and the copy is not adopted.
A delayed cleanup holding A's slot cannot claim B's new request ID, even when
both requests use the same physical slot and connection.

This avoids runtime allocation in tracing programs, which
[older verifiers reject on PREEMPT_RT kernels](https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/verifier.c#L8486-L8515).
It does not depend on hash-map reclamation timing.

#### Cost and alternatives

Storage is preallocated for 10,000 contexts and their connection index. Reservation
tries at most 16 candidate slots and bounds contention on the ID counter. If it
cannot claim a slot or insert the index, it skips injection; this can happen
before every slot is occupied. Publication, lookup validation, and retirement
use atomic compare-and-swap operations. There is no application-thread wait or
per-request kernel memory allocation.

A Kprobe program-load probe checks support for 64-bit `CMPXCHG`, the instruction
used for ownership. Java attachment and the eBPF loader share that check. On
unsupported kernels, the loader also replaces unreachable `CMPXCHG` instructions:
older verifiers reject unknown instruction encodings before eliminating branches
behind a false feature constant. Existing Java TLS observation remains available.

The following table compares ownership approaches and explains the choice for
this implementation.

| Approach | Lifecycle and cost | Decision |
| --- | --- | --- |
| Preallocated slots with unique request IDs and a connection index | Bounded allocation and atomic generation claims; stable slot addresses prevent stale-pointer deletion after reuse | Implemented |
| Connection-keyed non-preallocated hash with retirement | Depends on allocator reclamation; older tracing verifiers warn, and older PREEMPT_RT kernels reject it | Rejected |
| Request IDs stored only in preallocated hash values | The hash node can be reused while a reader holds its address; its state is overwritten during initialization of another entry | Does not provide stable ownership storage |
| Context carried with plaintext SEND | Could remove reservations and release packets, but context must follow captured bytes through TLS buffering and ciphertext-to-plaintext correlation | Requires buffer-owned context and validation of partial writes and retries |
| Bounded expiry | Can recover abandoned capacity, but cannot distinguish slow requests from abandoned ones | A separate capacity-recovery policy; does not replace ownership protection |

#### Cleanup limits and regression coverage

Normal failures release reservations when `send()` exits, the internal async
exchange completes, or the socket closes.
If both cleanup paths are missed, an abandoned entry can occupy capacity until
the tracer is unloaded. The reservation map does not use LRU eviction or
wall-clock expiry to remove potentially live entries.

These rules apply to the Java reservation map. Shared HTTP tracking retains its
existing LRU eviction behavior, so losing a request there can still prevent an
exported client span. Completed records are marked submitted in place.
Replacing their LRU entry would release the old slot for reuse while the HTTP
parser still holds its pointer, allowing export or cleanup to read another
request's identity. This does not change the map's capacity or eviction policy.

The native event-submission regression simulates that slot reuse and checks
that export retains the original request identity without duplicate submission.
The native lifecycle regression reproduces the A/B race described above: it
consumes A and reuses the exact same slot for B before A's delayed cleanup. Kernel tests exercise
the actual ioctl handler, parser mismatch, adopted trace/span/parent identity,
acknowledgment rollback, capacity recovery, and the disabled instruction gate.
A TLS kernel test also checks that `all` propagation publishes the reserved
client identity through TCP options, with the HTTP header beyond the downstream
1 KiB scanner so header extraction cannot hide a missing option.
The fixture's `/propagation-state` endpoint checks Java tracking only; it does
not measure eBPF map occupancy.

## Ownership and compatibility

Any application-supplied `traceparent` prevents injection. This includes mixed-case
names, invalid or empty values, and multiple values. OBI neither repairs nor adds
to an application-owned header. Other headers, including `tracestate`, retain
their application-provided values; OBI does not synthesize `tracestate`.

Sampling is unchanged: generated headers use OBI's existing sampled `01`
reservation policy, including for incoming `00`. Supplied flags are preserved;
a parent-based downstream sampler does not export requests with supplied `00`.

OBI checks the required JDK class, field, and method shapes before installing
the propagation hooks. The secure-connection and socket accessors are resolved
once inside the JDK module and cached. An incompatible layout leaves its
capability property false, with a diagnostic when agent debugging is enabled.
An incompatible async hook disables only async
injection when the common synchronous layout is still supported. Ordinary socket-close failures leave the original
headers intact and do not disable propagation for later requests.

These additional control operations preserve the existing agent contract version.
The agent publishes `otel.obi.java.agent.httpclient.propagation` to distinguish
the synchronous path, and `otel.obi.java.agent.httpclient.async.propagation`
for the async path. OBI warns when an already attached
agent cannot provide it. Restart the JVM to load the newer agent; a running
Java agent cannot be replaced. Agent options are established at attachment, so enabling propagation
for a JVM originally attached with header propagation disabled also requires a
JVM restart. Disabling header propagation in OBI always prevents injection.

These properties describe an available instrumentation path, not a successful
injection or evidence that the application uses that client. Check them with
`jcmd <pid> VM.system_properties` as the JVM owner, filtering for
`otel.obi.java.agent.*`. Combine them with the configured propagation mode and
OBI's kernel-capability diagnostics. Existing injector logs distinguish disabled
header configuration, unavailable kernel support, and missing async capability
in a loaded agent. They do not count supplied headers or skipped requests as
successful injection. This covers the JDK HTTP/1.1 path of #3842; broader
runtime/client discovery remains separate.

## Scope and validation

Only actual HTTPS HTTP/1.1 requests from `send()` or `sendAsync()` without
`expectContinue(true)` are eligible.
HTTP/2, plaintext HTTP, other clients, and messaging use their
existing instrumentation paths without this injection. An HTTP/2 preference
that negotiates HTTP/1.1 is still an HTTP/1.1 request.

`expectContinue(true)` requests remain excluded. An earlier Java 21/TLS 1.3
experiment observed cleanup overtaking SEND on a final `417` response; enabling
injection for these requests requires separate validation of their interim and
final response handling.
The immediate `417` regression is skipped on JDK 11: both the merged baseline
and an uninstrumented control hang with this response, matching
[JDK-8286171](https://github.com/openjdk/jdk/pull/9093).
Successful Expect-Continue requests still run in every runtime regression.

The complete serialized header block after injection must fit within the
existing Java plaintext capture limit of 16 KiB. Larger headers are sent
unchanged, avoiding propagation with a client span identity that OBI cannot
correlate. Reflection failures and unavailable reservation state likewise
leave the request unchanged. Trace continuity is not guaranteed when the
underlying Java TLS observation itself is unavailable. Parent capture uses the
current Java server context; this feature does not add context inheritance for
new threads or tasks. It never infers a virtual thread's parent from stale
carrier-thread state.
With header propagation disabled, the existing Java TLS path can export
virtual-thread clients and async work that outlives its source response in
separate traces. The merged synchronous baseline reproduces that behavior.

The integration fixture records the headers received by a TLS-terminating proxy
and checks the exported downstream trace. It covers application-owned headers,
disabled propagation, concurrent and pooled distinct parents, request reuse,
retries, redirects, authentication, request bodies, async calls, HTTP/2 and
HTTP/1.1 fallback, virtual threads on Java 21+, oversized headers, and cleanup
after timeouts, cancellation, body-publisher failure, interruption, TLS rejection,
and connection failure. The async source uses only OBI; its downstream uses the
standard OpenTelemetry Java agent. Expect-Continue
cases check accepted bodies, final rejection responses, and application-owned headers.

Run the focused integration suite with:

```sh
go test -v -count=1 -run '^TestJavaHTTPClient(Async)?Traceparent$' -timeout 20m ./internal/test/integration/
```

To select another JDK, set `JAVA_HTTPCLIENT_RUNTIME_IMAGE` to a digest-pinned
Java 11+ runtime image before building the fixture. Unit compatibility tests
also run in the Java agent CI JDK matrix (8, 11, 17, 21); the transport CI matrix
selects JDK 11, 17, and 21 on amd64 and arm64. Java 8 has no JDK HttpClient API.
Bundling both JNI libraries or compiling Java 8 bytecode does not establish
runtime coverage. The JMH
`JdkHttpClientPropagationBenchmark` compares bounded byte-buffer preparation
against the prototype's string decoding and splitting; it does not measure
total application or eBPF overhead.
