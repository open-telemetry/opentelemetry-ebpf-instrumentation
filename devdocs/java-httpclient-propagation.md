# Java HttpClient HTTPS propagation

OBI can inject a W3C `traceparent` into synchronous Java 11+ `java.net.http.HttpClient.send()`
requests sent over HTTPS with HTTP/1.1. Enable header propagation through the existing
`capture.engine.propagation.context_propagation: headers` setting in Config v2.
TCP-option propagation is independent and is not required.

The injected OBI Java agent must be enabled, and the kernel must support
`bpf_probe_write_user` under OBI's existing capability and lockdown checks.
On kernels that require it, OBI needs `CAP_SYS_ADMIN`. If those checks fail,
OBI leaves the request unchanged. No additional configuration is introduced.

## Injection and span identity

The agent tracks requests created during a synchronous `send()`, including
internal copies used for redirects and retries. Public `sendAsync()` calls
temporarily suspend that tracking, including calls made reentrantly during a
synchronous send. Tracking is removed when `send()` returns or throws.

The HTTP/1.1 header hook runs before TLS encryption. It obtains the connected
socket's addresses and asks eBPF to reserve an outbound client span identity.
At entry to `send()`, a separate control packet captures the current Java
server context before work moves to pooled workers. The captured parent is
retained only within that `send()`, so concurrent calls, retries on another
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
requests. Reservations are keyed by PID and the full connection tuple. The bounded hash
map does not evict active reservations; when full, new requests are sent without
injection. Reservations are consumed on matching observation, released when `send()`
exits, and removed when the socket closes. A mismatching plaintext notification
leaves the reservation for its owner to clean up.

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

The [reservation map and retirement helper](../bpf/generictracer/maps/java_http1_requests.h)
protect each entry through three rules:

1. **Insert only into an empty key.** `BPF_NOEXIST` prevents a new reservation
   from replacing an entry that is still present, including one awaiting deletion.
2. **Claim the entry before deleting it.** Compare-and-swap checks that the
   entry is still live and changes it to retired as one indivisible operation.
   Only the caller that makes this transition may delete the key. A delayed
   cleanup holding A's retired entry cannot win ownership again and delete B.
3. **Keep the reserved context immutable.** The
   [plaintext parser](../bpf/generictracer/protocol_http.h) copies the context
   before attempting retirement and adopts it only if that attempt succeeds.
   If acknowledgment to Java fails, rollback uses the same ownership check.

The map also uses `BPF_F_NO_PREALLOC` so a deleted entry's memory is not
immediately reused for a new reservation. The kernel uses read-copy-update
(RCU) to defer freeing that memory until existing readers have finished
([kernel reclamation path](https://github.com/torvalds/linux/blob/v5.8/kernel/bpf/hashtab.c#L745-L755)).
This matters because a delayed cleanup can still hold a pointer to the old entry;
its retirement state must continue to describe that entry, not a replacement.

#### Cost and alternatives

Each attempt to claim an entry performs one atomic operation. The kernel also
allocates memory for each reservation and reclaims it after RCU readers finish.
Map capacity bounds active entries, while deleted entries can temporarily remain
allocated pending reclamation. Allocation failure skips injection.

A Kprobe program-load probe checks support for 64-bit `CMPXCHG`, the instruction
used for this compare-and-swap. Without it, this feature stays inactive and emits
a diagnostic.
The constant gate keeps unsupported instructions out of reachable kernel code;
existing Java TLS observation and other propagation paths remain available.

The chosen design keeps ownership in one connection-keyed map. The following
table compares it with alternatives for identifying and cleaning up reservations,
and explains why those alternatives were not selected for this implementation.

| Approach | Lifecycle and cost | Decision |
| --- | --- | --- |
| Single reservation map with atomic retirement | Constant-time lookup and one retirement winner, without a second index or an application-thread wait; requires atomic instruction support and deferred reclamation | Implemented |
| Unique request/generation keys | Cleanup can name one generation, but the parser must recover that key. Current header scanners do not cover the full 16 KiB injection limit; adding a connection index also needs an ownership protocol | Requires additional identity lookup and index ownership |
| Context carried with plaintext SEND | Could remove reservations and release packets, but context must stay with captured bytes through TLS buffering and ciphertext-to-plaintext correlation. Context stored only on the caller thread does not follow pooled workers or delayed writes | Requires buffer-owned context and validation of partial writes and retries |
| Bounded expiry | Can recover abandoned capacity, but cannot distinguish a slow request from an abandoned reservation. Expiry still has to claim retirement before deletion | A separate capacity-recovery policy; does not replace ownership protection |

#### Cleanup limits and regression coverage

Normal failures release reservations when `send()` exits or the socket closes.
If both cleanup paths are missed, an abandoned entry can occupy capacity until
the tracer is unloaded. The reservation map does not use LRU eviction or
wall-clock expiry to remove potentially live entries.

These rules apply to the Java reservation map. Shared HTTP tracking retains its
existing LRU eviction behavior, so losing a request there can still prevent an
exported client span.

The native lifecycle regression reproduces the A/B race described above: it
consumes A and installs B between A's lookup and cleanup. Kernel tests exercise
the actual ioctl handler, parser mismatch, adopted trace/span/parent identity,
acknowledgment rollback, capacity recovery, and the disabled instruction gate.
The fixture's `/propagation-state` endpoint checks Java tracking only; it does
not measure eBPF map occupancy.

## Ownership and compatibility

Any application-supplied `traceparent` prevents injection. This includes mixed-case
names, invalid or empty values, and multiple values. OBI neither repairs nor adds
to an application-owned header. Other headers, including `tracestate`, retain
their application-provided values; OBI does not synthesize `tracestate`.

OBI checks the required JDK class, field, and method shapes before installing
the propagation hooks. The secure-connection and socket accessors are resolved
once inside the JDK module and cached. An incompatible layout disables this
feature with one diagnostic. Ordinary socket-close failures leave the original
headers intact and do not disable propagation for later requests.

These additional control operations preserve the existing agent contract version.
The agent publishes `otel.obi.java.agent.httpclient.propagation` to distinguish
this feature from an older or disabled agent. OBI warns when an already attached
agent cannot provide it. Restart the JVM to load the newer agent; a running
Java agent cannot be replaced. Agent options are established at attachment, so enabling propagation
for a JVM originally attached with header propagation disabled also requires a
JVM restart. Disabling header propagation in OBI always prevents injection.

## Scope and validation

Only actual HTTPS HTTP/1.1 requests from synchronous `send()` without
`expectContinue(true)` are eligible.
`sendAsync()`, HTTP/2, plaintext HTTP, other clients, and messaging use their
existing instrumentation paths without this injection. An HTTP/2 preference
that negotiates HTTP/1.1 is still an HTTP/1.1 request.

`expectContinue(true)` requests remain excluded. An earlier Java 21/TLS 1.3
experiment observed cleanup overtaking SEND on a final `417` response; enabling
injection for these requests requires separate validation of their interim and
final response handling.

The complete serialized header block after injection must fit within the
existing Java plaintext capture limit of 16 KiB. Larger headers are sent
unchanged, avoiding propagation with a client span identity that OBI cannot
correlate. Reflection failures and unavailable reservation state likewise
leave the request unchanged. Trace continuity is not guaranteed when the
underlying Java TLS observation itself is unavailable. Parent capture uses the
current Java server context; this feature does not add context inheritance for
new threads or tasks. It never infers a virtual thread's parent from stale
carrier-thread state.
With header propagation disabled, the existing Java TLS path can export a
virtual-thread HttpClient client span in a separate trace.

The integration fixture records the headers received by a TLS-terminating proxy
and checks the exported downstream trace. It covers application-owned headers,
disabled propagation, concurrent and pooled distinct parents, request reuse,
retries, redirects, authentication, request bodies, async calls, HTTP/2 and
HTTP/1.1 fallback, virtual threads on Java 21+, oversized headers, and cleanup
after timeouts, interruption, TLS rejection, and connection failure. Expect-Continue
cases check accepted bodies, final rejection responses, and application-owned headers.

Run the focused integration suite with:

```sh
go test -v -count=1 -run '^TestJavaHTTPClientTraceparent$' -timeout 15m ./internal/test/integration/
```

To select another JDK, set `JAVA_HTTPCLIENT_RUNTIME_IMAGE` to a digest-pinned
Java 11+ runtime image before building the fixture. Unit compatibility tests
also run in the Java agent CI JDK matrix. The JMH
`JdkHttpClientPropagationBenchmark` compares bounded byte-buffer preparation
against the prototype's string decoding and splitting; it does not measure
total application or eBPF overhead.
