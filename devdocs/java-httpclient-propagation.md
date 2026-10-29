# Java HttpClient HTTPS propagation

OBI can add a W3C `traceparent` header to HTTPS HTTP/1.1 requests made with
Java 11+ `java.net.http.HttpClient.send()`, either `sendAsync()` overload, or
synchronous Apache HttpClient 4 `CloseableHttpClient.execute()`.
Enable it with `capture.engine.propagation.context_propagation: headers` in
Config v2. Header propagation does not require TCP option propagation.

The injected OBI Java agent must be enabled, and the kernel must support
`bpf_probe_write_user` under OBI's existing capability and lockdown checks.
On kernels that require it, OBI needs `CAP_SYS_ADMIN`. If those checks fail,
OBI leaves the request unchanged. No additional configuration is introduced.

## Injection and span identity

The agent tracks internal request copies through redirects and retries.
For `send()`, tracking ends when the call returns or throws.

For `sendAsync()`, tracking lasts until the internal exchange completes.
Cancelling the public future does not release transport state. The agent returns
the original future and restores the caller's previous scope before returning.
Completion callbacks do not install context on executor threads. Concurrent
calls with the same immutable request are tracked separately.

Tracking has a fixed limit. An exchange that never completes can occupy capacity
until the JVM exits. If registering the completion callback fails, the agent
disables propagation and keeps the unfinished exchange's state.

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
entries per JVM. When capacity runs out, OBI skips injection and leaves active
requests alone. Reservations use the PID and full connection tuple as their key.
The preallocated slots and connection index also have fixed limits.

A reservation is consumed when OBI observes the matching request. It is released
when the synchronous call or internal async exchange ends, or when the socket
closes. A plaintext notification that does not match the reservation leaves it
for its owner to clean up.

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

## Apache HttpClient 4 synchronous execution

Apache `CloseableHttpClient` overloads, including response handlers, reach a
concrete `doExecute(HttpHost, HttpRequest, HttpContext)`. OBI captures the parent
there, without instrumenting forwarding overloads or compiler bridges.
Reentrant executions have separate scopes and restore the previous scope.
Calls from a response handler start their own execution after the outer transport
scope has ended.

`HttpRequestExecutor.doSendRequest()` associates each attempt with its managed
connection's JSSE `SSLSocket`. Only that socket's first nonempty plaintext write
can be modified. A split header consumes this opportunity; subsequent body writes
cannot trigger injection, even when their contents resemble HTTP headers.
Both byte-array write overloads preserve the selected slice and body. Delegating
streams share an observation guard. Reporting happens before the application
write, once per outer stream; a reporting failure leaves the original arguments.
An application write exception is preserved.

Each attempt copies the captured execution parent and uses the existing native
reservation and request-ID cleanup protocol. Its retained packet is released when
`doSendRequest()` returns or throws, after synchronous plaintext observation.
Retries, redirects, and authentication exchanges therefore receive fresh client
identities without accumulating packets for the whole execution. Execution exit
also releases an unfinished attempt. Socket-close cleanup retains the native
request-ID protections described above. The Java ioctl contract is unchanged.
After consuming a reservation, native HTTP tracking retains its request ID until
the matching release, so delayed body writes resembling HTTP cannot replace the
reserved client identity. Cleanup compares that ID before clearing it, preserving
a newer request on the same connection.

The entire first write after injection, including any coalesced body bytes, must
fit within 16 KiB, and it must contain complete HTTP/1.1 headers. Split, oversized,
unsupported, or uncorrelatable writes pass through unchanged. Apache request
objects and application-supplied headers are never modified. Any `traceparent`,
including an empty, invalid, duplicate, or mixed-case field, prevents injection.
A copied incoming ancestor does not become a new client span ID. `tracestate`
passes through; OBI does not create it. Under the existing native policy,
OBI-generated headers use sampled flags (`01`) even for unsampled incoming
context; supplied flags are preserved.

Requests containing `Expect` are excluded from injection. The transport regression
checks an accepted 100-Continue body and an immediate final 417 response, without
claiming injected interim-response handling. Plaintext, HTTP/2, HttpClient 5,
asynchronous clients, and custom transports/executors that bypass these hooks are
excluded. The minimum supported Apache HttpClient version is **4.3**, within the
4.x series. That release introduced
[`CloseableHttpClient`](https://hc.apache.org/httpcomponents-client-4.5.x/current/httpclient/apidocs/org/apache/http/impl/client/CloseableHttpClient.html)
and
[`ManagedHttpClientConnection`](https://hc.apache.org/httpcomponents-client-4.5.x/current/httpclient/apidocs/org/apache/http/conn/ManagedHttpClientConnection.html),
whose `getSocket()` method provides access to the TLS socket. Compatibility checks
inspect the required method signatures rather than comparing version numbers.

The existing header-propagation configuration, kernel write-user/atomic feature
checks, and permissions apply. Apache propagation supports Java 8 and later,
separately from the JDK client's Java 11 minimum. The
[fixture README](../internal/test/integration/components/java_apache_httpclient/validation/README.md)
describes how to run the regression suite and select Apache and JDK versions.
Agent upgrades and enabling propagation after a disabled attachment require a JVM
restart. Disabling propagation in OBI prevents injection without a restart.

### Apache capability diagnostics

Inspect `otel.obi.java.agent.apache4.propagation` with the JVM's existing
`jcmd <pid> VM.system_properties` command:

| Value | Meaning |
| --- | --- |
| `disabled` | The agent was attached without the header-propagation option; check OBI configuration and kernel capability diagnostics before restarting |
| `not-loaded` | No Apache layout has been inspected; client presence and effective support remain unknown |
| `unavailable-foundation` | A native/control or shared lifecycle failure disabled propagation; restart with a working agent/native path |
| `unsupported-layout` | A required Apache execution, attempt, or managed-socket shape is missing |
| `available` | An inspected Apache layout has an injection path; this does not prove an injected or delivered header |
| Missing property | The loaded agent predates this path; restart with the current agent |

The property summarizes inspected layouts in one JVM; it does not certify every
application class loader. OBI's existing attachment/rediscovery diagnostics report
configured propagation separately from capability, including on Java 8. Kernel
write-user or reservation-atomic failures leave the option disabled and report
the reason. These diagnostics add no new telemetry or per-request application logs.

The bootstrap helper's fixed counters distinguish first writes, prepared headers,
unsupported header layouts/sizes, application-owned fields, Expect exclusions,
and unavailable parent/reservation state. A final gauge counts active executions.
Preparation is not evidence of delivery or export. The validation fixture exposes
snapshots for testing; the unchanged Java ioctl contract does not identify which kernel
capacity/contention/parent check declined an individual reservation.

Run the Apache transport suite with:

```sh
go test -v -count=1 -run '^TestJavaApacheHTTPClientTraceparent$' -timeout 20m ./internal/test/integration/
```

Use `JAVA_APACHE_RUNTIME_IMAGE` for another digest-pinned runtime. The canonical
CI transport matrix includes JDK 8, 11, 17, and 21 on native amd64 and arm64 runners.
The [validation workflow](../internal/test/integration/components/java_apache_httpclient/validation/README.md)
records commands, controls, and the distinction between local evidence and CI.

## Ownership and compatibility

Any application-supplied `traceparent` prevents injection. This includes mixed-case
names, invalid or empty values, and multiple values. OBI neither repairs nor adds
to an application-owned header. Other headers, including `tracestate`, retain
their application-provided values; OBI does not synthesize `tracestate`.

OBI checks the required JDK class, field, and method shapes before installing
the propagation hooks. The secure-connection and socket accessors are resolved
once inside the JDK module and cached. An incompatible layout disables this
feature with one diagnostic. An incompatible async hook disables async
propagation only.
A socket closing during injection leaves the original headers intact and does
not disable propagation for later requests.

The control operations keep the existing agent contract version.
`otel.obi.java.agent.httpclient.propagation` reports whether synchronous
propagation is available. `otel.obi.java.agent.httpclient.async.propagation`
reports the same for async calls. Neither property confirms that a header was
injected.

OBI warns when an attached agent lacks the required capability. Restart the JVM
to load the newer agent. The agent cannot be replaced while the JVM is running.
Enabling header propagation also requires a restart if the agent was attached
with propagation disabled. Disabling header propagation in OBI prevents injection.

## Scope and validation

Only actual HTTPS HTTP/1.1 requests from `send()` or `sendAsync()` without
`expectContinue(true)` are eligible.
HTTP/2, plaintext HTTP, other clients outside the Apache slice above, and messaging use their
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
go test -v -count=1 -run '^TestJavaHTTPClient(Async)?Traceparent$' -timeout 20m ./internal/test/integration/
```

To select another JDK, set `JAVA_HTTPCLIENT_RUNTIME_IMAGE` to a digest-pinned
Java 11+ runtime image before building the fixture. Unit compatibility tests
also run in the Java agent CI JDK matrix. The JMH
`JdkHttpClientPropagationBenchmark` compares bounded byte-buffer preparation
against the prototype's string decoding and splitting; it does not measure
total application or eBPF overhead.
