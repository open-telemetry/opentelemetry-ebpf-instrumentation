# Deno trace-context propagation — HTTP-first roadmap

Status: **proposal, pending approval**. No implementation code written yet.

## Product constraint and phased goal

Both phases must work with **no change to the instrumented service**: no `--inspect`,
no `--inspect-brk`, no application code change, no extra Deno flag, and no native
OTel exporter configuration. Enabling OBI's existing header-propagation feature is
an OBI-side prerequisite, not a service-side change.

The work is split deliberately:

1. **Phase 1 — plaintext HTTP:** end-to-end W3C trace-context propagation for
   `Deno.serve` + native `fetch`, and the `node:http` compatibility path. This is
   the first implementation target described in detail below.
2. **Phase 2 — HTTPS:** reach the same result before rustls encrypts the request,
   without requiring Deno's native OTel flags or exporter. This remains design work;
   the current HTTP mechanism cannot rewrite encrypted bytes.

Phase 1 must not be presented as HTTPS parity. It should establish the runtime
anchor, correlation model, and test infrastructure that Phase 2 can reuse.

Phase 1 itself has two delivery steps:

- **Phase 1A — `node:http`:** ship the compatibility path and the shared injector,
  token, eBPF, and test infrastructure. This path has a real request boundary through
  `http.Server.prototype.emit` + `als.run(...)`.
- **Phase 1B — native `Deno.serve`:** enable native propagation only after a safe
  retroactive request-entry boundary is available. The accessor experiment remains
  useful for research and coverage measurements, but it must not be enabled by
  default while it can produce a wrong parent.

## Why Deno cannot reuse the Node.js mechanism

For Node.js, `pkg/internal/nodejs/fdextractor.js` correlates an outgoing socket to
the incoming one by **file descriptor pair**, signalling the pair to eBPF through a
`uv_fs_access` uprobe on a magic path. Neither half works on Deno (all verified
empirically against `denoland/deno:2.9.4`):

| Node.js mechanism | Deno |
| --- | --- |
| `socket._handle.fd` | not exposed to JS (`undefined`) |
| `uv_fs_access` uprobe | no libuv; symbol unresolvable |
| `async_hooks.createHook` before-hook | `createHook` exists and fires, but native `fetch` never creates a node:net resource |
| OpenSSL `SSL_read`/`SSL_write` uprobes | rustls + aws-lc-rs, statically linked and stripped — no symbols |

The agent is injected via SIGUSR1 + CDP `Runtime.evaluate`, which works on Deno with
no flags. But injection happens **after** the application has already called
`Deno.serve`, so every hook must be **retroactive**: patching globals or prototypes,
never replacing a function the application has already consumed.

## What the current state actually is

This design builds on two PRs that are still open at the time of writing;
implementation should start from, or be rebased after, both.

**PR #2858 ("NodeJS: simplify script injection")** moves the IIFE wrapper from the Go
side into `fdextractor.js` itself and injects `_extractorCode string` verbatim, with no
`fmt.Sprintf` pre-processing. That is exactly what a Deno payload needs, since it must
be wrapped in an `async` lambda rather than a plain one: the two agent files become
interchangeable strings and the injector needs no per-runtime wrapping logic.

**PR #2851 ("Deno instrumentable type")** adds `svc.InstrumentableDeno` and routes it
everywhere Deno needs to be distinguished: `proclang.go` maps the `deno` module to it,
`attacher.go` includes it in the generic-tracer case, the route harvester and its
`deno` disable switch handle it, and `NodeInjector.NewExecutable` accepts both JS
runtimes while threading a `runtimeType` argument down to `injectFile`. It also
settles the naming question:
`String()` returns **`deno-rust`**, matching Deno's own native OTel convention, and
`schemas/obi/groups/telemetry.yaml` declares that enum member.

What neither PR does is pick a different agent payload: `injectViaConn` still embeds
the single `fdextractor.js` for both runtimes, and on Deno its evaluation **fails**.
That agent uses top-level `require('net')`, and in a running Deno app (ESM,
`deno run`) `require` is undefined in the global scope where CDP
`Runtime.evaluate` executes; verified: `ReferenceError: require is not defined`. The
injector checks `exceptionDetails` (`pkg/internal/nodejs/injector.go:268`), so this
surfaces as an error log rather than silently. **Deno therefore runs with no working
agent**, and everything below is measured against that baseline.

Measured behaviour of that baseline (on the discarded branch, where the agent was
inert for native code paths, so the numbers apply unchanged):

- Sequential outbound `fetch` to a separate service: **correlated** — OBI's generic
  egress attribution (thread-current server context) is enough.
- 40 concurrent requests, one outbound `fetch` each: **~1/40 correlated**. Each
  outbound call becomes the root of its own trace.

The root cause is not the agent, it is the map key. `server_traces` is keyed by
`trace_key_t{extra_id, p_key{tid, pid, ns}}`; Deno runs every request on one thread, so
`server_or_client_trace()` (`bpf/common/trace_lifecycle.h:135`) sees a conflicting
entry and marks it invalid. `server_traces_aux`, keyed by
`connection_info_part_t` — the incoming connection's client address and port — does
preserve the distinction between simultaneous requests on different connections.

More precisely, `server_traces_aux` is correct **per connection**, not universally
per request. Concurrent HTTP/1.1 pipelining, or asynchronous work that outlives a
request while the same connection is reused, can still alias. Phase 1 must either
exclude those cases explicitly or add a request discriminator; the 40-client test
does not exercise them.

So the missing piece is a per-request link from "the JS async context making this
outgoing call" to "the incoming connection", which only the runtime knows.

## Empirical findings that drive the design

Probes run against `denoland/deno:2.9.4`, agent installed **2.5 s after the server
started serving traffic** (faithful stand-in for SIGUSR1 injection), 40 concurrent
requests, upstream in a separate process, handler awaiting before its egress call.
The matrix compared the baseline with no working Deno agent against late-installed
prototype hooks, sequential against concurrent traffic, and handlers that read an
accessor, read only the body, or never touch their `Request`. The no-touch shape is a
control for stale async context, not an application requirement.

Results:

1. **A retroactive ingress hook exists.** Patching the accessors of
   `Request.prototype` (`url`, `method`, `headers`) fires for requests delivered by
   an already-running `Deno.serve`. First touch per instance + `ALS.enterWith()`
   yields the correct per-request context at egress time: **40/40 correct, 0 wrong**,
   including across an intervening `await`.
   This positive result is not sufficient on its own, and the follow-up probes are
   worse than first reported. A handler that never touches its `Request` inherits the
   last anchor in **both** shapes: sequentially after the previous request completed
   (over one keep-alive connection *and* over a fresh one), and concurrently while
   another anchored request is still in flight. The leak is not a keep-alive artifact.
   The observed behaviour is consistent with `enterWith()` writing into a dispatch
   context reused by subsequent handlers. So the failure is a **wrong correlation**,
   not a missing one.
   Three candidate boundaries were then implemented and measured, and all three fail:
   - clearing in `queueMicrotask` after the anchor: no effect on the leak;
   - marking the store spent in the `Response` constructor: fail-closed, but it
     cross-contaminates — an unrelated fast handler spent the *live* store of a slow
     anchored request, which then lost its own correlation;
   - clearing in the runtime's own per-request `InnerRequest.close()` (finding 9):
     no effect either; that context cannot reach the leaking frame.
   Reading the body does not trigger any of the three accessors above: a probe using
   only `await req.text()` produced zero anchors. Wrapping `Request.prototype.text`
   explicitly did establish the expected store after the `await`; body getters and
   consumption methods therefore need their own wrappers if this experiment is kept.
2. **The incoming connection tuple is reachable from the `Request` alone.** The
   internal slot `req[Symbol(request)]` exposes `remoteAddr` on its prototype, and it
   matches `info.remoteAddr` from the `Deno.serve` handler exactly (verified over 5
   distinct client ports). This removes the need to wrap `Deno.serve`.
3. **Re-entrancy matters.** `fetch()` internally constructs a `Request`, whose
   accessors fire our hook and would clobber the ambient context. A re-entrancy flag
   around the `fetch` wrapper fixes it (anchors dropped from 80 to 40 for 40 requests).
4. **The runtime does not read the public `Response.prototype.headers` getter** — it
   serialises responses from internal slots. There is no universal response-side
   stamping point. (Relevant only to the rejected alternative below.)
5. **The request cycle is entirely Rust, on one thread** (`strace`): `accept4` →
   `getpeername` → `recvfrom` → (JS handler) → `sendto`, all on the same tid; the only
   other thread does `mmap`/`madvise`/`futex` (V8 allocator). Two consequences: the
   single-thread collision in `server_traces` is confirmed directly, and there is **no
   JS-issued syscall anywhere in a request** to piggyback a signal on — a signal-based
   channel would have to add one per request, which the header-carried tuple avoids.
   `getpeername` right after `accept4` also shows the peer address is already
   materialised when the handler runs, so reading it in the anchor costs nothing.
6. **Egress shape** (`strace` of native `fetch`): one `sendto` per request carrying the
   **whole header block** (no `writev`/`sendmsg` fragmentation), and an agent-set
   `traceparent` is serialised **first, right after the request line** (offset ~17) —
   well inside the first 1 KB chunk that `find_existing_tp` scans, and never reordered
   or dropped by Deno. Connections are **pooled**: two sequential fetches shared one fd
   with two `sendto` calls, which the per-message `sk_msg` design handles correctly.
7. **eBPF already adopts an existing outgoing `traceparent`.**
   `obi_packet_extender_find_existing_tp` (`bpf/tpinjector/tpinjector.c:1212`) parses a
   `traceparent` present in the outgoing HTTP headers, uses it as the client span's
   identity, and `assign_parent_tp` already **overwrites the span-id in place** in the
   socket buffer. There is a fixed-length JS→eBPF channel here, half-built.
8. **Injection currently precedes tracer readiness.** `traceAttacher` calls
   `nodeInjector.NewExecutable` before `getTracer`, which is where the common
   `tpinjector` is loaded and the PID is admitted. A Deno agent that starts writing
   placeholders at injection time can therefore race ahead of the only component
   able to rewrite them. Deno injection must happen after successful tracer/PID
   setup, or be gated by an equivalent kernel-visible readiness handshake.
   Scope refinement: `bpf_sock_ops_active_est_cb` inserts **every** actively
   established socket in the cgroup into `sock_dir` with no PID filter, so sockmap
   membership itself is not the race. What can lag is the `sk_msg` program being
   attached at all (the common `tpinjector` is loaded in `getTracer`) and the server
   span existing in `server_traces_aux` for that PID. Both still argue for reordering.
9. **The runtime touches an internal request object per request, but only at the
   end.** `req[Symbol(request)]` is an instance of Deno's internal `InnerRequest`
   class, and its prototype is patchable retroactively. The runtime calls
   `close()` on it for **every** request, including requests whose handler never
   touched the public `Request` — a reliable retroactive *completion* boundary. It
   calls none of `url`/`method`/`remoteAddr` on its own, so there is **no
   runtime-driven entry hook**: an anchor still requires the application to touch its
   `Request`. Bootstrapping the patch also requires one such request, because a
   client-constructed `Request` has a plain `Object` inner, not an `InnerRequest`.
10. **`awaitPromise` works, and it is a safety requirement rather than an
    observability nicety.** Measured over a real CDP session against Deno's inspector:
    with `awaitPromise: true` the response arrives only after the injected promise
    settles, carrying `exceptionDetails` on rejection and `result.value` on
    resolution. Without it the response returns immediately with a promise handle —
    and when that promise later rejects, Deno reports `Uncaught (in promise)` and
    **terminates the instrumented application**. Verified both ways: the target
    process survives with `awaitPromise: true` and dies without it. OBI must not be
    able to kill a user's service because its agent failed to install, so the agent
    also catches everything internally and *resolves* with a status instead of
    rejecting.
11. **`async_hooks` ids cannot substitute for ALS.** `executionAsyncId()` returns `0`
    unconditionally and `createHook`'s `init`/`before` fired 5 times in an entire run
    with 4 requests. Deno exports the API but does not implement the id graph, so an
    agent cannot build its own per-request context tracking on top of it.

## Decision (a): who owns the IDs

**eBPF remains the sole source of truth for final OBI trace and span IDs. The JS
agent never chooses an ID that OBI adopts as final.**

The JS agent contributes *correlation data only*: which incoming connection the
current async context belongs to. It expresses that in a fixed-length synthetic
`traceparent`; its W3C-shaped fields are an authenticated transport envelope, not
OBI trace identity, and eBPF overwrites them in place before the bytes leave the
socket when `sk_msg` observes the request.

Rationale: any design where JS mints IDs requires OBI's kernel-generated server span
to adopt them, i.e. rewriting a span's identity after creation, plus a channel to tell
the kernel *which* server span to rewrite. That is strictly more machinery, touches
span lifecycle shared by every language, and gains nothing here — because finding
2 gives us the exact ingress link that made the JS-owned model necessary in the first
place. It also keeps sampling, TCP-option propagation and ingress adoption unchanged.

## Candidate (b): the retroactive ingress hook

The accessor hook supplies the required tuple, but **it is not yet a complete ingress
boundary**. It is not `globalThis.Request` or a server-side `fetch`:

- `globalThis.Request` (the constructor) is *not* used by `Deno.serve` — patching it
  intercepts nothing incoming.
- `Request.prototype` **accessors** are used, and patching a prototype is retroactive
  for instances that already exist and for all future ones. This is the anchor.
- The connection tuple comes from `req[Symbol(request)].remoteAddr` (finding 2).
- `Deno.serve` is **not** wrapped. `node:http` servers use
  `http.Server.prototype.emit('request')`, which is retroactive and gives
  `req.socket.remoteAddress`/`remotePort` through public API.

Caveat, stated plainly: `Symbol(request)` is a Deno internal. The agent feature-detects
it (symbol looked up by description) and, when absent, logs and degrades to today's
behaviour — it never breaks the application. A version-compatibility note and a loud
integration-test failure cover regressions across Deno releases.

The implementation must also ensure that an ALS store cannot survive into an
unrelated handler. On Deno 2.9.4, **none of the mechanisms tested so far provides that
boundary**. Findings 1, 9 and 10 show why the current candidates fail: no patchable
runtime entry hook has been identified, clearing from `InnerRequest.close()` or a
microtask does not reach the leaking context, and `async_hooks` ids are unusable.
This is strong evidence against the current accessor-only design, but not a proof
that no internal or future Deno hook can exist.

The residual risk is therefore precise, and it is not the whole native path:

- Handler uses an **instrumented surface** of its `Request`: the anchor re-runs before
  that handler's own egress, so its context is correct. This is measured for `url`,
  `method`, and `headers` at 40/40 under concurrency with an intervening `await`.
  Body consumption is covered only if its getters and methods are wrapped explicitly.
- Handler **never touches** its `Request` *and* makes an outgoing HTTP call: it
  inherits another request's context and can be attributed to the wrong parent. This
  is undetectable at egress, in JS and in the kernel alike.

`node:http` is unaffected: wrapping the `'request'` branch of
`http.Server.prototype.emit` in `als.run(...)` is properly scoped, so that path has a
real boundary.

The roadmap does **not** accept shipping known-wrong parents. Phase 1A can proceed
with `node:http` and all shared infrastructure, while Phase 1B remains disabled by
default until a safe native boundary is demonstrated. A same-synchronous-turn mode
may be useful as an experimental probe, but it is too narrow for the product path and
must remain opt-in. In parallel, the project should ask upstream Deno for a stable
per-request entry hook or complete async-context support; either would also help
Phase 2.

## Phase 1 architecture (subject to the ingress-boundary gate)

```
 incoming request ──► [eBPF] server span created, stored in
                              server_traces_aux[{client addr, client port, pid, FD_SERVER}]
                      │
                      ▼
 handler runs ──► [JS] first touch of Request.prototype accessor
                       ├── read req[Symbol(request)].remoteAddr
                       └── enter request-bounded async context ← unresolved gate
                      │
                      ▼
 fetch()/http.request ──► [JS] inject authenticated opaque placeholder
                      │
                      ▼
 sendmsg ──► [eBPF sk_msg] tag verified → token index → parent tp
                       ├── client span: trace_id = parent.trace_id,
                       │                parent_id = parent.span_id, span_id = fresh
                       └── overwrite the 55 placeholder bytes in place
                      │
                      ▼
 wire carries a real traceparent; downstream parents to the client span
```

### What runs where

| Concern | JS agent | eBPF |
| --- | --- | --- |
| Which incoming connection is the current async context | ✔ | — |
| Trace/span ID generation | — | ✔ |
| Parent lookup | — | ✔ (token index + `server_traces_aux`) |
| Wire bytes | placeholder only | final traceparent (in-place) |
| Server span | — | ✔ (unchanged) |
| Ingress traceparent adoption | — | ✔ (unchanged) |

### Authenticated opaque placeholder wire format

Exactly 55 bytes, W3C-valid, same length as the final value, so the overwrite never
shifts a byte and never touches framing:

```
traceparent: 00-<NONCE8><TAG8>-<MASKED_TOKEN8>-01
                └ trace_id, 16 B ┘ └─ span_id, 8 B ─┘
```

- `CONNECTION_TOKEN = PRF64(secret, domain_conn || family || addr || port)`. The
  per-process secret is shared only by the injected agent and eBPF. At server-span
  creation eBPF calculates the same token and stores
  `{pid, CONNECTION_TOKEN} -> connection_info_part_t` in an internal index.
- `NONCE8` is fresh random data for each outgoing call.
- `MASKED_TOKEN8 = CONNECTION_TOKEN XOR PRF64(secret, domain_mask || NONCE8)`.
  Masking makes the wire span-id different on every call and prevents a leaked
  placeholder from exposing or linking the incoming connection token.
- `TAG8 = PRF64(secret, domain_tag || NONCE8 || MASKED_TOKEN8)`. Domain separation
  prevents the three uses of the PRF from overlapping.

The agent retries with another nonce if the resulting W3C trace-id or span-id would
be all zero. `sk_msg` looks up the enabled per-PID secret, verifies `TAG8`, unmasks the
connection token, resolves it through the token index, and finally validates the
`server_traces_aux` parent. A third-party `traceparent` fails authentication and stays
on the existing code path untouched; accidental acceptance is approximately 2⁻⁶⁴
before the token-map lookup.

If an authenticated placeholder reaches `sk_msg` but its parent is missing, eBPF
replaces it with fresh IDs. If `sk_msg` never sees it — for example after an abrupt OBI
exit — the downstream receives a unique, valid, random-looking trace context with no
peer tuple or stable token. That is an uncorrelated degradation, not an information
leak or a merge of unrelated traces.

This design adds a per-PID secret/readiness map and a token-to-connection index, but
no syscall per request: JS and eBPF derive the same deterministic connection token
independently.

Two simplifications should be settled before PR 3 implements the above:

- **The index is only needed for IPv6.** An IPv4 peer is 6 bytes (address plus port)
  and fits in the 8 masked bytes, so the agent can encrypt the *tuple itself* and eBPF
  can decrypt it and build the `connection_info_part_t` key directly. That yields the
  same opacity and per-call unlinkability with no `{pid, token}` index map, no PRF work
  in the ingress hot path, and no second per-connection lifecycle to define — which
  also removes half of design gate 3. Only native IPv6 (PR 7) needs the token/index
  indirection, which is where the plan already isolates it.
- **Prefer a 32-bit ARX block cipher over SipHash-2-4.** SipHash needs 64-bit
  arithmetic, so JS gets either BigInt or a hand-rolled 32-bit emulation that must
  byte-match the C side. An 8-byte-block ARX cipher such as Speck64/128 provides both
  the mask and the tag using only `|0`/`>>>` in JS and unrolled 32-bit ops in C, with
  no 64-bit emulation on either side. SipHash stays as the alternative if the cost
  check favours it.

Scope the tag honestly: the secret lives inside the instrumented process, so it is not
a defence against the application itself, which can always observe or patch the agent.
It defends against accidental collisions and against third parties on the network.
That is why 2⁻⁶⁴ versus 2⁻⁴⁰ should not drive the choice; implementation cost and
cross-language determinism should.

The agent injects a placeholder **only** when all of these hold:

- the native ingress-boundary mechanism proves that the current async work belongs
  to an active request; the mere presence of an ALS store is not sufficient;
- the target URL scheme is `http:` — never `https:`, because OBI cannot rewrite
  rustls-encrypted bytes and the placeholder would leak;
- the request carries no `traceparent` already — an application- or SDK-set header is
  never replaced by the agent (the lesson from issue #2732), while the existing eBPF
  handling of forwarded headers remains unchanged;
- the peer address and port can be canonicalised identically in JS and eBPF. The
  token input can carry the full IPv4 or IPv6 address without changing wire length.

## Phase 1 changes required

### eBPF

1. Add an internal per-PID state map containing the PRF secret and an enabled bit.
   An authenticated placeholder is recognized only for an enabled Deno PID; ordinary
   application `traceparent` values stay on the existing path.
2. Add an internal `{pid, connection_token} -> connection_info_part_t` index. When a
   Deno server span is created and the PID has secret state, derive the token from the
   canonical incoming peer and populate the index. This is the bridge to the existing
   `server_traces_aux` entry; the wire value itself never contains the peer tuple.
3. In `bpf/tpinjector/tpinjector.c`, after parsing `traceparent`, verify the tag,
   unmask the token, resolve the connection index, then validate the corresponding
   `server_traces_aux` parent. Reject missing, invalid, zero-trace, completed, or
   transaction-expired entries; a raw map hit is not enough. On success, fill `tp_p`
   with the parent trace-id, parent-id, and a fresh span-id, then overwrite trace-id
   and span-id in place. The existing `assign_parent_tp`, `set_tp_info_pid`, and
   `written = 1` flow can be extended rather than duplicated.
4. If the tag is valid but the token or parent cannot be resolved, overwrite the
   placeholder with fresh eBPF IDs. If the tag is invalid, do not treat the header as
   OBI-owned and leave existing third-party-header behaviour unchanged.
5. Delete or invalidate both the auxiliary parent and its token-index entry when the
   server request completes. Today `delete_server_trace()` removes `server_traces`
   and `trace_map` state but leaves the copied auxiliary value valid until LRU
   eviction. Cleanup and validation must prevent connection reuse from adopting a
   stale trace within the transaction window.

Nothing needs to be added to the generic `find_parent_trace` chain, and no `statx`
kprobe is needed. The old branch's `bpf/generictracer/deno.c` +
`nodejs_deno_map.h` are not assumed to be the answer.

### Go

Everything about the instrumentable type itself lands in #2851. Phase 1 then needs:

1. `pkg/internal/nodejs/`: thread the `runtimeType` #2851 already passes to
   `injectFile` on down through `injectViaConn`, and pick one of two embedded strings
   (`fdextractor.js` for Node, `fdextractor_deno.js` for Deno). After #2858 that is the
   whole change — both payloads are self-contained, so no wrapping differs per runtime.
   Injection transport still sizes the WebSocket write buffer to the payload, which is
   what Deno's inspector requires, as it does not reassemble continuation frames.
2. Move Deno injection after successful tracer setup and PID admission. The current
   `traceAttacher` order injects before `getTracer`; checking configuration alone does
   not prove that `sk_msg` is ready.
3. Inject the Deno agent only when `EBPF.ContextPropagation.HasHeaders()` is set;
   otherwise sk_msg never runs and every placeholder would leak.
4. Evaluate the async Deno payload with CDP `awaitPromise: true`, and rethrow setup
   failures after logging them. Otherwise Go reports "Script successfully injected"
   as soon as it receives the Promise object, even if the dynamic imports or patches
   later fail. This composes with #2858 only if the payload's completion value *is*
   the promise — `(async () => { ... })()` as the file's last expression, with no
   trailing statement — otherwise there is nothing to await. Deno's inspector support
   for `awaitPromise` must be confirmed empirically.
5. Use a two-phase activation so neither side is live alone:
   - create disabled per-PID eBPF state with a fresh secret;
   - expose the secret through a temporary global and evaluate the agent in dormant
     mode;
   - enable the eBPF state, then activate the installed wrappers with a final
     evaluation;
   - on any failure, leave the wrappers inactive and remove or disable the eBPF
     state.
   Passing the secret separately preserves #2858's "inject the file verbatim"
   property. The agent must copy it into closure state and delete the temporary global
   before installation completes. Remove the per-PID state and token entries when the
   process exits or the tracer detaches.

### JS agent — `pkg/internal/nodejs/fdextractor_deno.js`

Separate file from `fdextractor.js`; idempotent (restores originals from a
`Symbol.for` store before patching, so repeated injection cannot stack wrappers).
It must load `node:*` modules with dynamic `await import()`, never `require` — the
latter is undefined in the scope where `Runtime.evaluate` runs and is exactly why the
Node agent fails on Deno today. The async IIFE must settle before the injector logs
success.

- **Candidate anchor, native**: feature-detect and wrap `Request.prototype` accessors
  (`url`, `method`, `headers`, `body`, `bodyUsed`) and body-consumption methods such
  as `arrayBuffer`, `blob`, `bytes`, `formData`, `json`, and `text`; first touch per
  instance (`WeakSet`), skipped while inside our own `fetch` wrapper; read
  `remoteAddr` from the internal slot. The `text()` experiment confirms that body
  methods require their own wrappers. Do not ship the current bare
  `als.enterWith({addr, port})` form: it has demonstrated cross-request bleed. This
  remains Phase 1B research, not the default native path.
- **Anchor, node-compat**: wrap the `'request'` branch of
  `http.Server.prototype.emit` in `als.run(...)`, using
  `req.socket.remoteAddress`/`remotePort`.
- **Egress, native**: `globalThis.fetch` wrapper adding the placeholder header.
- **Egress, node-compat HTTP only**: `http.ClientRequest.prototype.end` / `.write`,
  setting the header while `headersSent` is false. `https:` requests must not receive
  a Phase 1 placeholder.
- **Token codec**: implement the selected synchronous PRF and canonical IPv4/IPv6
  input identically in JS and eBPF. The Node `ClientRequest` hooks are synchronous, so
  the design cannot depend on Web Crypto promises. SipHash with `BigInt` is only a
  candidate until cross-language vectors and overhead are measured.
- No tuple-encoding of the *outgoing* socket, no `fs.accessSync` signalling, no
  `Deno.serve` wrapper. Whether an async hook can provide the missing native request
  boundary remains an experiment, not a settled exclusion.

## Phase 1 failure modes and required degradation

| Situation | Result |
| --- | --- |
| `Symbol(request)` slot missing (future Deno) | no anchor; log; behaves as today |
| Native handler never touches an instrumented `Request` surface | Phase 1B remains disabled by default until a true entry boundary prevents stale ALS reuse; Phase 1A is unaffected |
| Outgoing `https:` | no Phase 1 injection; covered only by the Phase 2 roadmap |
| Peer address cannot be canonicalised, including an unsupported IPv6 form | no placeholder; behaves as today |
| Socket absent from the sockmap (for example, a pooled connection predating attach without iterator backfill) | the downstream may receive a unique, opaque W3C context; it reveals no tuple or stable token and cannot merge the call with another OBI trace |
| Authenticated token resolves to no valid parent | `sk_msg` replaces the placeholder with fresh IDs; do not correlate |
| App/SDK already set `traceparent` | untouched |
| Context propagation disabled by config | agent not injected |
| Agent installation or activation partially fails | wrappers remain inactive and per-PID eBPF state is removed or disabled |

"Behaves as today" means OBI's generic thread-current attribution still handles
some sequential calls; concurrent calls may stay uncorrelated. It must never mean
attaching a request to a different live server span.

## Phase 1 scope boundaries

- **HTTPS/rustls egress**: OBI cannot rewrite the encrypted stream with the Phase 1
  mechanism. Deno's native OTel is an opt-in interoperability path, not the answer to
  this roadmap's zero-service-change constraint.
- **IPv6 clients**: the opaque token/index design can cover the full address without
  changing the wire format. Phase 1 includes IPv6 only after JS/eBPF canonicalisation
  is implemented and covered by shared test vectors; otherwise that address form
  receives no placeholder.
- **Handlers that do not touch their incoming `Request`**: unsupported until the
  native ingress-boundary gate is solved. Pure proxies are an important Phase 1B
  test case.
- **HTTP/2 egress**: plaintext Deno `fetch` speaks HTTP/1.1; h2 is HTTPS-only here.

### Phase 1A acceptance criteria

- The `node:http` compatibility path correlates concurrent inbound requests and
  outbound HTTP calls without wrong parents.
- The service starts with its existing command line and environment.
- The Deno agent never replaces an application/SDK `traceparent`; those headers keep
  the pre-existing eBPF propagation semantics.
- HTTPS receives no placeholder and keeps current behaviour.
- Unsupported ingress cases fail uncorrelated, never cross-correlated.
- No peer address, port, stable token, or recognizable marker reaches an upstream
  service, including attach races and pre-existing pooled sockets.

### Phase 1B acceptance criteria

- Native `Deno.serve` + native HTTP `fetch` meets every Phase 1A safety property.
- Handlers that do not touch the request, touch only its body, or overlap on one
  keep-alive connection cannot inherit another request's parent.
- The native path is enabled by default only after a stable retroactive request-entry
  boundary satisfies those cases. Until then it remains future work within Phase 1,
  not a partially correct feature.

## Integration test plan

Linux CI only (eBPF). Use a separate non-instrumented `denoupstream` container so the
outbound call produces a real client span rather than a same-process loopback
collapse.

The current Deno suite runs the shared Express application through the Node
compatibility layer. Keep it for `node:http` coverage, but add a genuinely native
`Deno.serve` component rather than treating the existing suite as native coverage.
The test OBI config must explicitly enable `context_propagation: headers`.

- Phase 1A: run 40 concurrent `/nested-remote` calls through the `node:http`
  compatibility app, each making one outbound HTTP call. Assertions via Jaeger:
  every server trace contains its outbound client span, that span has the correct
  server-side parent, and no two root requests are accidentally merged.
- Phase 1B gate: run the same test through a genuinely native `Deno.serve` + native
  `fetch` app. This suite is required before native activation, not evidence that the
  accessor-only experiment is safe.
- Native boundary regressions: request A touches an instrumented accessor while B
  touches none; B touches only `await request.text()`; A and B overlap on one
  keep-alive connection. None may observe or inject another request's context.
- Verify the exact `traceparent` received upstream. With normal `sk_msg` handling it
  must match the finalized OBI client context; an application-set value must not be
  replaced by a Deno-agent placeholder and must follow the existing-header path.
- Exercise an authenticated-placeholder lookup miss and assert that `sk_msg` emits
  fresh valid IDs rather than the placeholder or a stale parent.
- Exercise a pre-attach pooled socket without iterator backfill. The received context
  may be uncorrelated, but must be unique per call and reveal no peer tuple, stable
  token, or recognizable OBI marker.
- Finish request A, reuse its connection, and prove that a later egress cannot adopt
  A's span through either the token index or `server_traces_aux`.
- Negative cases: HTTPS targets, disabled header propagation, failed/partial async
  installation, secret mismatch, tag mismatch, and a random third-party
  `traceparent`.
- Shared codec vectors: PRF outputs and domain separation, nonce masking, IPv4,
  IPv4-mapped IPv6, native IPv6, byte order, port boundaries, all-zero W3C retry, and
  token collision handling.

Gotcha for the assertions: after #2851 OBI reports `telemetry.sdk.language=deno-rust`,
which is exactly what Deno's own native OTel reports too. Tests that need to tell OBI
spans from native ones must key on `telemetry.sdk.name` (`deno-opentelemetry` is
native), never on the language.

## Phase 2 — HTTPS roadmap

### Objective

Propagate a real W3C `traceparent` through native `fetch('https://...')` and the
`node:https` compatibility path, and correlate the resulting client operation to the
current Deno server span, without flags, application changes, or an OTLP exporter in
the service.

### Why Phase 1 cannot simply be enabled for HTTPS

The Phase 1 placeholder is finalized by `sk_msg` after the JS client serializes an
HTTP/1.1 header block. With rustls, that hook sees TLS records, not the header. A
placeholder set by JS would therefore reach the downstream unchanged inside the
encrypted request. Deno's native OTel can solve this for users who opt in, but its
runtime flags and export configuration violate this roadmap's product constraint.

### Investigation tracks

1. **Persistent inspector bridge.** Keep a CDP session and expose a runtime binding.
   Before HTTPS fetch, JS sends the incoming correlation token to OBI; OBI resolves
   the eBPF parent and returns a final trace context that JS can inject before rustls.
   This also needs a design for the OBI client span, inspector lifecycle, target-PID
   authentication, backpressure, failure handling, and measurable overhead.
2. **Stable Deno runtime probe point.** Work with Deno or find a stable USDT/ABI hook
   before rustls encryption and after response decryption. This is preferable to
   per-version byte-signature offsets, but no such supported hook is identified yet.
3. **Revisit ID ownership and the JS→eBPF control channel.** If JS must mint the HTTPS
   client context, define how the existing eBPF server span adopts or links to it
   before emission. Any design must be request-specific, fail closed, and avoid
   response headers visible to users.

Native OTel interoperability remains useful compatibility coverage, but it is not an
acceptance path for zero-change HTTPS support.

### Phase 2 acceptance criteria

- Native HTTPS `fetch` and `node:https` propagate the correct W3C parent under
  concurrency and connection pooling.
- OBI emits a correctly parented client span, not only a downstream header.
- No service flag, permission, code, or exporter configuration changes.
- Failure produces an uncorrelated request, never a leaked marker or wrong parent.
- The mechanism has an explicit Deno-version/architecture compatibility policy and
  bounded overhead.

## Alternatives considered and rejected

- **Wrapping `Deno.serve`** (old branch): gives `info.remoteAddr` cleanly, but is
  function replacement, not prototype patching — not retroactive, so it only works
  under `--inspect-brk`. Rejected by the goal.
- **fd-pair correlation** (Node mechanism): impossible, no fd in Deno.
- **Outgoing-tuple correlation via `getsockname` + `statx` signal** (old branch):
  native `fetch` never surfaces a socket to JS, so the outbound half cannot be
  signalled at all. This is why that branch measured 1/40.
- **JS owns the IDs, server span rewritten from a marker on the response**: validated
  as *feasible* (40/40 tokens on the response matched the outgoing call under
  concurrency) but rejected — it needs kernel-side rewriting of a span's identity,
  leaks a response header to end users unless removed with `bpf_msg_pop_data`, has no
  universal stamping point (finding 4), and is more machinery than Phase 1 needs.
  ID ownership may still need to be revisited for Phase 2 through a different,
  non-leaking control channel.
- **Kernel-side FIFO binding of unclaimed server spans**: no JS tuple needed, but
  correctness rests on Deno dispatching handlers in read order; a single misalignment
  is persistent. Rejected as unreviewable.
- **Extra `x-obi-ctx` request header instead of a placeholder**: leaks a header
  downstream (removal needs `bpf_msg_pop_data`) and leaves two header mechanisms in
  play. A successfully rewritten placeholder is length-preserving and leaves exactly
  one valid header, but its own failure path must still be made safe.
- **Instrumenting rustls**: stripped static binary, no symbols, monomorphised
  generics; only byte-signature offset scanning per version/arch was found. Rejected
  as a production mechanism; a future stable Deno-supported probe remains open.

## Phase 1 design gates

1. **Phase 1A can start independently.** The tested native mechanisms have not found
   a safe retroactive `Deno.serve` request-entry boundary on Deno 2.9.4, which is
   strong evidence but not proof that none can exist. This blocks Phase 1B activation,
   not the `node:http` implementation. Continue async-hook research and pursue a
   stable upstream Deno hook; do not ship a mode known to produce wrong parents.
2. Validate the authenticated token design before implementation: select a PRF that
   is practical in supported eBPF programs and synchronous JS, publish shared test
   vectors, measure agent overhead, define collision behaviour, and review the
   approximately 2⁻⁶⁴ tag-forgery bound against the threat model.
3. Define token-index and `server_traces_aux` lifecycle and parent validation,
   including request completion, connection reuse, HTTP/1.1 pipelining, and work that
   outlives a response.
4. `awaitPromise` support is **closed** (finding 10): Deno's inspector honours it, and
   omitting it lets a rejecting agent terminate the instrumented process. What remains
   to validate is the rest of the two-phase CDP installation: verbatim payload
   injection from #2858, idempotent reinjection, rollback, and PID-exit cleanup. Enable
   JS wrappers only after the eBPF side can recognize their placeholders.
5. Specify one canonical peer codec for JS and eBPF, including IPv4, IPv4-mapped IPv6,
   native IPv6, scope handling, and byte order. Unsupported forms must suppress
   injection rather than encode ambiguously.

(The `String()` naming question is already answered by #2851: `deno-rust`.)

## Execution plan — incremental pull requests

The implementation should be a stack of small PRs. Every PR must be independently
mergeable, leave the repository green, and either add a usable vertical slice or a
production-inert primitive exercised through the real runtime or kernel. A later PR
must not be required to make an earlier one safe.

Common rules for the stack:

- Keep Node.js behaviour unchanged unless a PR explicitly adds a shared regression
  test for it.
- Do not add a user-facing Deno flag or a test-only production configuration knob.
  Activation continues to use OBI's existing `context_propagation: headers` setting.
- Add the highest-level test possible in the same PR. Do not merge skipped or
  expected-failure tests as acceptance coverage.
- A PR that changes eBPF C includes regenerated bindings and passes the required
  generation, formatting, verifier, and integration checks in that same PR.
- Each new egress path starts with HTTP-only scheme guards and existing-header tests;
  HTTPS is never temporarily allowed to carry the placeholder.
- PR descriptions state the dependency immediately before them, so reviewers can
  review the stack bottom-up and each PR can be rebased or reverted independently.

### Prerequisites — existing PRs #2858 and #2851

Land #2858, then rebase and land #2851 if their injector changes conflict. The
implementation stack starts only after both are present: #2858 provides verbatim
payload injection and #2851 provides the Deno instrumentable type. Do not mix fixes
for either prerequisite into the propagation PRs below.

### PR 1 — dedicated Deno integration topology

**Outcome:** the test suite distinguishes native Deno from Deno's Node compatibility
layer and has a deterministic, non-instrumented upstream that can report the exact
header it received.

Changes:

- Add `internal/test/integration/components/denoserver/` with a digest-pinned Deno
  image and a minimal `Deno.serve` application. Keep the existing
  `nodejsserver/Dockerfile_deno` fixture for `node:http`; do not call it native Deno.
- Add a small `denoupstream` component with a `/capture` endpoint. It returns the
  received `traceparent` and a test request ID, but is outside OBI's PID namespace and
  executable selection.
- Add a dedicated compose file and OBI config with header propagation enabled. The
  service command contains no `--inspect`, `--inspect-brk`, Deno OTel flag, or OTLP
  exporter environment.
- Give `denoserver` only deterministic local endpoints: smoke and native HTTP
  `fetch`, plus dedicated listeners or entrypoints for body-only and no-touch cases.
  Those handlers must not read `request.url` merely to route the test: one reads only
  the body and the other never reads its `Request`. Avoid public-internet dependencies
  and same-process loopback as propagation proof.

Tests:

- Container smoke and RED-signal coverage for the native server.
- A fixture-contract test sends concurrent request IDs and verifies that
  `denoupstream` returns the matching ID and captured header for every call. It does
  not assert correlation yet.
- Keep the current Deno suite passing against the compatibility fixture.

This reuses the useful fixture separation from the old
[`deno-old` branch](https://github.com/mariomac/opentelemetry-ebpf-instrumentation/tree/deno-old),
but trims its broad sample application and does not reuse its correlation mechanism.

### PR 2 — reliable Deno-specific CDP payload injection

**Outcome:** OBI can inject and await a Deno-specific async agent after the tracer is
ready, without enabling propagation hooks yet.

Changes:

- Add a minimal, idempotent `fdextractor_deno.js` async IIFE that uses dynamic
  `node:*` imports and installs in a dormant state.
- Select the Node or Deno embedded payload from the runtime type while preserving
  #2858's verbatim evaluation.
- Add CDP `awaitPromise` support, explicit completion/error handling, and Deno-only
  ordering after tracer creation and PID admission.
- Inject the Deno payload only when header propagation is configured. Do not copy the
  old branch's `Deno.serve`, `node:net`, `fs.accessSync`, or `statx` hooks.

Tests:

- Go tests for payload selection, promise completion, exception propagation, timeout,
  and repeated injection.
- A container integration test starts the service before OBI, observes one successful
  Deno-agent handshake, and verifies that the application remains responsive. The
  fake-CDP tests cover setup failure and prove that no wrappers become active.
- A **liveness** test for a deliberately failing agent: the payload must not be able to
  terminate the service. Finding 10 shows an un-awaited rejection kills the Deno
  process, so this test guards both `awaitPromise` and the agent's internal
  catch-and-resolve contract.

### PR 3 — authenticated placeholder codec

**Outcome:** JS and eBPF have one reviewed, deterministic implementation of the
nonce, masked token, authentication tag, and peer canonicalisation. Nothing writes a
placeholder to user traffic yet.

Changes:

- Select the synchronous PRF after a focused verifier/JS cost check; document the
  choice and its collision and forgery bounds in this file.
- Implement the codec as small JS and eBPF helpers with explicit domain separation.
- Initially accept only canonical IPv4 and IPv4-mapped IPv6 inputs. Unsupported forms
  return “do not inject” rather than guessing. Native IPv6 is added separately in
  PR 7.

Tests:

- Shared golden vectors cover byte order, port boundaries, domain separation,
  all-zero W3C retry, secret/tag mismatch, and random third-party headers.
- eBPF program tests execute the real C helpers; Deno container tests execute the JS
  helpers through the injected agent. Both must produce the same bytes for every
  vector.
- Add a small benchmark or bounded-cost assertion so an unsuitable BigInt or eBPF
  implementation is rejected before it reaches the data path.

### PR 4 — gated eBPF correlation and rewrite backend

**Outcome:** the kernel can authenticate a placeholder, resolve its incoming parent,
and finalize the wire `traceparent`; the path remains unreachable for production PIDs
until PR 5 activates it.

Changes:

- Add internal per-PID secret/readiness and token-to-connection maps, both pinned with
  `OBI_PIN_INTERNAL`.
- Populate the token index when a Deno HTTP server span is created. Add completion,
  expiry, collision, and PID-detach cleanup together with the map.
- Extend `tpinjector` to verify and unmask the token, validate
  `server_traces_aux`, and rewrite both IDs. An authenticated lookup miss receives
  fresh IDs; an unauthenticated third-party header stays on the existing path.
- Add the smallest Go controller needed to create disabled state, enable it, disable
  it, and remove it. No agent activation belongs in this PR.

Tests:

- **Infrastructure reality check:** `bpf/tests/` is userspace C that includes the BPF
  headers and mirrors program logic; the repository has **no** harness that loads the
  real programs, seeds maps through the production controller and pushes crafted HTTP
  through `sk_msg`. Building one (cgroup attach, sockmap, socket pairs, privileged CI)
  is a project of its own and must not be smuggled into this PR.
- So cover the decode/verify/resolve logic as pure functions in `bpf/tests/`, extend the
  constant matrix in `pkg/internal/ebpf/verifier/bpf_verifier_test.go`, and defer
  real-datapath proof to PR 5's container suite. If a privileged `sk_msg` harness is
  wanted, propose it as a separate PR with its own justification.
- Cover success, tag/key mismatch, missing and expired parents, stale connection
  reuse, a deliberately seeded token collision, disabled PID, process cleanup, and
  preservation of the existing application-header path.
- Regenerate and verify all affected eBPF artifacts in this PR.

### PR 5 — Phase 1A: `node:http` ingress to `node:http` egress

**Outcome:** the first user-visible slice correlates a Deno compatibility server's
inbound HTTP request with its outbound `http.request`/`http.get` call.

Changes:

- Wrap only the `'request'` branch of `http.Server.prototype.emit` with
  `AsyncLocalStorage.run()` and derive the incoming peer from the public socket API.
- Wrap the HTTP `ClientRequest` write/end path, respecting `headersSent`, an existing
  `traceparent`, and the `http:` scheme guard.
- Implement the two-phase secret and readiness handshake: dormant JS installation,
  eBPF enablement, then JS activation. Roll back both sides on every partial failure.
- Keep Node.js on its existing fd-pair mechanism; this is a Deno-agent change only.

Both hooks in this PR are already de-risked by the discarded branch, which measured
ALS propagation from `http.Server.prototype.emit('request')` and 20 distinct
ingress/egress pairings under 20-way concurrency for `node:http` plus `http.get`. The
no-touch-handler hazard that blocks Phase 1B does not exist here, because
`AsyncLocalStorage.run()` is scoped by construction; state that in the PR description
so review does not have to rediscover it.

Tests:

- Add 40-way concurrent `/nested-remote-http` coverage using the compatibility
  fixture and `denoupstream`. Every OBI client span must have its own server span as
  parent, and no two inbound requests may be merged.
- Assert the finalized upstream header, application-set-header behaviour, keep-alive
  reuse, late attach, disabled propagation, and HTTP-only handling.
- Add coordinator fault-injection tests for every activation step. Send a
  `node:https` request in the container suite and prove that no placeholder is
  installed.

### PR 6 — Phase 1A: `node:http` ingress to native `fetch` egress

**Outcome:** a request received through the compatibility server also correlates when
the handler uses Deno's native HTTP `fetch`.

Changes:

- Add the re-entrant `globalThis.fetch` wrapper and reuse the already active ALS store
  and token codec.
- Preserve every accepted fetch input shape and clone headers only when injection is
  required. Never replace an existing `traceparent`.
- Suppress injection for HTTPS and for absent, stale, or non-canonical context.

Tests:

- Repeat the 40-way correlation test through `/nested-remote-fetch`, including an
  intervening `await`, pooled outbound connections, and mixed
  `http.request`/`fetch` calls.
- Cover `Request` and URL/string inputs, caller-owned `Headers`, existing headers,
  HTTPS, aborted fetches, and an authenticated placeholder that misses the parent.
- Simulate a pre-attach pooled socket without iterator backfill and assert unique,
  opaque, uncorrelated degradation rather than a leaked tuple or wrong parent.

PR 6 completes Phase 1A and is the first sensible release boundary.

### PR 7 — canonical native IPv6 support

**Outcome:** the Phase 1A paths also correlate supported IPv6 peers; until this PR,
those peers deliberately receive no placeholder.

Changes and tests:

- Add native IPv6 and scope handling to the shared codec without changing the wire
  size or token-map shape.
- Add cross-language vectors plus a real IPv6 integration topology for both
  `http.request` and native `fetch`. Do not merge based only on unit vectors if the CI
  environment cannot exercise the socket path.

This PR is optional for the first release if CI cannot provide a reliable IPv6
network; the safe fallback from PR 3 remains in place.

### PR 8 — Phase 1B: native `Deno.serve` ingress

**Scheduling gate:** do not open this implementation PR until a stable retroactive
request-entry boundary has been demonstrated. The accessor-only `enterWith()` design
does not satisfy the gate and must not be proposed as a reduced first version.

**Outcome:** native `Deno.serve` handlers reuse the HTTP `fetch` egress slice from
PR 6 without cross-request ALS contamination.

Changes:

- Feature-detect the proven entry primitive and establish the per-request store with
  bounded lifetime. Unsupported Deno versions leave native propagation inactive.
- Reuse the existing token, activation, and egress code; do not introduce a second
  correlation protocol.
- Keep the accessor and body-method hooks only if the chosen entry primitive still
  needs them for peer discovery, not as the lifetime boundary.

Tests:

- Run the complete concurrent correlation suite against the PR 1 `denoserver`.
- Include handlers that touch `url`, touch only `await request.text()`, never touch the
  request, overlap on one keep-alive connection, throw, return immediately, and leave
  asynchronous work running after the response.
- Re-run all existing-header, HTTPS, late-attach, partial-installation, socket-backfill,
  and unsupported-version failure cases. Every unsupported case must be uncorrelated,
  never cross-correlated.

PR 8 completes plaintext HTTP for both Deno API families.

### Phase 2 — conditional HTTPS PR stack

The HTTP stack must not guess the HTTPS architecture. Start Phase 2 with a separate
design/prototype PR that selects one investigation track and removes the others from
the implementation plan. That PR contains reproducible probes and overhead results,
but no production hook based on version-specific rustls offsets.

Once the primitive is selected, keep the same vertical order:

1. **HTTPS PR A — authenticated control primitive:** implement only the persistent
   inspector bridge or stable runtime hook, with PID authentication, reconnect,
   timeout, backpressure, detach, and process-exit tests. It must not inject headers
   yet.
2. **HTTPS PR B — native `fetch` vertical slice:** obtain a final context before
   rustls, inject it into native HTTPS fetch, and prove correct OBI client-span and
   downstream parenting under concurrency and pooling. Failure must send no synthetic
   placeholder.
3. **HTTPS PR C — `node:https` vertical slice:** extend the selected primitive to the
   compatibility API without changing its synchronous construction semantics. Add
   existing-header, abort, timeout, pooling, and partial-activation coverage.
4. **HTTPS PR D — compatibility and cost envelope:** add the supported Deno-version
   and architecture matrix, soak tests, and an enforced overhead budget before
   declaring HTTPS parity.

The exact files and boundaries of HTTPS PRs A–D remain provisional until the Phase 2
design PR closes the control-channel and ID-ownership questions. Phase 1 review and
release must not depend on them.
