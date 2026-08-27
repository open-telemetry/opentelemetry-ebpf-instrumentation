# Node.js manual span capture (OTel API span bridge)

Captures spans that Node.js applications create through `@opentelemetry/api`
(`tracer.startSpan()`, `tracer.startActiveSpan()`, `span.end()`) when **no
OpenTelemetry SDK is registered** in the process. Without an SDK, those API
calls return non-recording spans and the telemetry is silently lost — this
feature makes them real and exports them through OBI's normal traces
pipeline, correlated with OBI's automatic spans.

It is the Node.js analog of the Go manual-span support
(`bpf/gotracer/go_sdk.c`), which uprobes the no-op global-API tracer and
backs off when a real SDK is installed. Since JIT-compiled JavaScript cannot
be uprobed (anonymous executable mappings have no inode to attach to), the
capture happens **in-process** via an injected JS bridge, and only the
transport back to OBI is eBPF.

Opt-in: `nodejs.enabled: true` (default) **and** `nodejs.manual_spans: true`
(`OTEL_EBPF_NODEJS_MANUAL_SPANS`, default `false`). Traces (or the trace
printer) must be enabled, like the rest of the Node.js injection support.

## How it works

```
customer app (@opentelemetry/api, no SDK)
   │  tracer.startSpan() / span.end()
   ▼
spanbridge.js ──────────── injected over the inspector protocol together with
   │                       fdextractor.js (SIGUSR1 → CDP Runtime.evaluate).
   │                       Installs a minimal, dependency-free TracerProvider
   │                       as the delegate of each reachable @opentelemetry/api
   │                       copy's ProxyTracerProvider. It does NOT write to the
   │                       API global registry (that would block the app's SDK).
   ▼
fs.accessSync('/dev/null/obi-span/<json>')      ── sentinel uv_fs_access path
   ▼
obi_uv_fs_access uprobe (bpf/generictracer/nodejs.c)
   │  '-span/' branch: copies the JSON payload into a node_span_event_t,
   │  stamps bpf_ktime_get_ns() + pid, and attaches the current request
   │  trace context from traces_ctx_v1 (kept fresh per async context by the
   │  fdextractor.js '-ctx/' sentinels)
   ▼
events ringbuf → EVENT_NODE_SPAN (24)
   ▼
ReadNodeSpanEventIntoSpan (pkg/ebpf/common/node_otel_transform.go)
   │  parses the JSON, re-anchors trace/parent IDs onto the request context
   ▼
request.Span{Type: EventTypeManualSpan}  → existing exporter path, unchanged
```

### Components

- **`pkg/internal/nodejs/spanbridge.js`** — the injected bridge. Implements
  just enough of the OTel API surface (TracerProvider → Tracer → Span, plus
  a context manager) with zero npm dependencies, so it can be evaluated as a
  single expression like `fdextractor.js`. Spans always record; there is no
  sampler (manual spans are explicit customer intent).
- **`pkg/internal/nodejs/{nodejs.go,injector.go}`** — embeds the bridge and
  evaluates it after `fdextractor.js` (both scripts are concatenated into a
  single `Runtime.evaluate` expression; the Node inspector does not accept
  fragmented websocket frames, so the dialer write buffer must stay larger
  than the combined script).
- **`bpf/generictracer/nodejs.c`** — the existing `uv_fs_access` uprobe with
  a third sentinel format. `fs.accessSync()` is safe to call from anywhere in
  JS (synchronous fs ops do not create AsyncWrap objects, so it cannot
  re-enter async_hooks), the kernel fails the call immediately with
  `ENOTDIR`, and the uprobe reads the raw path string before path resolution.
- **`bpf/maps/node_manual_ctx_shadow.h`** — the shadow slot: per-thread saved
  base trace context, stashed while `traces_ctx_v1` is overridden to an active
  manual span (see "Client spans nest under active manual spans").
- **`bpf/common/common.h`** — `node_span_event_t`: event type byte, payload
  length, `end_ktime`, parent trace context (+ validity flag), `pid_info`,
  and a `NODE_SPAN_PAYLOAD_MAX_LEN` (2048) byte payload buffer.
- **`pkg/ebpf/common/node_otel_transform.go`** — decoder. Produces the same
  `request.Span` shape as the Go path: name in `Method`, status message in
  `Path`, attributes as the `SpanAttr` JSON array in `Statement` (the exact
  encoding `tracesgen.manualSpanAttributes` consumes), and the span kind
  mapped from the payload (the JS SpanKind enum is zero-based while Go's is
  shifted by one; unknown values fall back to Internal).

### Sentinel path formats (all handled by `obi_uv_fs_access`)

| Path | Producer | Meaning |
|---|---|---|
| `/dev/null/obi/<fd1><fd2>` | fdextractor.js | outgoing→incoming fd correlation |
| `/dev/null/obi-ctx/<fd>` | fdextractor.js | async-context switch, refreshes `traces_ctx_v1` |
| `/dev/null/obi-noreqctx` | fdextractor.js | callback outside any request, clears `traces_ctx_v1` |
| `/dev/null/obi-span/<json>` | spanbridge.js | finished manual span |
| `/dev/null/obi-mspan/<traceId><spanId>` | spanbridge.js | active manual span: override `traces_ctx_v1` span id so client spans nest under it |
| `/dev/null/obi-mspan/-` | spanbridge.js | pop: no manual span active, restore the saved base context |

### Span payload (JSON, version field `v: 1`)

`name`, `tid`/`sid`/`psid` (hex trace/span/parent-span IDs generated by the
bridge), `extParent` (present and `true` only when `psid` refers to a parent
context the bridge does not own — an app/remote parent; user space flattens
such spans under the OBI request parent when re-anchoring, instead of
exporting a cross-trace parent reference), `kind`, `startNs`/`durNs`,
`endWallNs` (present only when the app passed an explicit end time to
`span.end(t)`; epoch nanoseconds),
`status`/`statusMsg`, `attrs` (flat map, string/number/bool). Budgets, chosen
to mirror the Go path and fit the payload buffer — all measured in UTF-8
BYTES and truncated on a valid sequence boundary (the Go side copies into
fixed byte arrays, so code-unit budgets would split multi-byte characters):
name ≤ 128, ≤ 16 attributes, keys ≤ 31, string values ≤ 127,
whole payload ≤ 1900 bytes. On overflow the attributes are dropped first; if
the bounded core still exceeds the buffer the span is dropped rather than
truncated (a truncated JSON would fail to parse in user space anyway).

Span events and instrumentation scope are intentionally **not** carried in v1:
neither reaches the exported span today (the reader models neither), so
serializing them would only waste the fixed transport budget — and an unbounded
scope string could push the core JSON over the buffer. They can be added once
the downstream span model supports them.

### Timing

The sentinel fires inside `span.end()`, so BPF's `bpf_ktime_get_ns()` at
that moment *is* the span end in the same monotonic domain the rest of the
pipeline uses (`request.Span.Timings()` converts to wall clock at export
time). The start time is reconstructed as `end - durNs`, with the duration
measured in-process by `process.hrtime.bigint()`.

An explicit end timestamp passed to `span.end(t)` (Date, epoch milliseconds,
or `[seconds, nanos]` hrtime tuple) travels as `endWallNs`. Matching
`@opentelemetry/core`, a number below half of `performance.timeOrigin` is
interpreted as a `performance.now()`-style offset; values the decoder cannot
represent (int64 ns) are never emitted. It only moves the span **end**: the
start stays at `anchor - durNs` (the span's actual start), so the exported
duration becomes `explicit end - start`. The explicit end is honored only
when, translated into the monotonic domain, it lands within a bounded skew
(5 minutes, `maxNodeExplicitEndSkew`) of the kernel-side sentinel anchor and
not before the start — an unbounded app wall clock must not corrupt the
monotonic-domain consistency the pipeline assumes. Otherwise (or on any
unusable input) the sentinel anchor is used, as before.

### Trace-context correlation

At sentinel time, BPF looks up `traces_ctx_v1` for the current thread — the
same map the `-ctx/` sentinels maintain, pointing at the trace context of
the in-flight request being processed by the current async context:

- If found, the span is **re-anchored**: it inherits the request's trace ID,
  and bridge-root spans (no in-bridge parent) are parented under OBI's
  automatic server span. Nested manual spans keep their in-bridge parent
  chain (`psid`). A span whose parent is **external** (`extParent`) is
  flattened under the request parent instead — its parent id belongs to a
  different trace, and re-anchoring must not export a cross-trace parent.
- If not found (span outside any request, or ended after the request
  completed), the span keeps the bridge-generated trace ID and is exported
  as its own trace root (unlike Go, which drops orphan manual spans).

### Client spans nest under active manual spans (`-mspan/` + shadow slot)

While a manual span is *active*, OBI's automatic **client** spans made inside
it (an outgoing HTTP call, a DB query) nest **under the manual span** rather
than as siblings under the server span. This mirrors the Go path, where a
manual span pushes itself into `go_trace_map` and restores `prev_tp` on end.

Mechanism:

- The bridge tracks its active-span transitions through the context manager's
  `with()` (`startActiveSpan`) and, per callback, its own `async_hooks`
  `before` hook (it re-applies after `fdextractor.js`'s `-ctx` refresh, since
  the bridge script is evaluated second). On entering/resuming a scope whose
  innermost span is a bridge span, it emits
  `-mspan/<traceId><spanId>`; on synchronous unwind it emits the enclosing
  span's override, or `-mspan/-` (pop) at the top.
- BPF (`handle_manual_ctx`) **overrides the span id** of the thread's
  `traces_ctx_v1` (`obi_ctx`) entry with the manual span's id, keeping the
  request's (server) **trace id**. The pre-override entry — the server context,
  or an all-zero "no base existed" marker when the override happens outside any
  request — is saved once per sync block in the **shadow slot**
  (`node_manual_ctx_shadow`, `bpf/maps/node_manual_ctx_shadow.h`). `pop`
  restores it; the per-callback `-ctx` / `-noreqctx` refresh clears it (each
  callback re-derives the base and the bridge re-applies the override right
  after).
- **Client-span parenting** (`nodejs_manual_reparent_client` in
  `trace_parent.h`): after the fd-correlation map resolves the outgoing call's
  server parent, if the shadow slot exists and the live `traces_ctx_v1` entry
  shares the resolved trace id, the client span's parent is swapped to the live
  (manual) span id. Downstream traceparent propagation follows transitively: the
  injected header carries the client span's own id, whose parent is now the
  manual span. Nothing in the tpinjector path reads `traces_ctx_v1` itself.
- **Root vs. client parenting differ.** The manual span-end handler
  (`handle_node_span`) parents from the **shadow slot** (the server context),
  not the live entry — otherwise a root manual span, whose own override is live
  when it ends, would become its own parent. So the manual *root* still parents
  under the automatic server span, while automatic *client* spans parent under
  the manual span. Nested manual spans are unaffected either way: they carry an
  in-bridge parent (`psid`) that user space prefers.

## Guards: never fight an application SDK

The bridge must never duplicate or break telemetry the customer configured
themselves. It handles this with two signals keyed on *actual provider
registration* — so we also handle cases where instrumentation is depended
upon and imported, but never registered (say it's disabled via
`OTEL_SDK_DISABLED`/feature flags, and those apps' manual spans
should still be captured)

The bridge **never writes to the API global registry**
(`globalThis[Symbol.for('opentelemetry.js.api.1')]`). Occupying its
`trace`/`context` slots — or even creating the object, which stamps an exact
API version — would make a later app `setGlobalTracerProvider` fail the api's
duplicate/version guard and block the app's own SDK. Instead it captures by
setting itself as the delegate of each reachable api copy's
`ProxyTracerProvider`. Two guards follow from this:

1. **Inert if an SDK already owns the API.** If a provider or context manager
   is already registered in the global registry when the bridge loads, it stays
   completely inert (and, as always, does not touch the registry object).

2. **Step aside if an SDK registers later.** If the app registers its own
   provider *after* the bridge is active (a lazily-initialized SDK), the bridge
   yields: it wraps `trace.setGlobalTracerProvider` /
   `context.setGlobalContextManager` on the api copies it wired, and on the
   app's registration it stops emitting and forwards any tracer it had already
   handed out to the app's now-registered provider. Because the bridge never
   occupied the registry, the app's `registerGlobal` succeeds on its own —
   there is nothing to un-register. The application's SDK ends up owning the API
   surface exactly as if the bridge had never been there.

The behavioral SDK detection (`exclude_otel_instrumented_services`, which
observes OTLP exports) applies on top of this as usual.

These behaviors are covered by `pkg/internal/nodejs/spanbridge_test/`
(`make test-nodejs`): api-only capture, SDK-loaded-but-not-
registered (still captured), SDK-registered-before-injection (inert), and
SDK-registered-after-injection (step-aside handover).

### Late attachment / pre-acquired tracers

The bridge is typically injected into an already-running process, after the
app has called `trace.getTracer()`. Those tracers are `ProxyTracer`s that
resolve **only** through their own api copy's `ProxyTracerProvider`
delegate. The bridge therefore walks `require.cache` for every loaded
`@opentelemetry/api` copy and calls `setDelegate(bridgeProvider)` on each
copy's proxy (`getTracerProvider()` returns the copy's own proxy because the
bridge never registers globally). A `Module._load` hook wires copies loaded
*after* injection the same way — including `import '@opentelemetry/api'`, which
resolves to the package's CommonJS entry (it ships no `import`/`node` export
condition) and so still flows through the loader. See "Unreachable api copies"
for the copies this cannot reach.

A `ProxyTracer` caches the first real delegate it resolves, so a tracer that
was acquired **and used** before injection caches the bridge's tracer and
would not follow a later step-aside handover on its own. The bridge's tracer
therefore checks, on each `startSpan`/`startActiveSpan`, whether it has
yielded, and if so forwards to the application-registered provider — so even
those pre-acquired tracers route to the app's SDK after handover.

The handover trigger is not limited to our wrapped setters. An app can also
register its provider through an api copy the bridge could not wrap (a
bundled/inlined copy — see "Unreachable api copies"), which writes the shared
global registry directly, bypassing the setter. The bridge therefore treats
**any non-bridge provider appearing in the global registry** as a handoff
signal too: it stops emitting and routes cached tracers to that provider. This
prevents a reachable copy's cached tracer from exporting through OBI while the
app's SDK — registered via an unwrapped copy — runs at the same time, which
would otherwise leave two providers active in one process.

## Constraints and limitations

- **Opt-in only.** Existing Node.js support (fd extraction, context
  propagation) is unaffected when `nodejs.manual_spans` is off; the BPF
  `-span/` branch simply never fires because nothing emits the sentinel.
- **Injection prerequisites are inherited** from the existing Node injector:
  the process must not have a custom SIGUSR1 handler (checked before
  sending the signal), and the inspector must be reachable. Injection
  happens once per process; apps started after OBI are picked up by
  discovery as usual.
- **Late-registering SDKs** are handled by the step-aside (see Guards): the
  bridge yields and the app's SDK takes over. This covers `@opentelemetry/api`
  copies already loaded when we inject (wired by the `require.cache` scan) and
  copies loaded after injection through the CommonJS loader — including native
  `import '@opentelemetry/api'`, which resolves to the package's CommonJS entry
  and so still hits the `Module._load` wrapper. Normal ESM apps are therefore
  fully supported (capture + handoff), verified on Node 18/20/22.
- **Unreachable api copies (bundled / native-ESM build).** The one copy the
  bridge cannot wire is one the CommonJS loader never sees: an api **inlined
  into a bundle** (webpack/esbuild), or a hypothetical future native-ESM build
  of the api (one that adds an `import`/`node` export condition). Because the
  bridge does not occupy the global registry, such a copy is **neither captured
  nor blocked**: the app's manual spans created through it are not collected,
  but the app's own SDK registers and works normally. If such an unreachable
  copy registers the app's SDK while a *reachable* copy has already cached the
  bridge's tracer, the registry-appearance handoff (see the tracer section
  above) still fires: the bridge stops emitting and routes cached tracers to the
  app provider, so OBI never runs alongside the app's own SDK. This is the
  deliberate trade-off of not touching the global registry — a coverage gap for that
  segment in exchange for never breaking a customer's own telemetry. (OBI
  injects via the inspector *after* process start, so it cannot retroactively
  install a launch-time ESM/bundle hook such as `--import` /
  `import-in-the-middle`.)
- **Dormant auto-instrumentation wakes up.** If the app has
  `@opentelemetry/instrumentation-*` packages *registered* but no SDK
  (today they emit nothing), the bridge's provider makes them record: their
  library spans (HTTP server/client etc.) flow through the bridge and
  duplicate OBI's own eBPF spans for the same operations. Packages that are
  merely installed but never required are harmless. Mitigation options
  (not yet implemented, pending a product decision): drop bridge spans
  whose scope matches `@opentelemetry/instrumentation-*`, or stay inert
  when `@opentelemetry/instrumentation` is loaded.
- **eBPF client spans nest under active manual spans.** An outgoing call made
  inside a manual span nests as a child of it, matching the Go path:

  ```
  GET /  (OBI server span)
  └─ process-order (manual)
     ├─ charge-card (manual)
     └─ HTTP GET downstream (OBI client span)   ← child of process-order
  ```

  This is implemented via the `-mspan/` sentinel + `node_manual_ctx_shadow`
  slot; see "Client spans nest under active manual spans" above. Note that it
  changes the observable *contents* of the OTEP-referenced `traces_ctx_v1` map
  mid-request (the span id is temporarily the manual span's while one is
  active); the trace id is always the server's, and the pre-override base is
  preserved in the shadow slot and restored on unwind.

  The **log enricher** (`bpf/logenricher/logenricher.c`) is the other reader of
  `traces_ctx_v1`, so this also moves log-to-trace correlation for Node manual-
  span users from the server span to the innermost active manual span — the
  correlation OTel SDKs produce for the same code. The override is dropped on
  the async_hooks `after` boundary as well as on synchronous unwind, so a log
  line emitted after the span ended does not carry it.
- **End-time context sampling.** The request context is read when the span
  *ends*. A manual span that outlives its request falls back to the bridge
  trace ID; if a nested chain ends across the request boundary, the chain
  can split across trace IDs. To avoid *mis*-parenting, `fdextractor.js` emits
  a `-noreqctx` clear when an async callback runs outside any request, so a
  span ending in a background timer is left un-parented rather than attached to
  whichever request last populated `traces_ctx_v1`. The clear is emitted only on
  the request→no-request transition (not on every background callback) to keep
  the syscall off the hot path.
- **Payload budgets** (above). Span events, instrumentation scope, links,
  non-primitive attribute values and `traceState` are not forwarded in v1.
- **Span kind** is exported from the payload (`spanKind()` in tracesgen
  consumes `request.Span.SpanKind` for manual spans, as on the Go Auto path).
- **One bridge per process.** A `globalThis` marker makes re-injection a
  no-op.
- **Never breaks the app.** All bridge failure paths are swallowed; the
  sentinel syscall cost is ~1–2 µs per finished span, zero when the feature
  is off. The one thing the bridge wraps is the CommonJS module loader
  (`Module._load`), used only to wire `@opentelemetry/api` copies loaded after
  injection; the wrapper always calls the original loader first and guards its
  own work, so it composes with other loader patches and can never break a
  `require`. It does *not* use require-in-the-middle/import-in-the-middle, and
  native ESM imports are not intercepted (see the ESM limitation above).
- **Diagnostics are opt-in.** The bridge runs inside the customer's process,
  so it is silent by default — it never writes to the app's stdout/stderr.
  The per-span sentinel emit is *expected* to fail (the path does not exist;
  the uprobe reads it on syscall entry), and that failure is indistinguishable
  from "OBI not attached", so it is never logged per span. Set
  `OTEL_EBPF_NODEJS_DEBUG=1` in the target process to log, to
  stderr, why the bridge stayed inert (SDK present, already registered),
  when it activated, and any genuinely unexpected emit/wiring error — for
  troubleshooting an injection. A hard exception during activation is
  already surfaced OBI-side, because the injector evaluates the script over
  CDP and logs `Runtime.evaluate` exceptions. (A future option, if
  app-side env flags are undesirable, is a dedicated error sentinel that
  OBI's uprobe logs on its own side — not implemented.)

## Testing

- Decoder unit tests: `pkg/ebpf/common/node_otel_transform_test.go`
  (re-anchoring, attribute encoding, timing, error paths).
- JS-side scenarios validated against real `@opentelemetry/api` ≥ 1.9:
  capture with parenting/attributes/status/exceptions, inertness with an
  app SDK (registry untouched, app exporter unaffected), late injection
  with pre-acquired tracers.
- End-to-end: OBI binary + trace printer against a Node HTTP server using
  only `@opentelemetry/api`; each request yields one trace with the manual
  spans nested under the automatic server span, no duplicates.
