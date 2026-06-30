# Go Channel Span Links

OBI can emit experimental OpenTelemetry span links for Go channel handoffs. The
feature models asynchronous causality: when one goroutine sends work through a
Go channel and another goroutine receives it, the receiver span can link to the
sender span.

## Behavior

OBI emits receiver-side links only. The receiver span links to the sender span,
but the sender span is not changed. OBI does not rewrite trace IDs, does not
rewrite parent span IDs, and does not model channel handoffs as parent-child
relationships. Linked spans remain in separate traces unless they already shared
a trace for another reason.

Links are attached only to OBI-generated spans. If a span is expanded into
queue and processing subspans, the link is attached to the processing subspan
whose span ID matches the receiver work.

## Probe Gating

There is no separate user-facing configuration flag for Go channel span links.
The feature is enabled by default. Runtime channel probes are registered when
Go-specific tracing is enabled and OBI can resolve all `runtime.hchan` offsets
needed by the target binary:

- `qcount`
- `dataqsiz`
- `sendx`
- `recvx`

If any required `runtime.hchan` offset is unavailable, OBI skips channel-link
probes for that binary instead of failing instrumentation. Disabling Go-specific
tracers also disables channel-link probes.

## Supported Handoffs

OBI currently instruments these Go runtime functions:

- `runtime.chansend1`
- `runtime.chanrecv1`
- `runtime.chanrecv2`

The supported handoff shapes are:

- direct unbuffered channel handoffs
- buffered channel handoffs correlated by `runtime.hchan` buffer slot

`runtime.selectgo` and `select`-based channel paths are not supported yet.

## Limits

Pending links are kept in a bounded userspace cache while OBI waits for the
receiver span to be parsed. The cache holds up to 1024 receiver spans and
expires entries after five minutes. Links are deduplicated, invalid span
contexts are ignored, and self-links are dropped.

OBI also honors the OpenTelemetry span link count limit. The default comes from
the OpenTelemetry SDK, and users can override it with
`OTEL_SPAN_LINK_COUNT_LIMIT`.
