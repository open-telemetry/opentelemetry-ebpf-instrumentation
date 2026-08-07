# Go Trace API Example

This example shows application-authored Go spans exported by OBI without an
application-side telemetry pipeline. The application uses the global
`otel.Tracer` API and deliberately does not configure an OpenTelemetry SDK,
`TracerProvider`, span processor, or exporter.

The example targets the OBI v0.11.0 behavior added by
[PR #2810](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/2810).
Until v0.11.0 is released, the Compose file defaults to a digest-pinned `main`
image built from a revision containing that change. Set `OBI_IMAGE` to use a
different feature-bearing image.

## What Runs

| Service | Description |
|:--------|:------------|
| `app` | Go HTTP application whose background checkout worker creates a root span and its child |
| `obi` | OBI discovers the application, activates the Auto SDK path, and exports its spans |
| `jaeger` | OTLP-compatible trace backend and UI at <http://localhost:16686> |

## Prerequisites

- Docker with Docker Compose
- A 64-bit Linux `amd64` or `arm64` host that meets the general
  [OBI runtime requirements](../../SUPPORT_MATRIX.md#runtime-requirements)
- Permission to run OBI as a privileged container with host PID access
- Permission for `bpf_probe_write_user`; on Linux 5.10 and later this requires
  effective `CAP_SYS_ADMIN` and kernel lockdown mode `[none]`

Check the active lockdown mode with:

```sh
cat /sys/kernel/security/lockdown
```

## Start The Example

From this directory, start all three services:

```sh
docker compose up --build --detach
```

Wait for the application to become ready:

```sh
until curl --fail --silent http://localhost:8080/health > /dev/null; do sleep 1; done
```

Give OBI a few seconds to discover and instrument the application, then create
the example trace:

```sh
curl --fail --silent --show-error http://localhost:8080/trace
```

Rich activation returns:

```json
{"root_recording":true,"child_recording":true}
```

If either value is `false`, wait a few seconds and retry once before following
the [activation troubleshooting](#application-or-activation-problems) steps.

To use another OBI build, set `OBI_IMAGE` to its complete tag-and-digest
reference before running the startup command. Use the published v0.11.0 digest
when that release becomes available.

## Inspect The Trace

Open the [Jaeger UI](http://localhost:16686), select the
`go-trace-api-example` service, and search for the `checkout` operation. The
endpoint queues representative checkout work to a background worker. The
worker's trace should contain exactly these application-authored spans:

```text
checkout
└── reserve inventory
```

The root span should have:

- attributes `example.order.id=order-123` and `example.cart.items=2`
- an event named `checkout started` with
  `example.customer.tier=gold`
- instrumentation scope name `go-trace-api-example` and version `1.0.0`

The `reserve inventory` child should share the root trace ID, name the root as
its parent, have `CLIENT` kind and `OK` status, and include
`example.inventory.sku=sku-42` and `example.inventory.quantity=2`.

Jaeger can also be queried directly:

```sh
curl --get --fail --silent --show-error \
  --data-urlencode service=go-trace-api-example \
  --data-urlencode operation=checkout \
  --data-urlencode limit=20 \
  http://localhost:16686/api/traces
```

## How Activation Works

The OpenTelemetry Go API includes the Auto SDK path used here, but OBI activates
it automatically only when every v0.11.0 eligibility gate passes. There is no
application SDK or exporter to configure, and the application must not install
a provider itself for this path. See the
[exact v0.11.0 module and platform allowlist](../../SUPPORT_MATRIX.md#go-global-trace-api-and-auto-sdk-activation).

The gates cover canonical module versions and checksums, an unreplaced module
graph, supported 64-bit ABI and architecture, required symbols and field
offsets, atomic probe attachment, no already registered SDK delegate, and
permission to use `bpf_probe_write_user`. OBI fails closed when a gate is not
satisfied.

### Rich Activation Versus Synthetic Fallback

The response's `root_recording` and `child_recording` values are an
application-visible signal. Both are `true` when OBI successfully activates the
Auto SDK for that request. In the backend, preservation of the named and
versioned instrumentation scope, event, requested `CLIENT` kind, status,
attributes, and root-child relationship provides positive evidence of the rich
path.

For an otherwise no-SDK application, the global API spans remain non-recording
and the response values are `false` when rich activation is unavailable. Where
its ordinary Go probes are available, OBI may still export reduced-fidelity
synthetic spans. Synthetic fallback does not preserve the complete
application-authored scope, events, kind, or attributes. It is not semantically
equivalent to rich activation and must not be treated as a substitute for it.
If the application has registered an SDK delegate, OBI defers to that SDK
instead of activating this path or creating a competing synthetic span.

OBI v0.11.0 has no stable public activation-success metric or log. Use the
application response together with the rich span data in the backend instead.

## Troubleshooting

### Application Or Activation Problems

If the application is unavailable or either recording value is `false`:

```sh
docker compose ps
docker compose logs app
docker compose logs obi
```

Confirm that the OBI image contains v0.11.0 Auto SDK activation, the executable
matches the exact eligibility matrix, OBI discovered `go-trace-api`, the host
supports OBI, `/sys/kernel/security` is mounted, and lockdown reports `[none]`
where required. `OBI_LOG_LEVEL=DEBUG` can expose discovery, symbol attachment,
optional-probe, or write-user messages:

```sh
OBI_LOG_LEVEL=DEBUG docker compose up --detach --force-recreate obi
docker compose logs --follow obi
```

Module, replacement, and checksum eligibility must still be checked against
the executable's build information and the support matrix. The absence of a
diagnostic reason is not proof that rich activation succeeded.

### OBI Export Or Backend Query Problems

If both recording values are `true` but no trace appears in Jaeger, the
application and activation succeeded. Check OBI's exporter and Jaeger:

```sh
docker compose logs obi
docker compose logs jaeger
```

Enable OBI's local JSON trace printer to separate collection from OTLP export,
then send fresh traffic:

```sh
OBI_TRACE_PRINTER=json_indent docker compose up --detach --force-recreate obi
curl --fail --silent --show-error http://localhost:8080/trace
docker compose logs obi
```

If the rich root and child appear in OBI's output but not Jaeger, investigate
the OTLP connection or backend query rather than application activation.

### Rich Payload Size

OBI v0.11.0 accepts a rich span's serialized OTLP JSON payload only when it is
at most 16 KiB. A larger rich payload is not emitted. v0.11.0 does not expose a
dedicated oversized-payload drop metric or warning, so do not infer the cause
from absent backend data alone, expect a deterministic synthetic replacement,
or expect operator-visible drop telemetry.

## Known Limitations In v0.11.0

- Sampling uses the current activated-root behavior rather than a configurable
  application SDK sampler:
  [#2793](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2793)
- Context handoffs to unrelated workers are not reliably correlated:
  [#2794](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2794)
- External or remote parents and `TraceState` semantics are not preserved:
  [#2959](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2959)
- Payloads larger than 16 KiB are not emitted as rich spans and lack drop
  observability:
  [#2958](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2958)
- Application-authored Auto SDK span IDs are not available for log enrichment:
  [#2932](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2932)

## Stop And Clean Up

```sh
docker compose down --remove-orphans
```
