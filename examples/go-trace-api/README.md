# Go Trace API Example

This example shows OBI exporting application-authored Go spans created through
the global `otel.Tracer` API. The application does not register a
`TracerProvider`.

## What Runs

| Service | Description |
|:--------|:------------|
| `app` | Go HTTP application whose checkout handler starts a span and calls a function that starts its child |
| `obi` | OBI discovers the application, activates the Auto SDK, and exports its spans |
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

To override the OBI image, supply a complete image reference:

```sh
OBI_IMAGE=<image-reference> docker compose up --build --detach
```

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
curl --fail --silent --show-error http://localhost:8080/checkout
```

When OBI activates the Auto SDK, the endpoint returns:

```json
{"checkout_recording":true,"inventory_recording":true}
```

If either value is `false`, wait a few seconds and retry once before following
the [activation troubleshooting](#application-or-activation-problems) steps.

## Inspect The Trace

Open the [Jaeger UI](http://localhost:16686), select the
`go-trace-api-example` service, and search for the `checkout` operation. The
handler starts the `checkout` span, and `reserveInventory` starts its child:

```text
checkout
└── reserve inventory
```

OBI's HTTP instrumentation also adds request-handling spans above `checkout`.
Those spans are not created by the application.

The `checkout` span should have `SERVER` kind and:

- attributes `example.order.id=order-123` and `example.cart.items=2`
- an event named `checkout started` with
  `example.customer.tier=gold`
- instrumentation scope name `go-trace-api-example` and version `1.0.0`

The `reserve inventory` child should share the `checkout` trace ID, name
`checkout` as its parent, have `CLIENT` kind and `OK` status, and include
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

OBI activates the Auto SDK only when the application has not registered a
`TracerProvider` and the executable and host meet the v0.11.0 requirements. See
the [exact module and platform allowlist](../../SUPPORT_MATRIX.md#go-global-trace-api-and-auto-sdk-activation).

The requirements cover canonical module versions and checksums, modules without
replacements, supported 64-bit ABI and architecture, required symbols and field
layouts, and permission to use `bpf_probe_write_user`. If any requirement is not
met, OBI leaves the Auto SDK inactive.

### Auto SDK Spans Versus Synthetic Spans

The response's `checkout_recording` and `inventory_recording` values show
whether the application's spans are recording. Both are `true` when OBI has
activated the Auto SDK for that request. In Jaeger, the named and versioned
instrumentation scope, event, requested span kinds, status, attributes, and
parent-child relationship confirm that OBI exported the data supplied by the
application.

For an application that has not configured an SDK, the global API spans remain
non-recording and the response values are `false` when OBI cannot activate the
Auto SDK. When OBI can observe calls to the global Trace API, it may still
construct synthetic spans. A synthetic span may contain the span name, parent
relationship, status, and some primitive attributes, but it does not contain
the instrumentation scope, events, or requested span kind. It is not a
substitute for the application-authored span. If the application has registered
an SDK `TracerProvider`, OBI defers to that provider instead of activating the
Auto SDK or creating a competing synthetic span.

OBI v0.11.0 has no metric or log that confirms Auto SDK activation. Check the
application response and the expected application-supplied fields in Jaeger.

## Troubleshooting

### Application Or Activation Problems

If the application is unavailable or either recording value is `false`:

```sh
docker compose ps
docker compose logs app
docker compose logs obi
```

Confirm that the OBI version supports the application's OpenTelemetry modules,
the executable matches the exact eligibility matrix, OBI discovered
`go-trace-api`, the host supports OBI, `/sys/kernel/security` is mounted, and
lockdown reports `[none]` where required. Debug logs can help check discovery,
instrumentation attachment, and write-user permission:

```sh
OBI_LOG_LEVEL=DEBUG docker compose up --detach --force-recreate obi
docker compose logs --follow obi
```

Module, replacement, and checksum eligibility must still be checked against
the executable's build information and the support matrix. A lack of debug
messages does not mean that Auto SDK activation succeeded.

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
curl --fail --silent --show-error http://localhost:8080/checkout
docker compose logs obi
```

If the `checkout` and `reserve inventory` spans appear in OBI's output but not
Jaeger, investigate the OTLP connection or backend query rather than application
activation.

### Payload Size

In OBI v0.11.0, each application-authored span must fit within a 16 KiB encoded
payload. Spans whose payloads exceed this limit are not exported. v0.11.0 does
not log a warning or publish a metric when this happens, so a missing span in
Jaeger does not by itself show that its payload was too large. OBI also does not
guarantee a synthetic replacement.

## Known Limitations In v0.11.0

- OBI's configured trace sampler does not control whether the Auto SDK records
  a span:
  [#2793](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2793)
- Context handoffs to unrelated workers are not reliably correlated:
  [#2794](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2794)
- External or remote parents and `TraceState` semantics are not preserved:
  [#2959](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2959)
- OBI does not export Auto SDK payloads larger than 16 KiB and does not report
  these drops:
  [#2958](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2958)
- Application-authored Auto SDK span IDs are not available for log enrichment:
  [#2932](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2932)

## Stop And Clean Up

```sh
docker compose down --remove-orphans
```
