# Excluding services already instrumented with OpenTelemetry

When a process ships its own OpenTelemetry SDK (manual or zero-code/auto
instrumentation), running OBI on top of it produces duplicate telemetry: every
event OBI instruments (HTTP, gRPC, SQL, Redis, Kafka, MongoDB, …) is
reported once by the SDK and once by OBI. To avoid that, OBI can detect that a
service is already exporting OTLP and suppress its own export for that service.

This document describes how that detection works, what assumptions it makes, and
where it falls short.

## Configuration

Two related options live under `discovery:` in the OBI config:

| Option | Env var | Default | Effect |
|---|---|---|---|
| `exclude_otel_instrumented_services` | `OTEL_EBPF_EXCLUDE_OTEL_INSTRUMENTED_SERVICES` | `true` | Suppress OBI-generated **traces** for a service once it is detected as exporting OTLP traces, and suppress OBI-generated **RED metrics** for a service once it is detected as exporting OTLP metrics. The two are tracked independently — exporting traces does not suppress metrics, and vice versa. |
| `exclude_otel_instrumented_services_span_metrics` | `OTEL_EBPF_EXCLUDE_OTEL_INSTRUMENTED_SERVICES_SPAN_METRICS` | `false` | Also suppress OBI-generated **span metrics** for a service detected as exporting OTLP traces. |
| `default_otlp_grpc_port` | `OTEL_EBPF_DEFAULT_OTLP_GRPC_PORT` | `4317` | Fallback peer port used by the gRPC endpoint heuristic (see below) when the process has no `OTEL_EXPORTER_OTLP_*_ENDPOINT` env var set. |

Defined in [`pkg/appolly/services/criteria.go`](../pkg/appolly/services/criteria.go); defaults set in [`pkg/obi/config.go`](../pkg/obi/config.go).

## How detection works

Detection is **behavioral**, not declarative. OBI does not look at command
lines, loaded shared libraries, `OTEL_SDK_DISABLED`, `-javaagent` flags,
`opentelemetry-instrument` wrappers, or any other static marker. Instead, every
HTTP and gRPC-client span produced by OBI is inspected after the fact: if the
span looks like a successful OTLP export, the source service is flagged as
"OTel-instrumented" and subsequent telemetry of that type is dropped at export
time.

### What counts as an "OTLP export span"

A client span originating from PID `p` flags the service when **all** of the
following hold (see `Span.IsExportTracesSpan` / `IsExportMetricsSpan` in
[`pkg/appolly/app/request/span.go`](../pkg/appolly/app/request/span.go)):

1. The span type is `HTTPClient` or `GRPCClient`.
2. The span status is `STATUS_CODE_UNSET` — i.e. HTTP < 400 or gRPC `OK`. A
   failed OTLP export does not trigger detection.
3. Either the path matches a known OTLP route, or — gRPC only — the peer port
   matches the process's OTLP endpoint (see below).

The path/method matchers:

| Telemetry | HTTP path suffix | gRPC method prefix |
|---|---|---|
| Traces | `/v1/traces` | `/opentelemetry.proto.collector.trace.v1.TraceService/Export` |
| Metrics | `/v1/metrics` | `/opentelemetry.proto.collector.metrics.v1.MetricsService/Export` |

For **gRPC** client spans, OBI also accepts the span as an export call when
the peer port matches the process's configured OTLP endpoint — even if the
gRPC method is empty. HTTP client spans only match by path; there is no
port-based fallback for HTTP.

This is done because of a known limitation in OBI's gRPC tracking: for
long-lived connections, OBI may not be able to extract the gRPC service /
method.

The gRPC port match (see `sendsTracesOnGrpcOtelPort` /
`sendsMetricsOnGrpcOtelPort` in
[`pkg/appolly/app/request/span.go`](../pkg/appolly/app/request/span.go)) works
as follows:

- Read `OTEL_EXPORTER_OTLP_PROTOCOL` / `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` /
  `OTEL_EXPORTER_OTLP_METRICS_PROTOCOL` from the target process's environment.
  If any is set to something other than `grpc`, the heuristic stops.
- Compare the span's peer port to the port parsed out of
  `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` / `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT`,
  falling back to `OTEL_EXPORTER_OTLP_ENDPOINT`, falling back to
  `default_otlp_grpc_port` (4317).

Detection is per-telemetry-type and per-service: a service may be flagged for
metrics but not traces, or vice versa. Once flagged, the flag is sticky for the
lifetime of the process.

### Where the flag is applied

The match runs inside `PIDsFilter.Filter` in
[`pkg/ebpf/common/pids.go`](../pkg/ebpf/common/pids.go):

```go
if pf.ignoreOtel {
    pf.checkIfExportsOTel(info.service, span, pf.defaultOtlpGRPCPort)
}
if pf.ignoreOtelSpan {
    pf.checkIfExportsOTelSpanMetrics(info.service, span, pf.defaultOtlpGRPCPort)
}
```

Once a service has its `ExportsOTelMetrics` / `ExportsOTelTraces` /
`ExportsOTelMetricsSpan` flag set, the corresponding exporters drop its spans:

- OTLP metrics — `otelMetricsAccepted` (RED metrics) and `otelSpanMetricsAccepted` (span metrics) in [`pkg/export/otel/metrics.go`](../pkg/export/otel/metrics.go).
- OTLP traces — [`pkg/export/otel/tracesgen/tracesgen.go`](../pkg/export/otel/tracesgen/tracesgen.go).
- Prometheus — RED-metrics and span-metrics filters in [`pkg/export/prom/prom.go`](../pkg/export/prom/prom.go).

Each detection event increments the `obi.avoided.services` internal metric
(Prometheus name: `obi_avoided_services`). Normal series are labeled with the
logical service name, service namespace, and the telemetry type that was
avoided (`metrics` or `traces`). The service instance ID is intentionally not
reported because it is unique per service instance and would churn backend
time series. When the configured cardinality limit is reached, additional
detections are collapsed before export and reported through the OpenTelemetry
overflow attribute `otel.metric.overflow=true` (Prometheus label:
`otel_metric_overflow="true"`). Span-metrics suppression is reported under the
`metrics` label, not a separate one — the `metrics_span` detection path in
`reportAvoidedService` routes through `AvoidInstrumentationMetrics`, which
emits `metrics`. It's emitted from `reportAvoidedService` in
[`pkg/ebpf/common/pids.go`](../pkg/ebpf/common/pids.go) and is the
authoritative signal for whether detection has fired for a given service.

## Assumptions

Detection works on the assumption that the instrumented service:

1. **Eventually emits at least one successful OTLP export.** Detection is
   reactive; OBI must observe the export call before it can suppress.
2. **Uses standard OTLP wire formats** — HTTP path ending in `/v1/traces` or
   `/v1/metrics`, or gRPC method on the standard
   `opentelemetry.proto.collector.{metrics|traces}.v1.{Metrics|Traces}Service/Export`
   service.
3. **Talks to its collector over a transport OBI can decode.** OBI's eBPF
   probes produce client spans for HTTP/1.1, HTTP/2 (including gRPC), and TLS
   only when the corresponding TLS uprobes are attached and the runtime's
   crypto stack is supported (e.g. OpenSSL, Go `crypto/tls`, etc).
4. **For the gRPC port heuristic only:** has its `OTEL_EXPORTER_OTLP_*`
   environment variables visible to OBI. The environment is captured at
   process discovery; the heuristic compares against that snapshot.
5. **Process is long-lived enough** to emit an export before the user looks at
   the data. Default OTLP exporters batch on 5s schedules in most SDKs.

## Limitations

These follow directly from the assumptions and explain the two failure modes
users hit: duplicate telemetry on one end, missing telemetry on the other.

### 1. Startup window: duplicates until the first export

There is always a gap between "first event OBI traces on the process" and
"first OTLP export OBI sees on the outbound client probe". During that gap,
both the SDK and OBI emit telemetry. Even after detection fires, OBI does
**not** retroactively withdraw the spans it already emitted.

In practice this means:

- Short-lived processes (jobs, lambdas) that finish before exporting will
  always produce duplicates.
- The first few requests of a long-lived process are duplicated.

### 2. Suppression is all-or-nothing per service

Once a service is flagged, OBI suppresses **every** span / metric it would
produce for that service, regardless of category. There is no way to say "the
SDK already instruments HTTP and gRPC, so drop only those — but keep emitting
SQL, Redis, Kafka, MongoDB, DNS, …".

Concretely: if a service's SDK only covers HTTP/gRPC (a common configuration
— e.g. only the web framework instrumentation is enabled, or the SDK has no
instrumentation for a database client OBI does support), observing a single
successful OTLP traces export will silence OBI's traces for that service
entirely. The categories the SDK does not cover go dark too, and OBI emits
nothing where it previously was the only source.

A particularly painful variant of this: a service uses the SDK to emit
**custom / business telemetry** (manually instrumented application-level
traces and metrics that have nothing to do with protocol-level events), and
relies on OBI for the protocol-level auto-instrumentation. Because OBI's
detection sees only "this service exports OTLP", it cannot tell the SDK's
output apart from its own — so it disables its entire auto-instrumentation
suite for that service. The user ends up with custom telemetry but no HTTP /
gRPC / SQL / Redis / … telemetry, even though the SDK never produced any of
those.
