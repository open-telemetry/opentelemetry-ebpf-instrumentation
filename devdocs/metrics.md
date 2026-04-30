# OBI metrics

> The full list of metrics OBI exports — names in OTel and Prometheus form, types, units, descriptions, and per-metric attribute defaults — lives in the user-facing OBI docs: <https://opentelemetry.io/docs/zero-code/obi/metrics/>.
>
> This document is the **developer-internal companion** to that page: it explains how each component's pipeline turns eBPF events into the metrics listed there, where to edit when adding a new one, and the attribute-group composition behind each metric's label set.

## Table Of Contents

- [NetO11y](#neto11y)
- [AppO11y](#appo11y)
- [StatsO11y](#statso11y)
- [General notes](#general-notes)

Each component has its own pipeline, described in the [pipeline-map doc](pipeline-map.md). In short, each component has its own maps, events, and a set of userspace nodes that add, modify, and export the data obtained from eBPF probes.

## NetO11y

**NetO11y** uses eBPF probes attached at the [TC level in ingress and egress](../bpf/netolly/flows.c) as well as a [socket/filter](../bpf/netolly/flows_sock.c).

The event we're interested in on the kernel side is called `flow_record_t` and on the userspace side is called `NetFlowRecordT`, which is read by a dedicated ringbuffer (exclusive to **NetO11y**) and will be treated as an `ebpf.Record` (defined in [pkg/internal/netolly/ebpf/record.go](../pkg/internal/netolly/ebpf/record.go)) field from there on.

The `ebpf.Record` contains accumulated metrics from a flow, with additional metadata added from the user space. It is the structure that passes all the pipeline nodes to the metric exporters.

The `Attrs` field contains various attributes that can be added to the flow record. In particular, any attributes here must also be added to the `RecordGetters` functions in [pkg/internal/netolly/ebpf/record_getters.go](../pkg/internal/netolly/ebpf/record_getters.go) and `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go). For each metric, other ad hoc attributes are defined (such as `networkCIDR` or `networkInterZoneCIDR`).

In [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go), `networkAttributes` and `networkKubeAttributes` are defined. These are `AttrReportGroup` structures that define groups of attributes allowed by a given metric, whether we're in a k8s environment or not. Note that not all attributes are set to true by default and if you want to enable them, you can do so during configuration using the `attributes` field, which allows you to configure the decoration of some extra attributes that will be added to each metric. Example:

```
attributes:
  select:
    obi_network_flow_bytes:
      include:
      - obi.ip
      - src.address
      - dst.address
      ...
```

In the following methods:

- `newMetricsExporter` in [pkg/export/otel/metrics_net.go](../pkg/export/otel/metrics_net.go) for OTEL
- `newNetReporter` in [pkg/export/prom/prom_net.go](../pkg/export/prom/prom_net.go) for Prometheus

the actual metrics are created using the names defined in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go) with the attributes defined and added in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go).

### Add a new network metric

To add a new network metric, follow these guidelines:

1. If new fields are needed on the flow record, extend `flow_record_t` on the eBPF side and the `NetFlowRecordT` / `ebpf.Record` structs on the userspace side.
2. Define the metric `Name` in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go) with its Section, Prom, and OTEL forms.
3. Register the metric in `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go), wiring it to the relevant `AttrReportGroup`s (e.g. `networkAttributes`, `networkKubeAttributes`) and any ad-hoc attributes it needs.
4. If new attributes are introduced, add the matching getters in [pkg/internal/netolly/ebpf/record_getters.go](../pkg/internal/netolly/ebpf/record_getters.go).
5. Wire up the metric in the exporters: `newMetricsExporter` in [pkg/export/otel/metrics_net.go](../pkg/export/otel/metrics_net.go) for OTEL, and `newNetReporter` in [pkg/export/prom/prom_net.go](../pkg/export/prom/prom_net.go) for Prometheus.

## AppO11y

**AppO11y** is the component that handles all application-level tasks and generates traces and metrics. Unlike NetO11y, it uses different types of eBPF probes (such as `uprobe`, `kprobe/kretprobe`) and introduces the concept of a `tracer`, which is the component responsible for tracing a given type of application. Specifically, we can divide tracers into two categories: `gotracer` and `generictracer`.

It also has three common tracers:

- `tpinjector`: handles context propagation via both HTTP headers (sk_msg) and TCP options (BPF_SOCK_OPS)
- `logenricher`: handles trace-log correlation
- `gputracer`: handles GPU (CUDA) instrumentation

These tracers are loaded for any tracer group.

That said, let's focus on the metrics.

In **AppO11y**, the `request.Span` (defined in [pkg/appolly/app/request/span.go](../pkg/appolly/app/request/span.go)) struct is populated with all the necessary information and passes through all the nodes of the pipeline, from reading the necessary data from the eBPF maps to exporting the metrics/traces.

In particular, any attribute here must also be added to the functions `SpanOTELGetters`, `SpanPromGetters` in [pkg/appolly/app/request/span_getters_providers.go](../pkg/appolly/app/request/span_getters_providers.go) and `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go).

In [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go) some `AttrReportGroup` type structures are defined for application metrics in both the k8s and non-k8s environment: `appAttributes` and `appKubeAttributes`. Here too, ad hoc attributes such as `httpCommon`, `httpClientInfo`, and so on are added for each metric. There are attributes that default to true and others to false, but which can be enabled by the user during configuration.

In the following methods:

- `setupOtelMeters` in [pkg/export/otel/metrics.go](../pkg/export/otel/metrics.go) for OTEL
- `newReporter` in [pkg/export/prom/prom.go](../pkg/export/prom/prom.go) for Prometheus

the actual metrics are created using the names defined in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go) with the attributes defined and added in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go).

### Add a new application metric

To add a new application metric, follow these guidelines:

1. If new fields are needed on the span, extend `request.Span` in [pkg/appolly/app/request/span.go](../pkg/appolly/app/request/span.go) and populate them in the relevant tracer.
2. Define the metric `Name` in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go).
3. Register the metric in `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go), wiring it to the relevant `AttrReportGroup`s (e.g. `appAttributes`, `appKubeAttributes`, `httpCommon`, `httpClientInfo`) and any ad-hoc attributes.
4. If new attributes are introduced, add them to `SpanOTELGetters` and `SpanPromGetters` in [pkg/appolly/app/request/span_getters_providers.go](../pkg/appolly/app/request/span_getters_providers.go).
5. Wire up the metric in the exporters: `setupOtelMeters` in [pkg/export/otel/metrics.go](../pkg/export/otel/metrics.go) for OTEL, and `newReporter` in [pkg/export/prom/prom.go](../pkg/export/prom/prom.go) for Prometheus.
6. Don't forget to clean each `Expirer` in [`cleanupAllMetricsInstances()`](../pkg/export/otel/metrics.go).

## StatsO11y

**StatsO11y** is the component responsible for calculating statistical metrics — for example, TCP RTT or failed-connection counts — across all applications running on a node, regardless of which PID triggered the event. The probes live in [bpf/statsolly](../bpf/statsolly/).

In [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go) some `AttrReportGroup` type structures are defined for stat metrics in both the k8s and non-k8s environment: `statsAttributes` and `statsKubeAttributes`. Here too, ad hoc attributes can be added for each metric. There are attributes that default to true and others to false, but which can be enabled by the user during configuration.

### Add a new stat metric

To add a new metric, follow these guidelines:

1. Decide on the hook point where you want to attach the eBPF probe. For example, you can use a kprobe on the `tcp_close` function to retrieve `srtt_us`.
2. Add a unique flag that indicates an event related to the metric you want to calculate in [bpf/statsolly/types.h](../bpf/statsolly/types.h) and the corresponding Go constant in [stat.go](../pkg/internal/statsolly/ebpf/stat.go), for example, `k_event_stat_tcp_rtt` and `StatTypeTCPRtt`.
3. Add the eBPF probe to the [bpf/statsolly](../bpf/statsolly/) folder. Here, the metric will be calculated and sent to userspace using the `stats_events` ringbuffer.
4. In the [tracer_ringbuf.go](../pkg/internal/statsolly/stats/tracer_ringbuf.go), simply add a function that handles that metric. This function will convert the event to a `ebpf.Stat`.
5. Then, modify the `Stat` struct accordingly, by adding a data structure containing all the necessary fields. For example `TCPRtt` struct.
6. The only thing left is to create the appropriate data structures in the `Prometheus` and `OTEL` exporters by adding the appropriate attributes. Each exporter owns one observe-method per stat type (e.g. `observeTCPRtt`, `observeTCPFailedConnections`) that translates the `ebpf.Stat` into a given observation.

    - `statMetricsReporter` in [pkg/export/prom/prom_stats.go](../pkg/export/prom/prom_stats.go) for Prometheus
    - `statMetricsExporter` in [pkg/export/otel/metrics_stats.go](../pkg/export/otel/metrics_stats.go) for OTEL

### Final notes

We decided to create a component separate from **AppO11y** and **NetO11y**, focusing only on **statistical metrics** calculated for all applications running on the node. This is because statistical metrics are important if correlated to all applications, and also because some hook points can cause unreliable PID calculations and lead to false positives.

The user can then filter the metrics in userspace using appropriate filters or even the collector.

## General notes

For both `OTEL` and `Prometheus`, there are metrics created in their respective methods that are **not** defined in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go) because we are disabling user-provided attribute selection for them. They are very specific metrics with an opinionated format for Span Metrics and Service Graph Metrics functionalities. Examples: `ServiceGraphClient = "traces_service_graph_request_client_seconds"` or `SpanMetricsResponseSizes = "traces_spanmetrics_response_size_total"`.

**Note**: a metric is defined using the `Name` type, which represents the name of a metric in three formats. Subsequently, that metric can be a counter, gauge, or other type.
