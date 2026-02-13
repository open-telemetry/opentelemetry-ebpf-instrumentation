# OBI metrics

OBI offers the ability to export various types of metrics using two main components:

1. **netolly**: handles network metrics
2. **appolly**: handles application metrics

Each component has its own pipeline, described in the [pipeline-map doc](pipeline-map.md). In short, each component has its own maps, events, and a set of userspace nodes that add, modify, and export the data obtained from eBPF probes.

## Table Of Contents

- [Netolly](#netolly)
- [Appolly](#appolly)
- [Statsolly](#statsolly)
- [Metric creation](#metric-creation)
- [Notes](#notes)

## Netolly

**Netolly** uses eBPF probes attached at the [TC level in ingress and egress](../bpf/netolly/flows.c) as well as a [socket/filter](../bpf/netolly/flows_sock.c).
The event we're interested in on the kernel side is called `flow_record_t` and on the userspace side is called `NetFlowRecordT`, which is read by a dedicated ringbuffer (exclusive to **Netolly**) and will be treated as an `ebpf.Record` (defined in [pkg/internal/netolly/ebpf/record.go](../pkg/internal/netolly/ebpf/record.go)) field from there on.

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

Below is a list of network metrics supported by OBI, along with an example of a metric in **Prometheus** format:

- **NetworkFlow**:

```
obi_network_flow_bytes_total{dst_name="internal-pinger",job="otel",k8s_src_owner_name="testserver",obi_revision="unset",instance="otelcol:9464",k8s_dst_owner_name="internal-pinger",obi_version="unset",src_name="testserver-5f478dfd76-rp5nb",} 1.770318771509e+09 423 
```

- **NetworkInterZone**:

```
obi_network_inter_zone_bytes_total{job="obi-network-flows-scrape",k8s_cluster_name="my-kube",src_zone="client-zone",dst_zone="control-plane-zone",instance="172.18.0.2:8999",} 1.77039181687e+09 20596 
```

**Note**: a metric is defined using the `Name` type, which represents the name of a metric in three formats. Subsequently, that metric can be a counter, gauge, or other type.

### Metric creation

In the following methods:
- `newMetricsExporter` in [pkg/export/otel/metrics_net.go](../pkg/export/otel/metrics_net.go) for OTEL
- `newNetReporter` in [pkg/export/prom/prom_net.go](../pkg/export/prom/prom_net.go) for Prometheus
the actual metrics are created using the names defined in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go) with the attributes defined and added in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go).


## Appolly

**Appolly** is the component that handles all application-level tasks and generates traces and metrics. Unlike Netolly, it uses different types of eBPF probes (such as `uprobe`, `kprobe/kretprobe`) and introduces the concept of a `tracer`, which is the component responsible for tracing a given type of application. Specifically, we can divide tracers into two categories: `gotracer` and `generictracer`. The latter includes for example the GPU tracer.

It also has three common tracers:

- `tpinjector`: handles context propagation via both HTTP headers (sk_msg) and TCP options (BPF_SOCK_OPS)
- `logenricher`: handles trace-log correlation

These tracers are loaded for any tracer group.

That said, let's focus on the metrics.

In **Appolly**, the `request.Span` (defined in [pkg/appolly/app/request/span.go](../pkg/appolly/app/request/span.go)) struct is populated with all the necessary information and passes through all the nodes of the pipeline, from reading the necessary data from the eBPF maps to exporting the metrics/traces.

In particular, any attribute here must also be added to the functions `SpanOTELGetters`, `SpanPromGetters` in[pkg/appolly/app/request/span_getters_providers.go](../pkg/appolly/app/request/span_getters_providers.go)  and `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go).

As for **Netolly**, also for **Appolly**, in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go) some `AttrReportGroup` type structures are defined for application metrics in both the k8s and non-k8s environment: `appAttributes` and `appKubeAttributes`. Here too, ad hoc attributes such as `httpCommon`, `httpClientInfo`, and so on are added for each metric. There are attributes that default to true and others to false, but which can be enabled by the user during configuration.


In the following methods:
- `setupOtelMeters` in [pkg/export/otel/metrics.go](../pkg/export/otel/metrics.go) for OTEL
- `newReporter` in [pkg/export/prom/prom.go](../pkg/export/prom/prom.go) for Prometheus

the actual metrics are created using the names defined in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go) with the attributes defined and added in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go).


Below is a list of network metrics supported by OBI with an example metric in Prometheus format:

- **HTTPServerRequestSize**

```
http_server_request_body_size_bytes_count{http_request_method="GET",http_response_status_code="200",job="integration-test/testserver",k8s_replicaset_name="testserver-554c8c5646",server_address="testserver",server_port="8080",client_address="runnervmwffz4",k8s_namespace_name="default",k8s_node_name="test-kind-cluster-prom-control-plane",k8s_pod_start_time="2026-02-06 15:28:19 +0000 UTC",k8s_pod_uid="236225b4-e560-49d4-b4c8-331c497bd66a",url_path="/smoke",http_route="/smoke",k8s_cluster_name="obi-k8s-test-cluster",k8s_deployment_name="testserver",k8s_kind="Deployment",k8s_owner_name="testserver",service_name="testserver",instance="default.testserver-554c8c5646-fqh67.testserver",k8s_container_name="testserver",k8s_pod_name="testserver-554c8c5646-fqh67",service_namespace="integration-test",} 1.770391746662e+09 11 
```

- **HTTPServerResponseSize**:

```
http_server_response_body_size_bytes_count{http_response_status_code="200",instance="default.testserver-554c8c5646-fqh67.testserver",k8s_container_name="testserver",k8s_deployment_name="testserver",k8s_kind="Deployment",k8s_pod_name="testserver-554c8c5646-fqh67",k8s_pod_start_time="2026-02-06 15:28:19 +0000 UTC",client_address="runnervmwffz4",http_route="/smoke",k8s_node_name="test-kind-cluster-prom-control-plane",k8s_owner_name="testserver",service_namespace="integration-test",url_path="/smoke",http_request_method="GET",job="integration-test/testserver",k8s_namespace_name="default",k8s_pod_uid="236225b4-e560-49d4-b4c8-331c497bd66a",k8s_replicaset_name="testserver-554c8c5646",server_address="testserver",k8s_cluster_name="obi-k8s-test-cluster",server_port="8080",service_name="testserver",} 1.770391746662e+09 11 
```

- **HTTPClientRequestSize**:

```

```

- **HTTPClientResponseSize**:

```

```

- **HTTPServerDuration**::

```
http_server_request_duration_seconds_count{instance="default.testserver-554c8c5646-fqh67.testserver",k8s_deployment_name="testserver",k8s_owner_name="testserver",k8s_replicaset_name="testserver-554c8c5646",service_name="testserver",http_response_status_code="200",http_route="/iping",k8s_kind="Deployment",server_address="testserver",service_namespace="integration-test",client_address="internal-pinger.default",job="integration-test/testserver",k8s_cluster_name="obi-k8s-test-cluster",k8s_namespace_name="default",k8s_node_name="test-kind-cluster-prom-control-plane",k8s_pod_name="testserver-554c8c5646-fqh67",k8s_pod_start_time="2026-02-06 15:28:19 +0000 UTC",url_path="/iping",http_request_method="GET",k8s_container_name="testserver",k8s_pod_uid="236225b4-e560-49d4-b4c8-331c497bd66a",server_port="8080",} 1.770391746662e+09 9 
```

- **HTTPClientDuration**:

```

```

- **RPCServerDuration**:

```
rpc_server_duration_seconds_count{k8s_container_name="testserver",k8s_kind="Deployment",k8s_pod_name="testserver-554c8c5646-fqh67",k8s_replicaset_name="testserver-554c8c5646",rpc_method="/routeguide.RouteGuide/GetFeature",server_address="testserver",k8s_node_name="test-kind-cluster-prom-control-plane",k8s_owner_name="testserver",k8s_pod_start_time="2026-02-06 15:28:19 +0000 UTC",server_port="5051",job="integration-test/testserver",k8s_pod_uid="236225b4-e560-49d4-b4c8-331c497bd66a",rpc_grpc_status_code="0",rpc_system="grpc",service_name="testserver",client_address="internal-grpc-pinger.default",k8s_deployment_name="testserver",k8s_namespace_name="default",service_namespace="integration-test",instance="default.testserver-554c8c5646-fqh67.testserver",k8s_cluster_name="obi-k8s-test-cluster",} 1.770391746662e+09 21 
```

- **RPCClientDuration**:

```
rpc_client_duration_seconds_count{k8s_node_name="test-kind-cluster-prom-control-plane",k8s_pod_name="internal-grpc-pinger",rpc_method="/routeguide.RouteGuide/GetFeature",rpc_system="grpc",service_namespace="default",instance="default.internal-grpc-pinger.pinger",k8s_pod_start_time="2026-02-06 15:28:41 +0000 UTC",rpc_grpc_status_code="0",server_address="testserver",k8s_cluster_name="obi-k8s-test-cluster",k8s_namespace_name="default",service_name="internal-grpc-pinger",job="default/internal-grpc-pinger",k8s_kind="Pod",k8s_owner_name="internal-grpc-pinger",k8s_pod_uid="037addfd-7a56-4aeb-a4d8-b68846f4f63f",k8s_container_name="pinger",} 1.770391746662e+09 21 
```

- **DBClientDuration**::

```
db_client_operation_duration_seconds_count{error_type!="", db_system_name="redis"} 3
```

- **MessagingPublishDuration**:

```
messaging_publish_duration_seconds_count{messaging_system="kafka", messaging_destination_name="my-topic"} 5
```

- **MessagingProcessDuration**:

```
messaging_process_duration_seconds_count{messaging_system="kafka", messaging_destination_name="my-topic"} 9
```

- **GPUCudaKernelLaunchCalls**:

```

```

- **GPUCudaGraphLaunchCalls**:

```

```

- **GPUCudaKernelGridSize**:

```

```

- **GPUCudaKernelBlockSize**:

```

```

- **GPUCudaMemoryAllocations**:

```

```

- **GPUCudaMemoryCopies**:

```

```

- **DNSLookupDuration**:

```
dns_lookup_duration_seconds_count{dns_question_name="www.opentelemetry.invalid."error_type="NXDomain",service_namespace="integration-test"",service_name="python3.14"} 2
```

## Statsolly

**Statsolly** is the component responsible to calculate statistical metrics, such as TCP RTT of all application running on a node.





## Notes

For both `OTEL` and `Prometheus`, there are metrics created in their respective methods that are **not** defined in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go) because we are disabling user-provided attribute selection for them. They are very specific metrics with an opinionated format for Span Metrics and Service Graph Metrics functionalities. Examples: `ServiceGraphClient = "traces_service_graph_request_client_seconds"` or `SpanMetricsResponseSizes = "traces_spanmetrics_response_size_total"`.

**Important note**: don't forget to clean each `Expirer` in [`cleanupAllMetricsInstances()`](../pkg/export/otel/metrics.go) method.



You can find more metric examples directly in the OBI [CI](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/actions) logs or in the [integration](../internal/test/integration/) tests.
