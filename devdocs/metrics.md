# OBI metrics

OBI offers the ability to export various types of metrics using three main components:

1. **NetO11y**: handles network metrics
2. **AppO11y**: handles application metrics
3. **StatsO11y**: handles statistical metrics

Each component has its own pipeline, described in the [pipeline-map doc](pipeline-map.md). In short, each component has its own maps, events, and a set of userspace nodes that add, modify, and export the data obtained from eBPF probes.

## Table Of Contents

- [NetO11y](#neto11y)
- [AppO11y](#appo11y)
- [StatsO11y](#statso11y)
- [Notes](#notes)

> **Note on examples**: the metric samples shown throughout this document are mixed — some are taken from real integration-test scrapes, others are illustrative (label sets reflect the configured attribute groups, but the values are placeholders). Treat them as a guide to the **shape** of each metric (name + label set), not as a guarantee of specific values.

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

Below is a list of network metrics supported by OBI, along with an example of a metric in **Prometheus** format:

- **NetworkFlow**:

```
obi_network_flow_bytes_total{dst_name="internal-pinger",job="otel",k8s_src_owner_name="testserver",obi_revision="unset",instance="otelcol:9464",k8s_dst_owner_name="internal-pinger",obi_version="unset",src_name="testserver-5f478dfd76-rp5nb",} 1.770318771509e+09 423 
```

The example above shows the default attribute set. Attributes such as `obi_ip`, `src.address`, and `dst.address` are off by default and must be enabled via the `attributes.select` config shown earlier.

- **NetworkInterZone**:

```
obi_network_inter_zone_bytes_total{job="obi-network-flows-scrape",k8s_cluster_name="my-kube",src_zone="client-zone",dst_zone="control-plane-zone",instance="172.18.0.2:8999",} 1.77039181687e+09 20596 
```

**Note**: a metric is defined using the `Name` type, which represents the name of a metric in three formats. Subsequently, that metric can be a counter, gauge, or other type.

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

Below is a list of application metrics supported by OBI with an example metric in Prometheus format:

- **HTTPServerRequestSize**:

```
http_server_request_body_size_bytes_count{http_request_method="GET",http_response_status_code="200",job="integration-test/testserver",k8s_replicaset_name="testserver-554c8c5646",server_address="testserver",server_port="8080",client_address="runnervmwffz4",k8s_namespace_name="default",k8s_node_name="test-kind-cluster-prom-control-plane",k8s_pod_start_time="2026-02-06 15:28:19 +0000 UTC",k8s_pod_uid="236225b4-e560-49d4-b4c8-331c497bd66a",url_path="/smoke",http_route="/smoke",k8s_cluster_name="obi-k8s-test-cluster",k8s_deployment_name="testserver",k8s_kind="Deployment",k8s_owner_name="testserver",service_name="testserver",instance="default.testserver-554c8c5646-fqh67.testserver",k8s_container_name="testserver",k8s_pod_name="testserver-554c8c5646-fqh67",service_namespace="integration-test",} 1.770391746662e+09 11 
```

- **HTTPServerResponseSize**:

```
http_server_response_body_size_bytes_count{http_response_status_code="200",instance="default.testserver-554c8c5646-fqh67.testserver",k8s_container_name="testserver",k8s_deployment_name="testserver",k8s_kind="Deployment",k8s_pod_name="testserver-554c8c5646-fqh67",k8s_pod_start_time="2026-02-06 15:28:19 +0000 UTC",client_address="runnervmwffz4",http_route="/smoke",k8s_node_name="test-kind-cluster-prom-control-plane",k8s_owner_name="testserver",service_namespace="integration-test",url_path="/smoke",http_request_method="GET",job="integration-test/testserver",k8s_namespace_name="default",k8s_pod_uid="236225b4-e560-49d4-b4c8-331c497bd66a",k8s_replicaset_name="testserver-554c8c5646",server_address="testserver",k8s_cluster_name="obi-k8s-test-cluster",server_port="8080",service_name="testserver",} 1.770391746662e+09 11 
```

- **HTTPClientRequestSize**:

```
http_client_request_body_size_bytes_count{http_request_method="GET",http_response_status_code="200",http_route="/iping",url_path="/iping",server_address="testserver",server_port="8080",service_name="internal-pinger",service_namespace="default",job="default/internal-pinger",instance="default.internal-pinger.pinger",k8s_cluster_name="obi-k8s-test-cluster",k8s_namespace_name="default",k8s_node_name="test-kind-cluster-prom-control-plane",k8s_pod_name="internal-pinger",k8s_pod_uid="037addfd-7a56-4aeb-a4d8-b68846f4f63f",k8s_pod_start_time="2026-02-06 15:28:41 +0000 UTC",k8s_container_name="pinger",k8s_kind="Pod",k8s_owner_name="internal-pinger",} 1.770391746662e+09 9 
```

- **HTTPClientResponseSize**:

```
http_client_response_body_size_bytes_count{http_request_method="GET",http_response_status_code="200",http_route="/iping",url_path="/iping",server_address="testserver",server_port="8080",service_name="internal-pinger",service_namespace="default",job="default/internal-pinger",instance="default.internal-pinger.pinger",k8s_cluster_name="obi-k8s-test-cluster",k8s_namespace_name="default",k8s_node_name="test-kind-cluster-prom-control-plane",k8s_pod_name="internal-pinger",k8s_pod_uid="037addfd-7a56-4aeb-a4d8-b68846f4f63f",k8s_pod_start_time="2026-02-06 15:28:41 +0000 UTC",k8s_container_name="pinger",k8s_kind="Pod",k8s_owner_name="internal-pinger",} 1.770391746662e+09 9 
```

- **HTTPServerDuration**:

```
http_server_request_duration_seconds_count{instance="default.testserver-554c8c5646-fqh67.testserver",k8s_deployment_name="testserver",k8s_owner_name="testserver",k8s_replicaset_name="testserver-554c8c5646",service_name="testserver",http_response_status_code="200",http_route="/iping",k8s_kind="Deployment",server_address="testserver",service_namespace="integration-test",client_address="internal-pinger",job="integration-test/testserver",k8s_cluster_name="obi-k8s-test-cluster",k8s_namespace_name="default",k8s_node_name="test-kind-cluster-prom-control-plane",k8s_pod_name="testserver-554c8c5646-fqh67",k8s_pod_start_time="2026-02-06 15:28:19 +0000 UTC",url_path="/iping",http_request_method="GET",k8s_container_name="testserver",k8s_pod_uid="236225b4-e560-49d4-b4c8-331c497bd66a",server_port="8080",} 1.770391746662e+09 9 
```

- **HTTPClientDuration**:

```
http_client_request_duration_seconds_count{http_request_method="GET",http_response_status_code="200",http_route="/iping",url_path="/iping",server_address="testserver",server_port="8080",service_name="internal-pinger",service_namespace="default",job="default/internal-pinger",instance="default.internal-pinger.pinger",k8s_cluster_name="obi-k8s-test-cluster",k8s_namespace_name="default",k8s_node_name="test-kind-cluster-prom-control-plane",k8s_pod_name="internal-pinger",k8s_pod_uid="037addfd-7a56-4aeb-a4d8-b68846f4f63f",k8s_pod_start_time="2026-02-06 15:28:41 +0000 UTC",k8s_container_name="pinger",k8s_kind="Pod",k8s_owner_name="internal-pinger",} 1.770391746662e+09 9 
```

- **RPCServerDuration**:

```
rpc_server_duration_seconds_count{k8s_container_name="testserver",k8s_kind="Deployment",k8s_pod_name="testserver-554c8c5646-fqh67",k8s_replicaset_name="testserver-554c8c5646",rpc_method="/routeguide.RouteGuide/GetFeature",server_address="testserver",k8s_node_name="test-kind-cluster-prom-control-plane",k8s_owner_name="testserver",k8s_pod_start_time="2026-02-06 15:28:19 +0000 UTC",server_port="5051",job="integration-test/testserver",k8s_pod_uid="236225b4-e560-49d4-b4c8-331c497bd66a",rpc_grpc_status_code="0",rpc_system="grpc",service_name="testserver",client_address="internal-grpc-pinger.default",k8s_deployment_name="testserver",k8s_namespace_name="default",service_namespace="integration-test",instance="default.testserver-554c8c5646-fqh67.testserver",k8s_cluster_name="obi-k8s-test-cluster",} 1.770391746662e+09 21 
```

- **RPCClientDuration**:

```
rpc_client_duration_seconds_count{k8s_node_name="test-kind-cluster-prom-control-plane",k8s_pod_name="internal-grpc-pinger",rpc_method="/routeguide.RouteGuide/GetFeature",rpc_system="grpc",service_namespace="default",instance="default.internal-grpc-pinger.pinger",k8s_pod_start_time="2026-02-06 15:28:41 +0000 UTC",rpc_grpc_status_code="0",server_address="testserver",k8s_cluster_name="obi-k8s-test-cluster",k8s_namespace_name="default",service_name="internal-grpc-pinger",job="default/internal-grpc-pinger",k8s_kind="Pod",k8s_owner_name="internal-grpc-pinger",k8s_pod_uid="037addfd-7a56-4aeb-a4d8-b68846f4f63f",k8s_container_name="pinger",} 1.770391746662e+09 21 
```

- **DBClientDuration**:

```
db_client_operation_duration_seconds_count{error_type!="", db_system_name="redis"} 3
```

- **MessagingPublishDuration**:

```
messaging_client_operation_duration_seconds_count{messaging_system="kafka", messaging_destination_name="my-topic"} 5
```

- **MessagingProcessDuration**:

```
messaging_process_duration_seconds_count{messaging_system="kafka", messaging_destination_name="my-topic"} 9
```

- **GPUCudaKernelLaunchCalls**:

```
gpu_cuda_kernel_launch_calls_total{service_name="vector-add",service_namespace="gpu-test",job="gpu-test/vector-add",instance="gpu-test.vector-add"} 42
```

- **GPUCudaGraphLaunchCalls**:

```
gpu_cuda_graph_launch_calls_total{service_name="vector-add",service_namespace="gpu-test",job="gpu-test/vector-add",instance="gpu-test.vector-add"} 7
```

- **GPUCudaKernelGridSize**:

```
gpu_cuda_kernel_grid_size_total{service_name="vector-add",service_namespace="gpu-test",job="gpu-test/vector-add",instance="gpu-test.vector-add"} 4096
```

- **GPUCudaKernelBlockSize**:

```
gpu_cuda_kernel_block_size_total{service_name="vector-add",service_namespace="gpu-test",job="gpu-test/vector-add",instance="gpu-test.vector-add"} 256
```

- **GPUCudaMemoryAllocations**:

```
gpu_cuda_memory_allocations_bytes_total{service_name="vector-add",service_namespace="gpu-test",job="gpu-test/vector-add",instance="gpu-test.vector-add",k8s_cluster_name="obi-k8s-test-cluster",k8s_namespace_name="gpu-test",k8s_pod_name="vector-add-7c9d5f8b6c-x2lqp",k8s_container_name="vector-add",k8s_deployment_name="vector-add",k8s_replicaset_name="vector-add-7c9d5f8b6c",k8s_node_name="gpu-node-1",k8s_kind="Deployment",k8s_owner_name="vector-add",k8s_pod_uid="2f6a8d1c-3b4e-4c2a-9f1d-7c8a9b0e1f23",k8s_pod_start_time="2026-02-06 15:28:19 +0000 UTC"} 2.097152e+06
```

- **GPUCudaMemoryCopies**:

```
gpu_cuda_memory_copies_bytes_total{cuda_memcpy_kind="HostToDevice",service_name="vector-add",service_namespace="gpu-test",job="gpu-test/vector-add",instance="gpu-test.vector-add"} 1.048576e+06
```

- **DNSLookupDuration**:

```
dns_lookup_duration_seconds_count{dns_question_name="www.opentelemetry.invalid.",error_type="NXDomain",service_name="python3.14",service_namespace="integration-test"} 2
```

- **GenAIClientInputTokenUsage**:

```
gen_ai_client_token_usage_count{gen_ai_operation_name="chat",gen_ai_provider_name="openai",gen_ai_token_type="input",gen_ai_request_model="gpt-4o-mini",gen_ai_response_model="gpt-4o-mini-2024-07-18",server_address="api.openai.com",server_port="443",service_name="chat-app",service_namespace="genai-test",job="genai-test/chat-app",instance="genai-test.chat-app"} 11
```

- **GenAIClientOutputTokenUsage**:

```
gen_ai_client_token_usage_count{gen_ai_operation_name="chat",gen_ai_provider_name="openai",gen_ai_token_type_output="output",gen_ai_request_model="gpt-4o-mini",gen_ai_response_model="gpt-4o-mini-2024-07-18",server_address="api.openai.com",server_port="443",service_name="chat-app",service_namespace="genai-test",job="genai-test/chat-app",instance="genai-test.chat-app"} 19
```

- **GenAIClientOperationDuration**:

```
gen_ai_client_operation_duration_seconds_count{gen_ai_operation_name="chat",gen_ai_provider_name="openai",gen_ai_request_model="gpt-4o-mini",gen_ai_response_model="gpt-4o-mini-2024-07-18",error_type="",server_address="api.openai.com",server_port="443",service_name="chat-app",service_namespace="genai-test",job="genai-test/chat-app",instance="genai-test.chat-app"} 13
```

**Note**: `GenAIClientInputTokenUsage` and `GenAIClientOutputTokenUsage` share the same Prometheus name (`gen_ai_client_token_usage`) and are disambiguated only by the token-type label — `gen_ai_token_type="input"` vs `gen_ai_token_type_output="output"` (the latter is an OBI-specific key, see `GenAITokenTypeOutput` in [pkg/export/attributes/names/attrs.go](../pkg/export/attributes/names/attrs.go)).

### Add a new application metric

To add a new application metric, follow these guidelines:

1. If new fields are needed on the span, extend `request.Span` in [pkg/appolly/app/request/span.go](../pkg/appolly/app/request/span.go) and populate them in the relevant tracer.
2. Define the metric `Name` in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go).
3. Register the metric in `getDefinitions` in [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go), wiring it to the relevant `AttrReportGroup`s (e.g. `appAttributes`, `appKubeAttributes`, `httpCommon`, `httpClientInfo`) and any ad-hoc attributes.
4. If new attributes are introduced, add them to `SpanOTELGetters` and `SpanPromGetters` in [pkg/appolly/app/request/span_getters_providers.go](../pkg/appolly/app/request/span_getters_providers.go).
5. Wire up the metric in the exporters: `setupOtelMeters` in [pkg/export/otel/metrics.go](../pkg/export/otel/metrics.go) for OTEL, and `newReporter` in [pkg/export/prom/prom.go](../pkg/export/prom/prom.go) for Prometheus.
6. Don't forget to clean each `Expirer` in [`cleanupAllMetricsInstances()`](../pkg/export/otel/metrics.go).

## StatsO11y

**StatsO11y** is the component responsible for calculating statistical metrics, such as the TCP RTT of all applications running on a node.

Below is a list of stat metrics supported by OBI with an example metric in Prometheus format:

- **StatTCPRtt**:

```
obi_stat_tcp_rtt_seconds_bucket{dst_address="10.100.x.x",dst_name="quote",dst_port="8080",dst_zone="",k8s_cluster_name="",k8s_dst_name="quote",k8s_dst_namespace="default",k8s_dst_node_ip="",k8s_dst_node_name="",k8s_dst_owner_name="quote",k8s_dst_owner_type="Service",k8s_dst_type="Service",k8s_src_name="shipping-76f697f685-2wqwc",k8s_src_namespace="default",k8s_src_node_ip="192.168.x.x",k8s_src_node_name="i-0xxxxxxxxxxxxx",k8s_src_owner_name="shipping",k8s_src_owner_type="Deployment",k8s_src_type="Pod",obi_ip="192.168.x.x",src_address="192.168.x.x",src_name="shipping-76f697f685-2wqwc",src_port="39658",src_zone="us-west-2",le="0.01"} 1
```

- **StatTCPFailedConnections**:

```
obi_stat_tcp_failed_connections{dst_address="192.168.x.x",dst_name="frontend-proxy-59cbb58fcd-fhxnj",dst_port="37868",dst_zone="***",k8s_cluster_name="",k8s_dst_name="frontend-proxy-59cbb58fcd-fhxnj",k8s_dst_namespace="default",k8s_dst_node_ip="192.168.x.x.",k8s_dst_node_name="node1",k8s_dst_owner_name="frontend-proxy",k8s_dst_owner_type="Deployment",k8s_dst_type="Pod",k8s_src_name="frontend-64765f9445-sjqrq",k8s_src_namespace="default",k8s_src_node_ip="192.168.x.x.",k8s_src_node_name="i-054820b1045823806",k8s_src_owner_name="frontend",k8s_src_owner_type="Deployment",k8s_src_type="Pod",obi_ip="192.168.x.x.",reason="unknown",service_name="frontend",service_namespace="opentelemetry-demo",service_peer_name="frontend-proxy",service_peer_namespace="opentelemetry-demo",src_address="192.168.x.x",src_name="frontend-64765f9445-sjqrq",src_port="0",src_zone="**"} 1
```

In [pkg/export/attributes/attr_defs.go](../pkg/export/attributes/attr_defs.go) some `AttrReportGroup` type structures are defined for application metrics in both the k8s and non-k8s environment: `statsAttributes` and `statsKubeAttributes`. Here too, ad hoc attributes can be added for each metric. There are attributes that default to true and others to false, but which can be enabled by the user during configuration.

### Add a new stat metric

To add a new metric, follow these guidelines:

1. Decide on the hook point where you want to attach the eBPF probe. For example, you can use a kprobe on the `tcp_close` function to retrieve `srtt_us`.
2. Add a unique flag that indicates an event related to the metric you want to calculate in [bpf/statsolly/types.h](../bpf/statsolly/types.h) and the corresponding Go constant in [stat.go](../pkg/internal/statsolly/ebpf/stat.go), for example, `k_event_stat_tcp_rtt` and `StatTypeTCPRtt`.
3. Add the eBPF probe to the [bpf/statsolly](../bpf/statsolly/) folder. Here, the metric will be calculated and sent to userspace using the `stats_events` ringbuffer.
4. In the [tracer_ringbuf.go](../pkg/internal/statsolly/stats/tracer_ringbuf.go), simply add a function that handles that metric. This function will convert the event to a `ebpf.Stat`.
5. Then, modify the `Stat` struct accordingly, by adding a data structure containing all the necessary fields. For example `TCPRtt` struct.
6. The only thing left is to create the appropriate data structures in the `Prometheus` and `OTEL` exporters by adding the appropriate attributes. Check `statMetricsReporter` struct for Prometheus and `statMetricsExporter` struct for OTEL.

### Important notes

Statistical metrics are calculated for all applications running on the node, regardless of the PID that triggered the event. This is because statistical metrics are important if correlated to all applications, and also because some hook points can cause unreliable PID calculations and lead to false positives.

The user can then filter the metrics in userspace using appropriate filters or even the collector.

## General notes

For both `OTEL` and `Prometheus`, there are metrics created in their respective methods that are **not** defined in [pkg/export/attributes/metric.go](../pkg/export/attributes/metric.go) because we are disabling user-provided attribute selection for them. They are very specific metrics with an opinionated format for Span Metrics and Service Graph Metrics functionalities. Examples: `ServiceGraphClient = "traces_service_graph_request_client_seconds"` or `SpanMetricsResponseSizes = "traces_spanmetrics_response_size_total"`.

**Important note for AppO11y**: don't forget to clean each `Expirer` in [`cleanupAllMetricsInstances()`](../pkg/export/otel/metrics.go) method.
