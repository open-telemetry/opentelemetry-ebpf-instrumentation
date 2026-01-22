# Application Network Tracer

OBI offers the ability to obtain application network metrics, such as TCP RTT related to an instrumented application.

## Table Of Contents

- [Example](#example)
- [Add a new application network metric](#add-a-new-application-network-metric)
- [Notes on attributes](#notes-on-attributes)

## Example

In a non Kubernetes environment:

```
obi_net_tcp_rtt_seconds_bucket{dst_address="127.0.0.1",dst_name="",dst_port="56724",dst_zone="",instance="lima-ubuntu-ebpf:651294",job="main",service_namespace="",src_address="127.0.0.1",src_name="",src_port="9092",src_zone="",le="0.5"} 8
```

And the same metric in a Kubernetes environment:

```
obi_net_tcp_rtt_seconds_bucket{dst_address="192.168.187.167",dst_name="go-client-3-deployment-795484488d-nhfm9",dst_port="52804",dst_zone="us-east-2c",instance="default.go-server-3-deployment-674fb9748f-hpzrf.go-server",job="default/go-server-3-deployment",k8s_cluster_name="",k8s_dst_name="go-client-3-deployment-795484488d-nhfm9",k8s_dst_namespace="default",k8s_dst_node_ip="192.168.177.102",k8s_dst_node_name="i-08e6fe8a9b5968e8a",k8s_dst_owner_name="go-client-3-deployment",k8s_dst_owner_type="Deployment",k8s_dst_type="Pod",k8s_src_name="go-server-3-deployment-674fb9748f-hpzrf",k8s_src_namespace="default",k8s_src_node_ip="192.168.177.102",k8s_src_node_name="i-08e6fe8a9b5968e8a",k8s_src_owner_name="go-server-3-deployment",k8s_src_owner_type="Deployment",k8s_src_type="Pod",service_namespace="default",src_address="192.168.187.168",src_name="go-server-3-deployment-674fb9748f-hpzrf",src_port="9092",src_zone="us-east-2c",le="0.001"} 7
```

## Add a new application network metric

To add a new metric, follow these guidelines:

1. Decide on the hook point where you want to attach the eBPF probe. For example, you can use a kprobe on the `tcp_close` function to retrieve `srtt_us`.
2. Understand how reliable the PID calculation is at that particular hook point. It may happen that the selected hook point is triggered not directly by the instrumented process but by something else (a timer, an external event), and therefore the eBPF probe is executed in a context other than the instrumented process.
3. Add a unique flag that indicates an event related to the metric you want to calculate in [bpf/appnetworktracer/types.h](../bpf/appnetworktracer/types.h) and the corresponding Go constant in [appnetworktracer.go](../pkg/internal/ebpf/appnetworktracer/appnetworktracer.go), for example, `event_app_net_tcp_rtt` and `EventTypeAppNetTcpRtt`.
4. Add the eBPF probe to the [bpf/appnetworktracer](../bpf/appnetworktracer/) folder. Here, the metric will be calculated and sent to userspace using the `app_network_events` ringbuffer.
5. In the [appnetworktracer.go](../pkg/internal/ebpf/appnetworktracer/appnetworktracer.go), simply add a function that handles that metric. This function will convert the event to a `Span`.
6. To use the **Application instrumentation pipeline**, you need to modify the [package request](../pkg/appolly/app/request/span.go) accordingly, in particular by adding the constant relating to the created metric, and adding a data structure containing all the necessary fields within the `AppNet` structure. For example `TCPRtt` struct.
7. The only thing left is to create the appropriate data structures in the `Prometheus` and `OTEL` exporters by adding the appropriate attributes.

## Notes on attributes

Application network metrics have a list of attributes for both k8s and non-k8s defined in [pkg/export/attributes/attrs_defs.go](../pkg/export/attributes/attr_defs.go). Some of these attributes default to true, and false can be set to true during configuration.
Finally, it's possible to add ad hoc attributes specific to a given metric.
