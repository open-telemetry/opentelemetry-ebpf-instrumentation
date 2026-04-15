# Statsolly

OBI offers the ability to obtain statistical metrics, such as TCP RTT of all application running on a node.

## Table Of Contents

- [Example](#example)
- [Add a new stat metric](#add-a-new-stat-metric)
- [Notes on attributes](#notes-on-attributes)
- [Final notes](#final-notes)
- [Current metrics](#current-metrics)

## Example

In a non Kubernetes environment:

```
obi_stat_tcp_rtt_seconds_bucket{dst_address="127.0.0.1",dst_name="127.0.0.1",dst_port="54198",dst_zone="",obi_ip="192.168.5.15",src_address="127.0.0.1",src_name="127.0.0.1",src_port="9092",src_zone="",le="1"} 1
```

And the same metric in a Kubernetes environment:

```
obi_stat_tcp_rtt_seconds_bucket{dst_address="10.100.x.x",dst_name="quote",dst_port="8080",dst_zone="",k8s_cluster_name="",k8s_dst_name="quote",k8s_dst_namespace="default",k8s_dst_node_ip="",k8s_dst_node_name="",k8s_dst_owner_name="quote",k8s_dst_owner_type="Service",k8s_dst_type="Service",k8s_src_name="shipping-76f697f685-2wqwc",k8s_src_namespace="default",k8s_src_node_ip="192.168.x.x",k8s_src_node_name="i-0xxxxxxxxxxxxx",k8s_src_owner_name="shipping",k8s_src_owner_type="Deployment",k8s_src_type="Pod",obi_ip="192.168.x.x",src_address="192.168.x.x",src_name="shipping-76f697f685-2wqwc",src_port="39658",src_zone="us-west-2",le="0.01"} 1
```

## Add a new stat metric

To add a new metric, follow these guidelines:

1. Decide on the hook point where you want to attach the eBPF probe. For example, you can use a kprobe on the `tcp_close` function to retrieve `srtt_us`.
2. Add a unique flag that indicates an event related to the metric you want to calculate in [bpf/statsolly/types.h](../bpf/statsolly/types.h) and the corresponding Go constant in [stat.go](../pkg/internal/statsolly/ebpf/stat.go), for example, `k_event_stat_tcp_rtt` and `StatTypeTCPRtt`.
3. Add the eBPF probe to the [bpf/statsolly](../bpf/statsolly/) folder. Here, the metric will be calculated and sent to userspace using the `stats_events` ringbuffer.
4. In the [tracer_ringbuf.go](../pkg/internal/statsolly/stats/tracer_ringbuf.go), simply add a function that handles that metric. This function will convert the event to a `ebpf.Stat`.
5. Then, modify the `Stat` struct accordingly, by adding a data structure containing all the necessary fields. For example `TCPRtt` struct.
6. The only thing left is to create the appropriate data structures in the `Prometheus` and `OTEL` exporters by adding the appropriate attributes. Check `statMetricsReporter` struct for Prometheus and `statMetricsExporter` struct for OTEL.

## Notes on attributes

Statistical metrics have a list of attributes for both k8s and non-k8s defined in [pkg/export/attributes/attrs_defs.go](../pkg/export/attributes/attr_defs.go). Some of these attributes default to true, and false can be set to true during configuration.
Finally, it's possible to add ad hoc attributes specific to a given metric.

## Final notes

We decided to create a component separate from **Appolly** and **Netolly**, focusing only on **statistical metrics**. Statistical metrics are calculated for all applications running on the node, regardless of the PID that triggered the event. This is because statistical metrics are important if correlated to all applications, and also because some hook points can cause unreliable PID calculations and lead to false positives.

The user can then filter the metrics in userspace using appropriate filters or even the collector.

## Current metrics

Below is a table of the currently supported stat metrics:

| Metric name | Hook Point | Description |
|:-------------|:--------------|:--------------|
| obi_stat_tcp_rtt_seconds | kprobe/tcp_close | measures the smoothed TCP RTT as calculated by the kernel in seconds |
| obi_stat_tcp_failed_connections | tracepoint/sock/inet_sock_set_state | counts the TCP failed connections between 2 endpoints |
