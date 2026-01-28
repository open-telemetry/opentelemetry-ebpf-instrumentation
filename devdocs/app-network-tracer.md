# Application Network Tracer

OBI offers the ability to obtain application network metrics, such as TCP RTT and TCP connection failures related to an instrumented application. For example, by instrumenting port 9092 on a server, we can obtain the following metric:

```
# HELP obi_net_tcp_rtt_seconds mearures the smoothed TCP RTT as calculated by the kernel in seconds
# TYPE obi_net_tcp_rtt_seconds histogram
obi_net_tcp_rtt_seconds_bucket{instance="lima-ubuntu-ebpf:1661999",job="main",netns="4026531840",port="9092",service_name="main",service_namespace="",le="0.0005"} 0
obi_net_tcp_rtt_seconds_bucket{instance="lima-ubuntu-ebpf:1661999",job="main",netns="4026531840",port="9092",service_name="main",service_namespace="",le="0.001"} 0
obi_net_tcp_rtt_seconds_bucket{instance="lima-ubuntu-ebpf:1661999",job="main",netns="4026531840",port="9092",service_name="main",service_namespace="",le="0.002"} 0
obi_net_tcp_rtt_seconds_bucket{instance="lima-ubuntu-ebpf:1661999",job="main",netns="4026531840",port="9092",service_name="main",service_namespace="",le="0.005"} 0
obi_net_tcp_rtt_seconds_bucket{instance="lima-ubuntu-ebpf:1661999",job="main",netns="4026531840",port="9092",service_name="main",service_namespace="",le="0.01"} 0
obi_net_tcp_rtt_seconds_bucket{instance="lima-ubuntu-ebpf:1661999",job="main",netns="4026531840",port="9092",service_name="main",service_namespace="",le="0.025"} 0
obi_net_tcp_rtt_seconds_bucket{instance="lima-ubuntu-ebpf:1661999",job="main",netns="4026531840",port="9092",service_name="main",service_namespace="",le="0.05"} 0
obi_net_tcp_rtt_seconds_bucket{instance="lima-ubuntu-ebpf:1661999",job="main",netns="4026531840",port="9092",service_name="main",service_namespace="",le="0.1"} 0
obi_net_tcp_rtt_seconds_bucket{instance="lima-ubuntu-ebpf:1661999",job="main",netns="4026531840",port="9092",service_name="main",service_namespace="",le="0.25"} 6
obi_net_tcp_rtt_seconds_bucket{instance="lima-ubuntu-ebpf:1661999",job="main",netns="4026531840",port="9092",service_name="main",service_namespace="",le="0.5"} 6
obi_net_tcp_rtt_seconds_bucket{instance="lima-ubuntu-ebpf:1661999",job="main",netns="4026531840",port="9092",service_name="main",service_namespace="",le="1"} 6
obi_net_tcp_rtt_seconds_bucket{instance="lima-ubuntu-ebpf:1661999",job="main",netns="4026531840",port="9092",service_name="main",service_namespace="",le="+Inf"} 6
obi_net_tcp_rtt_seconds_sum{instance="lima-ubuntu-ebpf:1661999",job="main",netns="4026531840",port="9092",service_name="main",service_namespace=""} 1.221
obi_net_tcp_rtt_seconds_count{instance="lima-ubuntu-ebpf:1661999",job="main",netns="4026531840",port="9092",service_name="main",service_namespace=""} 6
```

To add a new metric, follow these guidelines:

1. Decide on the hook point where you want to attach the eBPF probe. For example, you can use a kprobe on the `tcp_close` function to retrieve `srtt_us`.
2. Understand how reliable the PID calculation is at that particular hook point. It may happen that the selected hook point is triggered not directly by the instrumented process but by something else (a timer, an external event), and therefore the ebpf probe is executed in a context other than the instrumented process.
3. Add a unique flag that indicates an event related to the metric you want to calculate in [bpf/appnetworktracer/types.h](../bpf/appnetworktracer/types.h) and the corresponding go constant in [appnetworktracer.go](../pkg/internal/ebpf/appnetworktracer/appnetworktracer.go), for example, `EVENT_APP_NET_TCP_RTT` and `EventTypeAppNetTcpRtt`.
4. Add the ebpf probe to the [bpf/appnetworktracer](../bpf/appnetworktracer/) folder. Here, the metric will be calculated and sent to userspace using the `app_network_events` ringbuffer.
5. In the [appnetworktracer.go](../pkg/internal/ebpf/appnetworktracer/appnetworktracer.go), simply add a function that handles that metric This function will convert the event to a Span.
6. To use the **Application instrumentation pipeline**, you need to modify the [package request](../pkg/appolly/app/request/span.go) accordingly, in particular by adding the constant relating to the created metric, and adding a data structure containing all the necessary fields within the `AppNet` structure.
7. The only thing left is to create the appropriate data structures in the Prometheus and OTEL exporters by adding the appropriate labels.
