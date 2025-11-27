# Add new TCP based BPF tracer

This document the steps required to add a new TCP protocol based BPF tracer to OBI.

## Table Of Contents

- [Investigate the protocol](#investigate-the-protocol)
- [Add the new protocol to the BPF program](#add-new-tcp-based-bpf-tracer)
- [Other considerations](#other-considerations)

## Investigate the protocol

First, you need to understand the protocol used by the application you want to trace. OBI captures TCP packets and you need to add the logic to identify the packets that belong to the protocol you want to trace. The are basically two cases:

- The package comes in plain text, like SQL. In this case, you can just search for the SQL keywords in the packets.
- The package comes in binary format, like Kafka. In this case, you need to figure out how to identify the start and end of the packets and where the relevant information is.

## Add the new protocol to the BPF program

In [pkg/ebpf/common/tcp_detect_transform.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/4dac55491290db8992c4a3d0c30f60039b406a83/pkg/components/ebpf/common/tcp_detect_transform.go) any TCP packet captured from BPF passes through the [`ReadTCPRequestIntoSpan` function](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/4dac55491290db8992c4a3d0c30f60039b406a83/pkg/components/ebpf/common/tcp_detect_transform.go#L32), and depending what's in the bytes, you can identify if the packet is SQL, Redis, etc. You need to add a new case to this function to identify the new protocol.

Once you have this done (the hard part!), you have to create a new `EventType` in [pkg/app/request/span.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/4dac55491290db8992c4a3d0c30f60039b406a83/pkg/app/request/span.go#L26). Look how other `EventTypes` are handled, and you probably need to edit every single file where the data is flowing. For example, to add a new OTEL trace you have to edit `TraceAttributesSelector` function in [pkg/export/otel/tracesgen/tracesgen.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/4dac55491290db8992c4a3d0c30f60039b406a83/pkg/export/otel/tracesgen/tracesgen.go#L296)

Take a look at [this PR](https://github.com/grafana/beyla/pull/890) for an example of how to add a new Kafka protocol.

## Other considerations

- Add always definitions for Prometheus metrics and OpenTelemetry traces and metrics.
- Look for already defined semantic conventions defined in OpenTelemetry spec for those attributes.
  - If there's nothing defined, you can create your own attributes, and if they are useful, propose them to the OpenTelemetry community.
- Add always tests, both unit and OATS integration tests.
- Add always documentation of the newly introduced metrics and traces for this protocol.
