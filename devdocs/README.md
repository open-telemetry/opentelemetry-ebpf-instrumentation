# Documentation for developers

This directory contains documentation that is not useful for our users but might be useful for developers.

## Table Of Contents

- [Pipeline Map](pipeline-map.md): explanation of pipeline map.
- [Profiling](profiling.md): how to profile OBI.
- [Features](features.md): features supported by OBI.
- [Context Propagation Architecture](context-propagation.md): how OpenTelemetry context propagation works in the eBPF instrumentation.
- [gRPC Context Propagation](grpc-context-propagation.md): HTTP/2 gRPC context propagation via sk_msg HPACK injection and TCP options.
- [Protocols](protocols/README.md): documentation about supported protocols.
- [Java TLS IOCTL Security Notes](java-tls-ioctl-security.md): rationale for the localized Java TLS `ioctl` hardening and why OBI keeps this fix in `java_tls.c`.
- [AI Tooling](ai-tooling.md): recommendations for configuring agent tooling for this repository.
- [BPF print format](bpf-print-format.md): it explains a uniform standard for all BPF print debug statements across the project.
- [Dependency Integrity Policy](dependency-integrity-policy.md): required dependency pinning and verification rules for Dockerfiles.
- [Python asyncio and uvloop Context Propagation](python-asyncio-context-propagation.md): architecture and implementation of Python async context propagation for `asyncio` workloads, including applications running on `uvloop`.
- [Go Channel Span Links](go-channel-span-links.md): receiver-side span links for supported Go channel handoffs.
- [Trace-Profile Correlation](trace-profile-correlation.md): standard communication channel for correlating profiles to OBI traces.
- [Kubernetes Metadata Cache Service (`k8s-cache`)](k8s-cache.md): what the standalone metadata cache service is, why it exists, and how to deploy it alongside OBI.
- [Metrics](./metrics.md): how the NetO11y, AppO11y, and StatsO11y pipelines turn eBPF events into exported metrics, and where to edit when adding a new one.
- [Runtime Metrics](runtimes/README.md): developer notes for the `application_runtime` feature and per-runtime coverage.
