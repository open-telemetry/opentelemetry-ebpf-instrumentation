# Documentation for developers

This directory contains documentation that is not useful for our users but might be useful for developers.

## Table Of Contents

- [Pipeline Map](pipeline-map.md): explanation of pipeline map.
- [Profiling](profiling.md): how to profile OBI.
- [Features](features.md): features supported by OBI.
- [Context Propagation Architecture](context-propagation.md): how OpenTelemetry context propagation works in the eBPF instrumentation.
- [Protocols](protocols/README.md): documentation about supported protocols.
- [AI Tooling](ai-tooling.md): recommendations for configuring agent tooling for this repository.
- [BPF print format](bpf-print-format.md): it explains a uniform standard for all BPF print debug statements across the project.
- [Dependency Integrity Policy](dependency-integrity-policy.md): required dependency pinning and verification rules for Dockerfiles.
- [Statistical Metrics](statsolly.md): it explains how to add a new statitiscal metric to OBI.
- [Python asyncio and uvloop Context Propagation](python-asyncio-context-propagation.md): architecture and implementation of Python async context propagation for `asyncio` workloads, including applications running on `uvloop`.
- [Trace-Profile Correlation](trace-profile-correlation.md): standard communication channel for correlating profiles to OBI traces.
