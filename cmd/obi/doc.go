// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

/*
OBI automatically instruments applications using eBPF to collect distributed
traces, metrics, and logs without requiring code changes.

OBI (OpenTelemetry eBPF Instrumentation) attaches eBPF probes to running
processes to capture telemetry data from HTTP/HTTPS, gRPC, database queries
(SQL, Redis, MongoDB), message queues (Kafka, MQTT), and other protocols.
The collected telemetry is exported in OpenTelemetry format (OTLP).

# Usage

	obi --config=config.yml

The configuration file specifies service discovery, export destinations,
and instrumentation settings.

# Requirements

  - Linux kernel 5.8 or later (recommended: 5.10+)
  - Elevated privileges (CAP_BPF, CAP_PERFMON, ...)
  - Architecture: amd64 or arm64

# Example Configuration

	discovery:
	  services:
	    - open_port: 8080

	otel_traces_export:
	  endpoint: http://localhost:4317

For more information, visit https://opentelemetry.io/docs/zero-code/obi/
*/
package main
