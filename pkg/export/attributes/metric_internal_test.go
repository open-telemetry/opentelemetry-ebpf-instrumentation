// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The expectations are the names OBI's internal Prometheus exporter emitted before these metrics
// were declared here, so this pins the move as a refactor rather than a rename.
func TestInternalPrometheusNames(t *testing.T) {
	tests := []struct {
		metric Name
		prom   string
	}{
		{InternalTracerFlushes, "obi_ebpf_tracer_flushes"},
		{InternalOTELMetricExports, "obi_otel_metric_exports_total"},
		{InternalOTELMetricExportErrors, "obi_otel_metric_export_errors_total"},
		{InternalOTELTraceExports, "obi_otel_trace_exports_total"},
		{InternalOTELTraceExportErrors, "obi_otel_trace_export_errors_total"},
		{InternalInstrumentedProcesses, "obi_instrumented_processes"},
		{InternalInstrumentationErrors, "obi_instrumentation_errors_total"},
		{InternalAvoidedServices, "obi_avoided_services"},
		{InternalBuildInfo, "obi_internal_build_info"},
		{InternalBpfProbeLatency, "obi_bpf_probe_latency_seconds"},
		{InternalBpfMapEntries, "obi_bpf_map_entries"},
		{InternalBpfMapMaxEntries, "obi_bpf_map_max_entries"},
		{InternalKubeCacheForwardLag, "obi_kube_cache_forward_lag_seconds"},
		{InternalBpfNetworkIgnoredPackets, "obi_bpf_network_ignored_packets_total"},
		{InternalBpfNetworkPackets, "obi_bpf_network_packets_total"},
		{InternalQueueCapacityRatio, "obi_queue_capacity_ratio"},
	}

	for _, test := range tests {
		t.Run(test.metric.OTEL, func(t *testing.T) {
			require.NotEmpty(t, test.metric.Prom)
			assert.Equal(t, test.prom, test.metric.Prom)
		})
	}
}
