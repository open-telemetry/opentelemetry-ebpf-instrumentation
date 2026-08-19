// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The expectations are the names OBI's internal Prometheus exporter emitted before these metrics
// were declared here, so this pins the move as a refactor rather than a rename.
func TestInternalPrometheusNames(t *testing.T) {
	internal := NewInternalMetrics("obi")

	tests := []struct {
		metric Name
		prom   string
	}{
		{internal.TracerFlushes, "obi_ebpf_tracer_flushes"},
		{internal.OTELMetricExports, "obi_otel_metric_exports_total"},
		{internal.OTELMetricExportErrors, "obi_otel_metric_export_errors_total"},
		{internal.OTELTraceExports, "obi_otel_trace_exports_total"},
		{internal.OTELTraceExportErrors, "obi_otel_trace_export_errors_total"},
		{internal.InstrumentedProcesses, "obi_instrumented_processes"},
		{internal.InstrumentationErrors, "obi_instrumentation_errors_total"},
		{internal.AvoidedServices, "obi_avoided_services"},
		{internal.BuildInfo, "obi_internal_build_info"},
		{internal.BpfProbeLatency, "obi_bpf_probe_latency_seconds"},
		{internal.BpfMapEntries, "obi_bpf_map_entries"},
		{internal.BpfMapMaxEntries, "obi_bpf_map_max_entries"},
		{internal.KubeCacheForwardLag, "obi_kube_cache_forward_lag_seconds"},
		{internal.BpfNetworkIgnoredPackets, "obi_bpf_network_ignored_packets_total"},
		{internal.BpfNetworkPackets, "obi_bpf_network_packets_total"},
		{internal.QueueCapacityRatio, "obi_queue_capacity_ratio"},
	}

	for _, test := range tests {
		t.Run(test.metric.OTEL, func(t *testing.T) {
			require.NotEmpty(t, test.metric.Prom)
			assert.Equal(t, test.prom, test.metric.Prom)
		})
	}
}

// A component that vendors OBI can override attr.VendorPrefix, so the names must be built from
// the prefix rather than baked in.
func TestInternalMetricsHonourVendorPrefix(t *testing.T) {
	vendored := NewInternalMetrics("beyla")

	assert.Equal(t, "beyla.ebpf.tracer.flushes", vendored.TracerFlushes.OTEL)
	assert.Equal(t, "beyla_ebpf_tracer_flushes", vendored.TracerFlushes.Prom)
	assert.Equal(t, "beyla_bpf_network_packets_total", vendored.BpfNetworkPackets.Prom)
	assert.Equal(t, "beyla_bpf_probe_latency_seconds", vendored.BpfProbeLatency.Prom)
}

func TestInternalMetricsAllDeclared(t *testing.T) {
	internal := NewInternalMetrics("obi")

	for name, m := range map[string]Name{
		"TracerFlushes":            internal.TracerFlushes,
		"OTELMetricExports":        internal.OTELMetricExports,
		"OTELMetricExportErrors":   internal.OTELMetricExportErrors,
		"OTELTraceExports":         internal.OTELTraceExports,
		"OTELTraceExportErrors":    internal.OTELTraceExportErrors,
		"InstrumentedProcesses":    internal.InstrumentedProcesses,
		"InstrumentationErrors":    internal.InstrumentationErrors,
		"AvoidedServices":          internal.AvoidedServices,
		"BuildInfo":                internal.BuildInfo,
		"BpfProbeLatency":          internal.BpfProbeLatency,
		"BpfMapEntries":            internal.BpfMapEntries,
		"BpfMapMaxEntries":         internal.BpfMapMaxEntries,
		"KubeCacheForwardLag":      internal.KubeCacheForwardLag,
		"BpfNetworkIgnoredPackets": internal.BpfNetworkIgnoredPackets,
		"BpfNetworkPackets":        internal.BpfNetworkPackets,
		"QueueCapacityRatio":       internal.QueueCapacityRatio,
	} {
		t.Run(name, func(t *testing.T) {
			require.NotEmpty(t, m.OTEL, "OTEL name must be set")
			require.NotEmpty(t, m.Prom, "Prom name must be derived")
			assert.True(t, strings.HasPrefix(m.OTEL, "obi."), "must carry the vendor prefix")
		})
	}
}
