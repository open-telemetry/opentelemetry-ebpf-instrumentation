// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes // import "go.opentelemetry.io/obi/pkg/export/attributes"

// OBI's own internal ("meta") metrics, which describe OBI rather than the instrumented
// application. Declared here so their Prometheus name is derived from the OTLP definition
// instead of being hand-written a second time in the internal Prometheus exporter.
//
// Unlike the metrics above these are not user-selectable, so they carry no Section: nothing
// refers to them from an attributes.select group.
var (
	InternalTracerFlushes = metric(Name{
		OTEL: "obi.ebpf.tracer.flushes",
		Unit: "1",
		Type: InstrumentHistogram,
	})
	InternalOTELMetricExports = metric(Name{
		OTEL: "obi.otel.metric.exports",
		Type: InstrumentCounter,
	})
	InternalOTELMetricExportErrors = metric(Name{
		OTEL: "obi.otel.metric.export.errors",
		Type: InstrumentCounter,
	})
	InternalOTELTraceExports = metric(Name{
		OTEL: "obi.otel.trace.exports",
		Type: InstrumentCounter,
	})
	InternalOTELTraceExportErrors = metric(Name{
		OTEL: "obi.otel.trace.export.errors",
		Type: InstrumentCounter,
	})
	InternalInstrumentedProcesses = metric(Name{
		OTEL: "obi.instrumented.processes",
		Type: InstrumentUpDownCounter,
	})
	InternalInstrumentationErrors = metric(Name{
		OTEL: "obi.instrumentation.errors",
		Type: InstrumentCounter,
	})
	InternalAvoidedServices = metric(Name{
		OTEL: "obi.avoided.services",
		Type: InstrumentGauge,
	})
	InternalBuildInfo = metric(Name{
		OTEL: "obi.internal.build.info",
		Type: InstrumentGauge,
	})
	InternalBpfProbeLatency = metric(Name{
		OTEL: "obi.bpf.probe.latency",
		Unit: "s",
		Type: InstrumentHistogram,
	})
	InternalBpfMapEntries = metric(Name{
		OTEL: "obi.bpf.map.entries",
		Type: InstrumentGauge,
	})
	InternalBpfMapMaxEntries = metric(Name{
		OTEL: "obi.bpf.map.max_entries",
		Type: InstrumentGauge,
	})
	InternalKubeCacheForwardLag = metric(Name{
		OTEL: "obi.kube.cache.forward.lag",
		Unit: "s",
		Type: InstrumentHistogram,
	})
	InternalBpfNetworkIgnoredPackets = metric(Name{
		OTEL: "obi.bpf.network.ignored.packets",
		Unit: "{packet}",
		Type: InstrumentCounter,
	})
	InternalBpfNetworkPackets = metric(Name{
		OTEL: "obi.bpf.network.packets",
		Unit: "{packet}",
		Type: InstrumentCounter,
	})
	InternalQueueCapacityRatio = metric(Name{
		OTEL: "obi.queue.capacity.ratio",
		Unit: "1",
		Type: InstrumentGauge,
	})
)
