// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes // import "go.opentelemetry.io/obi/pkg/export/attributes"

import (
	"fmt"
	"strings"

	"github.com/prometheus/otlptranslator"
)

// Section of the attributes.select configuration. They are metric names
// using the dot.notation and suppressing any .total .sum or .count suffix.
// They are used as a standardized key in the attributes.select map, whichever
// metric format or name the user provides.
type Section string

// Instrument is the kind of instrument a metric is recorded with. It selects the
// type suffix a Prometheus consumer appends to the metric name.
type Instrument uint8

const (
	UnknownInstrument Instrument = iota
	Counter
	UpDownCounter
	Gauge
	Histogram
)

func (i Instrument) otlp() otlptranslator.MetricType {
	switch i {
	case Counter:
		return otlptranslator.MetricTypeMonotonicCounter
	case UpDownCounter:
		return otlptranslator.MetricTypeNonMonotonicCounter
	case Gauge:
		return otlptranslator.MetricTypeGauge
	case Histogram:
		return otlptranslator.MetricTypeHistogram
	default:
		return otlptranslator.MetricTypeUnknown
	}
}

// Name of a metric. OTEL, Unit and Type are the definition; Prom is derived from
// them so that OBI's Prometheus exporter and any Prometheus consumer of OBI's OTLP
// output name the same metric identically.
type Name struct {
	// Section name in the attributes.select configuration option. It is
	// a normalized form accorting to the normalizeMetric function below.
	// It makes sure that it does not have metric nor aggregation suffix.
	Section Section
	// OTEL name of a metric for the OTEL exporter
	OTEL string
	// Unit of the metric, in UCUM notation, as declared to the OTEL instrument
	Unit string
	// Type of instrument the metric is recorded with
	Type Instrument
	// Prom name of a metric for the Prometheus exporter. Derived, never set by hand.
	Prom string
}

// metric derives the Prometheus name of a metric from its OTLP definition, applying the
// same translation a collector re-exporting OBI's OTLP metrics in Prometheus format does.
func metric(n Name) Name {
	namer := otlptranslator.MetricNamer{WithMetricSuffixes: true}

	prom, err := namer.Build(otlptranslator.Metric{Name: n.OTEL, Unit: n.Unit, Type: n.Type.otlp()})
	if err != nil {
		panic(fmt.Sprintf("cannot derive Prometheus name for metric %q: %s", n.OTEL, err))
	}

	n.Prom = prom
	return n
}

var (
	NetworkFlow = metric(Name{
		Section: "obi.network.flow",
		OTEL:    "obi.network.flow.bytes",
		Unit:    "{bytes}",
		Type:    Counter,
	})
	NetworkFlowPackets = metric(Name{
		Section: "obi.network.flow.packets",
		OTEL:    "obi.network.flow.packets",
		Unit:    "{packets}",
		Type:    Counter,
	})
	NetworkInterZone = metric(Name{
		Section: "obi.network.inter.zone",
		OTEL:    "obi.network.inter.zone.bytes",
		Unit:    "{bytes}",
		Type:    Counter,
	})
	HTTPServerRequestSize = metric(Name{
		Section: "http.server.request.body.size",
		OTEL:    "http.server.request.body.size",
		Unit:    "By",
		Type:    Histogram,
	})
	HTTPServerResponseSize = metric(Name{
		Section: "http.server.response.body.size",
		OTEL:    "http.server.response.body.size",
		Unit:    "By",
		Type:    Histogram,
	})
	HTTPClientRequestSize = metric(Name{
		Section: "http.client.request.body.size",
		OTEL:    "http.client.request.body.size",
		Unit:    "By",
		Type:    Histogram,
	})
	HTTPClientResponseSize = metric(Name{
		Section: "http.client.response.body.size",
		OTEL:    "http.client.response.body.size",
		Unit:    "By",
		Type:    Histogram,
	})
	HTTPServerDuration = metric(Name{
		Section: "http.server.request.duration",
		OTEL:    "http.server.request.duration",
		Unit:    "s",
		Type:    Histogram,
	})
	HTTPClientDuration = metric(Name{
		Section: "http.client.request.duration",
		OTEL:    "http.client.request.duration",
		Unit:    "s",
		Type:    Histogram,
	})
	RPCServerDuration = metric(Name{
		Section: "rpc.server.call.duration",
		OTEL:    "rpc.server.call.duration",
		Unit:    "s",
		Type:    Histogram,
	})
	RPCClientDuration = metric(Name{
		Section: "rpc.client.call.duration",
		OTEL:    "rpc.client.call.duration",
		Unit:    "s",
		Type:    Histogram,
	})
	DBClientDuration = metric(Name{
		Section: "db.client.operation.duration",
		OTEL:    "db.client.operation.duration",
		Unit:    "s",
		Type:    Histogram,
	})
	MessagingPublishDuration = metric(Name{
		Section: "messaging.client.operation.duration",
		OTEL:    "messaging.client.operation.duration",
		Unit:    "s",
		Type:    Histogram,
	})
	MessagingProcessDuration = metric(Name{
		Section: "messaging.process.duration",
		OTEL:    "messaging.process.duration",
		Unit:    "s",
		Type:    Histogram,
	})
	GPUCudaKernelLaunchCalls = metric(Name{
		Section: "gpu.cuda.kernel.launch.calls",
		OTEL:    "gpu.cuda.kernel.launch.calls",
		Type:    Counter,
	})
	GPUCudaGraphLaunchCalls = metric(Name{
		Section: "gpu.cuda.graph.launch.calls",
		OTEL:    "gpu.cuda.graph.launch.calls",
		Type:    Counter,
	})
	GPUCudaKernelGridSize = metric(Name{
		Section: "gpu.cuda.kernel.grid.size",
		OTEL:    "gpu.cuda.kernel.grid.size",
		Unit:    "1",
		Type:    Histogram,
	})
	GPUCudaKernelBlockSize = metric(Name{
		Section: "gpu.cuda.kernel.block.size",
		OTEL:    "gpu.cuda.kernel.block.size",
		Unit:    "1",
		Type:    Histogram,
	})
	GPUCudaMemoryAllocations = metric(Name{
		Section: "gpu.cuda.memory.allocations",
		OTEL:    "gpu.cuda.memory.allocations",
		Unit:    "By",
		Type:    Counter,
	})
	GPUCudaMemoryCopies = metric(Name{
		Section: "gpu.cuda.memory.copies",
		OTEL:    "gpu.cuda.memory.copies",
		Unit:    "By",
		Type:    Histogram,
	})
	DNSLookupDuration = metric(Name{
		Section: "dns.lookup.duration",
		OTEL:    "dns.lookup.duration",
		Unit:    "s",
		Type:    Histogram,
	})
	GenAIClientInputTokenUsage = metric(Name{
		Section: "gen_ai.client.token.usage.input",
		OTEL:    "gen_ai.client.token.usage",
		Unit:    "{token}",
		Type:    Histogram,
	})
	GenAIClientOutputTokenUsage = metric(Name{
		Section: "gen_ai.client.token.usage.output",
		OTEL:    "gen_ai.client.token.usage",
		Unit:    "{token}",
		Type:    Histogram,
	})
	GenAIClientOperationDuration = metric(Name{
		Section: "gen_ai.client.operation.duration",
		OTEL:    "gen_ai.client.operation.duration",
		Unit:    "s",
		Type:    Histogram,
	})
	GoRuntimeMemoryLimit = metric(Name{
		Section: "go.memory.limit",
		OTEL:    "go.memory.limit",
		Unit:    "By",
		Type:    UpDownCounter,
	})
	GoRuntimeMemoryGCGoal = metric(Name{
		Section: "go.memory.gc.goal",
		OTEL:    "go.memory.gc.goal",
		Unit:    "By",
		Type:    UpDownCounter,
	})
	GoRuntimeMemoryGCCycles = metric(Name{
		Section: "go.memory.gc.cycles",
		OTEL:    "go.memory.gc.cycles",
		Unit:    "{gc_cycle}",
		Type:    Counter,
	})
	GoRuntimeMemoryGCPauseDuration = metric(Name{
		Section: "go.memory.gc.pause.duration",
		OTEL:    "go.memory.gc.pause.duration",
		Unit:    "s",
		Type:    Histogram,
	})
	GoRuntimeMemoryUsed = metric(Name{
		Section: "go.memory.used",
		OTEL:    "go.memory.used",
		Unit:    "By",
		Type:    UpDownCounter,
	})
	GoRuntimeMemoryAllocated = metric(Name{
		Section: "go.memory.allocated",
		OTEL:    "go.memory.allocated",
		Unit:    "By",
		Type:    Counter,
	})
	GoRuntimeMemoryAllocations = metric(Name{
		Section: "go.memory.allocations",
		OTEL:    "go.memory.allocations",
		Unit:    "{allocation}",
		Type:    Counter,
	})
	GoRuntimeCPUTime = metric(Name{
		Section: "go.cpu.time",
		OTEL:    "go.cpu.time",
		Unit:    "s",
		Type:    Counter,
	})
	GoRuntimeGoroutineCount = metric(Name{
		Section: "go.goroutine.count",
		OTEL:    "go.goroutine.count",
		Unit:    "{goroutine}",
		Type:    UpDownCounter,
	})
	GoRuntimeProcessorLimit = metric(Name{
		Section: "go.processor.limit",
		OTEL:    "go.processor.limit",
		Unit:    "{thread}",
		Type:    UpDownCounter,
	})
	GoRuntimeConfigGOGC = metric(Name{
		Section: "go.config.gogc",
		OTEL:    "go.config.gogc",
		Unit:    "%",
		Type:    UpDownCounter,
	})
	GoRuntimeScheduleDuration = metric(Name{
		Section: "go.schedule.duration",
		OTEL:    "go.schedule.duration",
		Unit:    "s",
		Type:    Histogram,
	})
	JVMMemoryUsed = metric(Name{
		Section: "jvm.memory.used",
		OTEL:    "jvm.memory.used",
		Unit:    "By",
		Type:    UpDownCounter,
	})
	JVMMemoryCommitted = metric(Name{
		Section: "jvm.memory.committed",
		OTEL:    "jvm.memory.committed",
		Unit:    "By",
		Type:    UpDownCounter,
	})
	JVMMemoryLimit = metric(Name{
		Section: "jvm.memory.limit",
		OTEL:    "jvm.memory.limit",
		Unit:    "By",
		Type:    UpDownCounter,
	})
	JVMMemoryUsedAfterLastGC = metric(Name{
		Section: "jvm.memory.used_after_last_gc",
		OTEL:    "jvm.memory.used_after_last_gc",
		Unit:    "By",
		Type:    UpDownCounter,
	})
	// Resource is not a metric. It only names the attributes.select section that
	// selects resource attributes.
	Resource = metric(Name{
		Section: "resource",
		OTEL:    "resource",
	})
	StatTCPRtt = metric(Name{
		Section: "obi.stat.tcp.rtt",
		OTEL:    "obi.stat.tcp.rtt",
		Unit:    "s",
		Type:    Histogram,
	})
	StatTCPFailedConnections = metric(Name{
		Section: "obi.stat.tcp.failed.connections",
		OTEL:    "obi.stat.tcp.failed.connections",
		Type:    Counter,
	})
	StatTCPRetransmits = metric(Name{
		Section: "obi.stat.tcp.retransmits",
		OTEL:    "obi.stat.tcp.retransmits",
		Type:    Counter,
	})
	StatTCPIo = metric(Name{
		Section: "obi.stat.tcp.io",
		OTEL:    "obi.stat.tcp.io",
		Unit:    "By",
		Type:    Counter,
	})
)

// normalizeMetric will facilitate the user-input in the attributes.enable section.
// The user can specify the Prometheus or OTEL notation, and can include or not
// the units and aggregations for the metrics. OBI will accept all the inputs
// as long as the metric name is recorgnisable.
func normalizeMetric(name Section) Section {
	nameStr := strings.ReplaceAll(string(name), "_", ".")
	for _, suffix := range []string{".ratio", ".bucket", ".sum", ".count", ".total"} {
		if strings.HasSuffix(nameStr, suffix) {
			nameStr = nameStr[:len(nameStr)-len(suffix)]
			break
		}
	}
	for _, suffix := range []string{".bytes", ".seconds"} {
		if strings.HasSuffix(nameStr, suffix) {
			nameStr = nameStr[:len(nameStr)-len(suffix)]
			break
		}
	}
	return Section(nameStr)
}
