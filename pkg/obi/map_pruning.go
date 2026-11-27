// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi // import "go.opentelemetry.io/obi/pkg/obi"

import (
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
)

// MapPruneOptions derives deterministic map-pruning options from the global
// OBI config so generictracer, gotracer, and tpinjector apply identical rules
// to shared PinInternal maps.
func (c *Config) MapPruneOptions() ebpfcommon.MapPruneOptions {
	return c.MapPruneOptionsForContext(false)
}

// MapPruneOptionsForContext derives map-pruning options while accounting for
// vendored callers that consume spans via ContextInfo.OverrideAppExportQueue
// even when no built-in traces exporter is configured.
func (c *Config) MapPruneOptionsForContext(externalSpanExport bool) ebpfcommon.MapPruneOptions {
	if c == nil {
		return ebpfcommon.MapPruneOptions{
			ContextPropagationEnabled: true,
			HeaderPropagationEnabled:  true,
			TrackRequestHeaders:       true,
			PopulateTraceContext:      true,
			NodeJSEnabled:             true,
			NodeJSManualSpans:         true,
			JavaEnabled:               true,
			LargeBuffersEnabled:       true,
			AppRuntimeMetricsEnabled:  true,
			ExceptionsEnabled:         true,
			GoChannelLinksEnabled:     true,
			GoManualSDKEnabled:        true,
		}
	}

	buf := c.EBPF.BufferSizes
	largeBufs := buf.HTTP > 0 || buf.TCP > 0 || buf.MySQL > 0 || buf.Kafka > 0 ||
		buf.Postgres > 0 || buf.MSSQL > 0 || buf.Aerospike > 0

	tracesExported := c.Traces.Enabled() || c.TracePrinter.Enabled() || externalSpanExport
	metricsExported := c.OTELMetrics.EndpointEnabled() || c.Prometheus.EndpointEnabled()
	features := c.JoinMetricsConfig().Features
	spanOrTopologyMetrics := (features.AnySpanMetrics() || features.ServiceTopology()) && metricsExported
	noConfiguredExporters := !tracesExported && !metricsExported

	allProtocols := instrumentations.NewInstrumentationSelection([]instrumentations.Instrumentation{
		instrumentations.InstrumentationALL,
	})
	var protocols instrumentations.InstrumentationSelection
	if c.TracePrinter.Enabled() || externalSpanExport {
		protocols = allProtocols
	} else {
		if c.Traces.Enabled() {
			protocols |= instrumentations.NewInstrumentationSelection(c.Traces.Instrumentations)
		}
		if c.OTELMetrics.EndpointEnabled() {
			protocols |= instrumentations.NewInstrumentationSelection(c.OTELMetrics.Instrumentations)
		}
		if c.Prometheus.EndpointEnabled() {
			protocols |= instrumentations.NewInstrumentationSelection(c.Prometheus.Instrumentations)
		}
		// In Config v1, RED `instrumentations` does not filter span metrics or
		// service-graph metrics, which observe all non-DNS protocols.
		if !c.Attributes.UseV2Selection && spanOrTopologyMetrics {
			dnsOnly := instrumentations.NewInstrumentationSelection([]instrumentations.Instrumentation{
				instrumentations.InstrumentationDNS,
			})
			protocols |= allProtocols &^ dnsOnly
		}
	}

	return ebpfcommon.MapPruneOptions{
		ContextPropagationEnabled: c.EBPF.ContextPropagation.IsEnabled(),
		HeaderPropagationEnabled:  c.EBPF.ContextPropagation.HasHeaders(),
		TrackRequestHeaders:       c.EBPF.TrackRequestHeaders,
		PopulateTraceContext:      c.PopulateTraceContext(),
		NodeJSManualSpans:         c.NodeJS.ManualSpans,
		NodeJSEnabled:             c.NodeJS.Enabled,
		JavaEnabled:               c.Java.Enabled,
		LargeBuffersEnabled:       largeBufs,
		AppRuntimeMetricsEnabled:  c.AppRuntimeMetricsEnabled(),
		ExceptionsEnabled:         c.ExceptionsEnabled() && c.Logs.Enabled(),
		GoChannelLinksEnabled:     !c.EBPF.DisableGoChannelLinks && (tracesExported || noConfiguredExporters),
		GoManualSDKEnabled:        tracesExported || spanOrTopologyMetrics || noConfiguredExporters,
		Protocols:                 protocols,
	}
}
