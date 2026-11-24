// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
)

func TestMapPruneOptionsNilConfig(t *testing.T) {
	var cfg *Config
	opts := cfg.MapPruneOptions()
	assert.True(t, opts.ContextPropagationEnabled)
	assert.True(t, opts.HeaderPropagationEnabled)
	assert.True(t, opts.TrackRequestHeaders)
	assert.True(t, opts.PopulateTraceContext)
	assert.True(t, opts.NodeJSEnabled)
	assert.True(t, opts.NodeJSManualSpans)
	assert.True(t, opts.JavaEnabled)
	assert.True(t, opts.LargeBuffersEnabled)
	assert.True(t, opts.AppRuntimeMetricsEnabled)
	assert.True(t, opts.ExceptionsEnabled)
	assert.True(t, opts.GoChannelLinksEnabled)
	assert.True(t, opts.GoManualSDKEnabled)
	assert.Zero(t, opts.Protocols)
}

func TestMapPruneOptionsMetricsOnlyDefaults(t *testing.T) {
	cfg := DefaultConfig
	cfg.Prometheus.Port = 9090

	opts := cfg.MapPruneOptions()
	assert.False(t, opts.ContextPropagationEnabled)
	assert.False(t, opts.HeaderPropagationEnabled)
	assert.False(t, opts.TrackRequestHeaders)
	assert.False(t, opts.PopulateTraceContext)
	assert.True(t, opts.NodeJSEnabled)
	assert.False(t, opts.NodeJSManualSpans)
	assert.True(t, opts.JavaEnabled)
	assert.False(t, opts.LargeBuffersEnabled)
	assert.False(t, opts.AppRuntimeMetricsEnabled)
	assert.False(t, opts.ExceptionsEnabled)
	assert.False(t, opts.GoChannelLinksEnabled)
	assert.False(t, opts.GoManualSDKEnabled)
	assert.True(t, opts.Protocols.Enabled(instrumentations.InstrumentationALL))
}

func TestMapPruneOptionsZeroExporterPreservesGoSDKAndProtocols(t *testing.T) {
	cfg := DefaultConfig

	opts := cfg.MapPruneOptions()
	assert.True(t, opts.GoChannelLinksEnabled)
	assert.True(t, opts.GoManualSDKEnabled)
	assert.Zero(t, opts.Protocols)

	cfg.EBPF.DisableGoChannelLinks = true
	assert.False(t, cfg.MapPruneOptions().GoChannelLinksEnabled)
}

func TestMapPruneOptionsTracesSpanAndTopologyMetrics(t *testing.T) {
	t.Run("traces exporter enables channel links and manual SDK", func(t *testing.T) {
		cfg := DefaultConfig
		cfg.Traces.CommonEndpoint = "http://localhost:4318"
		opts := cfg.MapPruneOptions()
		assert.True(t, opts.GoChannelLinksEnabled)
		assert.True(t, opts.GoManualSDKEnabled)
	})

	t.Run("span metrics enable manual SDK without channel links", func(t *testing.T) {
		cfg := DefaultConfig
		cfg.Prometheus.Port = 9090
		cfg.Metrics.Features = export.FeatureApplicationRED | export.FeatureSpanOTel
		opts := cfg.MapPruneOptions()
		assert.False(t, opts.GoChannelLinksEnabled)
		assert.True(t, opts.GoManualSDKEnabled)
	})

	t.Run("service graph and connection info enable manual SDK without channel links", func(t *testing.T) {
		for _, feature := range []export.Features{export.FeatureGraph, export.FeatureConnectionInfo} {
			cfg := DefaultConfig
			cfg.Prometheus.Port = 9090
			cfg.Metrics.Features = export.FeatureApplicationRED | feature
			opts := cfg.MapPruneOptions()
			assert.False(t, opts.GoChannelLinksEnabled)
			assert.True(t, opts.GoManualSDKEnabled)
		}
	})

	t.Run("trace printer forces all protocols", func(t *testing.T) {
		cfg := DefaultConfig
		cfg.Prometheus.Port = 9090
		cfg.Prometheus.Instrumentations = []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP}
		cfg.TracePrinter = debug.TracePrinterText
		opts := cfg.MapPruneOptions()
		assert.True(t, opts.GoChannelLinksEnabled)
		assert.True(t, opts.GoManualSDKEnabled)
		assert.True(t, opts.Protocols.Enabled(instrumentations.InstrumentationALL))
	})

	t.Run("vendored OverrideAppExportQueue with metrics exporter forces all protocols and Go SDK", func(t *testing.T) {
		cfg := DefaultConfig
		cfg.Prometheus.Port = 9090
		cfg.Prometheus.Instrumentations = []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP}
		opts := cfg.MapPruneOptionsForContext(true)
		assert.True(t, opts.GoChannelLinksEnabled)
		assert.True(t, opts.GoManualSDKEnabled)
		assert.True(t, opts.Protocols.Enabled(instrumentations.InstrumentationALL))
	})
}

func TestMapPruneOptionsConfigV1VsV2SpanMetricsProtocolPruning(t *testing.T) {
	t.Run("config v1 preserves non-DNS protocols when span or service graph metrics enabled", func(t *testing.T) {
		cfg := DefaultConfig
		cfg.Prometheus.Port = 9090
		cfg.Prometheus.Instrumentations = []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP}
		cfg.Metrics.Features = export.FeatureApplicationRED | export.FeatureSpanOTel

		opts := cfg.MapPruneOptions()
		assert.True(t, opts.Protocols.HTTPEnabled())
		assert.True(t, opts.Protocols.GRPCEnabled())
		assert.True(t, opts.Protocols.SQLEnabled())
		assert.True(t, opts.Protocols.KafkaEnabled())
		assert.False(t, opts.Protocols.DNSEnabled(), "span/service-graph metrics skip DNS")
	})

	t.Run("config v2 retains restricted protocol pruning with span metrics", func(t *testing.T) {
		cfg := DefaultConfig
		cfg.Attributes.UseV2Selection = true
		cfg.Prometheus.Port = 9090
		cfg.Prometheus.Instrumentations = []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP}
		cfg.Metrics.Features = export.FeatureApplicationRED | export.FeatureSpanOTel

		opts := cfg.MapPruneOptions()
		assert.True(t, opts.Protocols.HTTPEnabled())
		assert.False(t, opts.Protocols.GRPCEnabled())
		assert.False(t, opts.Protocols.SQLEnabled())
		assert.False(t, opts.Protocols.KafkaEnabled())
		assert.False(t, opts.Protocols.DNSEnabled())
	})
}

func TestMapPruneOptionsProtocolUnionAndFeatures(t *testing.T) {
	cfg := DefaultConfig
	cfg.Prometheus.Port = 9090
	cfg.Prometheus.Instrumentations = []instrumentations.Instrumentation{instrumentations.InstrumentationHTTP}
	cfg.Traces.CommonEndpoint = "http://localhost:4318"
	cfg.Traces.Instrumentations = []instrumentations.Instrumentation{instrumentations.InstrumentationGRPC}
	cfg.EBPF.ContextPropagation = config.ContextPropagationTCP
	cfg.EBPF.BufferSizes.HTTP = 4096
	cfg.Exceptions.Enabled = true

	opts := cfg.MapPruneOptions()
	assert.True(t, opts.ContextPropagationEnabled)
	assert.False(t, opts.HeaderPropagationEnabled)
	assert.True(t, opts.LargeBuffersEnabled)
	assert.False(t, opts.ExceptionsEnabled, "exceptions require logs exporter")
	assert.True(t, opts.Protocols.HTTPEnabled())
	assert.True(t, opts.Protocols.GRPCEnabled())
	assert.False(t, opts.Protocols.SQLEnabled())
	assert.False(t, opts.Protocols.KafkaEnabled())

	cfg.Logs.Endpoint = "http://localhost:4318"
	assert.True(t, cfg.MapPruneOptions().ExceptionsEnabled)
}
