// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestDocumentToRuntimeImportsExportedDocumentSections(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	cfg.ChannelBufferLen = 77

	cfg.Attributes.InstanceID.OverrideHostname = "host-override"
	cfg.Attributes.HostID.Override = "host-id-1"

	cfg.Traces.TracesEndpoint = "http://traces.example:4317"
	cfg.Traces.BatchMaxSize = 907
	cfg.Traces.QueueSize = 908
	cfg.Traces.BatchTimeout = 909 * time.Millisecond
	cfg.Traces.SamplerConfig.Name = services.SamplerTraceIDRatio
	cfg.Traces.SamplerConfig.Arg = "0.25"

	cfg.OTELMetrics.MetricsEndpoint = "https://metrics.example:4317"
	cfg.OTELMetrics.Interval = 914 * time.Millisecond
	cfg.OTELMetrics.HistogramAggregation = otelcfg.HistogramAggregationExponential

	cfg.Prometheus.Port = 917

	doc, _ := RuntimeToV2(&cfg)

	got, err := DocumentToRuntime(doc)
	require.NoError(t, err)

	require.Equal(t, 77, got.ChannelBufferLen)
	require.Equal(t, "host-override", got.Attributes.InstanceID.OverrideHostname)
	require.Equal(t, "host-id-1", got.Attributes.HostID.Override)

	require.Equal(t, "http://traces.example:4317", got.Traces.TracesEndpoint)
	require.Equal(t, otelcfg.ProtocolGRPC, got.Traces.TracesProtocol)
	require.Equal(t, 908, got.Traces.QueueSize)
	require.Equal(t, 907, got.Traces.BatchMaxSize)
	require.Equal(t, 909*time.Millisecond, got.Traces.BatchTimeout)
	require.Equal(t, services.SamplerConfig{
		Name: services.SamplerTraceIDRatio,
		Arg:  "0.25",
	}, got.Traces.SamplerConfig)

	require.Equal(t, "https://metrics.example:4317", got.OTELMetrics.MetricsEndpoint)
	require.Equal(t, otelcfg.ProtocolGRPC, got.OTELMetrics.MetricsProtocol)
	require.Equal(t, 914*time.Millisecond, got.OTELMetrics.Interval)
	require.Equal(t, otelcfg.HistogramAggregationExponential, got.OTELMetrics.HistogramAggregation)
	require.Equal(t, 917, got.Prometheus.Port)
}

func TestDocumentToRuntimePreservesDefaultsForMissingDocumentSections(t *testing.T) {
	t.Parallel()

	got, err := DocumentToRuntime(&schema.Document{
		Extensions: schema.Extensions{
			OBI: &schema.Extension{Version: schema.SupportedVersion},
		},
	})
	require.NoError(t, err)

	require.Equal(t, obi.DefaultConfig.Attributes.InstanceID.OverrideHostname, got.Attributes.InstanceID.OverrideHostname)
	require.Equal(t, obi.DefaultConfig.Attributes.HostID.Override, got.Attributes.HostID.Override)
	require.Equal(t, obi.DefaultConfig.Traces.TracesEndpoint, got.Traces.TracesEndpoint)
	require.Equal(t, obi.DefaultConfig.Traces.TracesProtocol, got.Traces.TracesProtocol)
	require.Equal(t, obi.DefaultConfig.Traces.QueueSize, got.Traces.QueueSize)
	require.Equal(t, obi.DefaultConfig.Traces.BatchMaxSize, got.Traces.BatchMaxSize)
	require.Equal(t, obi.DefaultConfig.Traces.BatchTimeout, got.Traces.BatchTimeout)
	require.Equal(t, obi.DefaultConfig.Traces.SamplerConfig, got.Traces.SamplerConfig)
	require.Equal(t, obi.DefaultConfig.OTELMetrics.MetricsEndpoint, got.OTELMetrics.MetricsEndpoint)
	require.Equal(t, obi.DefaultConfig.OTELMetrics.MetricsProtocol, got.OTELMetrics.MetricsProtocol)
	require.Equal(t, obi.DefaultConfig.OTELMetrics.GetInterval(), got.OTELMetrics.GetInterval())
	require.Equal(t, obi.DefaultConfig.OTELMetrics.HistogramAggregation, got.OTELMetrics.HistogramAggregation)
	require.Equal(t, obi.DefaultConfig.Prometheus.Port, got.Prometheus.Port)
}

func TestDocumentToRuntimeSkipsUnsupportedMetricReaderShapes(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	cfg.OTELMetrics.MetricsEndpoint = "https://metrics.example:4317"
	cfg.OTELMetrics.Interval = 914 * time.Millisecond
	cfg.Prometheus.Port = 917

	doc, _ := RuntimeToV2(&cfg)
	doc.MeterProvider.Readers = append(doc.MeterProvider.Readers, doc.MeterProvider.Readers[0])

	got, err := DocumentToRuntime(doc)
	require.NoError(t, err)

	require.Equal(t, obi.DefaultConfig.OTELMetrics.MetricsEndpoint, got.OTELMetrics.MetricsEndpoint)
	require.Equal(t, obi.DefaultConfig.OTELMetrics.MetricsProtocol, got.OTELMetrics.MetricsProtocol)
	require.Equal(t, obi.DefaultConfig.OTELMetrics.GetInterval(), got.OTELMetrics.GetInterval())
	require.Equal(t, obi.DefaultConfig.Prometheus.Port, got.Prometheus.Port)
}
