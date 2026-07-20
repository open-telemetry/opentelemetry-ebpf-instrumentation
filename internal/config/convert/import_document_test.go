// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	otelconfx "go.opentelemetry.io/contrib/otelconf/x"

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

	cfg.LogLevel = obi.LogLevelDebug

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
	require.Equal(t, obi.LogLevelDebug, got.LogLevel)

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

func TestDocumentToRuntimeImportsTopLevelLogLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		level string
		want  obi.LogLevel
	}{
		{name: "trace", level: "trace4", want: obi.LogLevelDebug},
		{name: "debug", level: "debug", want: obi.LogLevelDebug},
		{name: "info", level: "info", want: obi.LogLevelInfo},
		{name: "warn", level: "warn3", want: obi.LogLevelWarn},
		{name: "error", level: "error2", want: obi.LogLevelError},
		{name: "fatal", level: "fatal", want: obi.LogLevelError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc, _, err := schema.ParseStandaloneYAML([]byte(`
file_format: "1.0"
log_level: ` + tt.level + `
extensions:
  obi:
    version: "2.0"
    daemon:
      logging:
        format: json
`))
			require.NoError(t, err)

			got, err := DocumentToRuntime(doc)
			require.NoError(t, err)

			require.Equal(t, tt.want, got.LogLevel)
			require.Equal(t, obi.LogFormatJSON, got.LogFormat)
		})
	}
}

func TestDocumentToRuntimeUsesDefaultLogLevelWhenTopLevelLogLevelOmitted(t *testing.T) {
	t.Parallel()

	doc, _, err := schema.ParseStandaloneYAML([]byte(`
file_format: "1.0"
extensions:
  obi:
    version: "2.0"
    daemon:
      logging:
        format: json
`))
	require.NoError(t, err)
	require.False(t, doc.HasLogLevel())
	require.NotNil(t, doc.LogLevel)

	got, err := DocumentToRuntime(doc)
	require.NoError(t, err)

	require.Equal(t, obi.DefaultConfig.LogLevel, got.LogLevel)
	require.Equal(t, obi.LogFormatJSON, got.LogFormat)
}

func TestDocumentToRuntimeRejectsUnsupportedTopLevelLogLevel(t *testing.T) {
	t.Parallel()

	doc, _, err := schema.ParseStandaloneYAML([]byte(`
file_format: "1.0"
log_level: verbose
extensions:
  obi:
    version: "2.0"
`))
	require.NoError(t, err)

	_, err = DocumentToRuntime(doc)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported log_level")
	require.Contains(t, err.Error(), "verbose")
}

func TestDocumentToRuntimeRejectsOpenTelemetryExtensionFields(t *testing.T) {
	t.Parallel()

	doc, _, err := schema.ParseStandaloneYAML([]byte(`
file_format: "1.0"
tracer_provider:
  sampler:
    vendor_sampler: {}
extensions:
  obi:
    version: "2.0"
`))
	require.NoError(t, err)

	_, err = DocumentToRuntime(doc)
	require.ErrorContains(
		t,
		err,
		"OpenTelemetry extension fields are not supported: tracer_provider.sampler.vendor_sampler",
	)
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

func TestDocumentToRuntimeSkipsUnsupportedTracerProviderShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*otelconfx.TracerProvider)
	}{
		{
			name: "span limits",
			mutate: func(provider *otelconfx.TracerProvider) {
				limit := 12
				provider.Limits = &otelconfx.SpanLimits{
					AttributeCountLimit: &limit,
				}
			},
		},
		{
			name: "tracer configurator",
			mutate: func(provider *otelconfx.TracerProvider) {
				provider.TracerConfiguratorDevelopment = &otelconfx.ExperimentalTracerConfigurator{}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := documentWithRuntimeTelemetry()
			tt.mutate(doc.TracerProvider)

			got, err := DocumentToRuntime(doc)
			require.NoError(t, err)

			requireDefaultTraceProvider(t, got)
		})
	}
}

func TestDocumentToRuntimeSkipsUnsupportedMeterProviderShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*otelconfx.MeterProvider)
	}{
		{
			name: "exemplar filter",
			mutate: func(provider *otelconfx.MeterProvider) {
				filter := otelconfx.ExemplarFilterAlwaysOn
				provider.ExemplarFilter = &filter
			},
		},
		{
			name: "meter configurator",
			mutate: func(provider *otelconfx.MeterProvider) {
				provider.MeterConfiguratorDevelopment = &otelconfx.ExperimentalMeterConfigurator{}
			},
		},
		{
			name: "views",
			mutate: func(provider *otelconfx.MeterProvider) {
				provider.Views = []otelconfx.View{{}}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := documentWithRuntimeTelemetry()
			tt.mutate(doc.MeterProvider)

			got, err := DocumentToRuntime(doc)
			require.NoError(t, err)

			requireDefaultMeterProvider(t, got)
		})
	}
}

func TestDocumentToRuntimeSkipsUnsupportedTraceOTLPGrpcTLS(t *testing.T) {
	t.Parallel()

	for _, tt := range unsupportedTLSFields() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := documentWithRuntimeTelemetry()
			tt.mutate(doc.TracerProvider.Processors[0].Batch.Exporter.OTLPGrpc.Tls)

			got, err := DocumentToRuntime(doc)
			require.NoError(t, err)

			requireDefaultTraceExporter(t, got)
		})
	}
}

func TestDocumentToRuntimeSkipsUnsupportedMetricOTLPGrpcTLS(t *testing.T) {
	t.Parallel()

	for _, tt := range unsupportedTLSFields() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := documentWithRuntimeTelemetry()
			tt.mutate(doc.MeterProvider.Readers[0].Periodic.Exporter.OTLPGrpc.Tls)

			got, err := DocumentToRuntime(doc)
			require.NoError(t, err)

			requireDefaultMeterProvider(t, got)
		})
	}
}

func documentWithRuntimeTelemetry() *schema.Document {
	cfg := defaultRuntimeConfig()
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
	return doc
}

func unsupportedTLSFields() []struct {
	name   string
	mutate func(*otelconfx.GrpcTls)
} {
	return []struct {
		name   string
		mutate func(*otelconfx.GrpcTls)
	}{
		{
			name: "CA file",
			mutate: func(tls *otelconfx.GrpcTls) {
				caFile := "/tmp/ca.pem"
				tls.CaFile = &caFile
			},
		},
		{
			name: "cert file",
			mutate: func(tls *otelconfx.GrpcTls) {
				certFile := "/tmp/cert.pem"
				tls.CertFile = &certFile
			},
		},
		{
			name: "key file",
			mutate: func(tls *otelconfx.GrpcTls) {
				keyFile := "/tmp/key.pem"
				tls.KeyFile = &keyFile
			},
		},
	}
}

func requireDefaultTraceProvider(t *testing.T, got *obi.Config) {
	t.Helper()

	requireDefaultTraceExporter(t, got)
	require.Equal(t, obi.DefaultConfig.Traces.SamplerConfig, got.Traces.SamplerConfig)
}

func requireDefaultTraceExporter(t *testing.T, got *obi.Config) {
	t.Helper()

	require.Equal(t, obi.DefaultConfig.Traces.TracesEndpoint, got.Traces.TracesEndpoint)
	require.Equal(t, obi.DefaultConfig.Traces.TracesProtocol, got.Traces.TracesProtocol)
	require.Equal(t, obi.DefaultConfig.Traces.QueueSize, got.Traces.QueueSize)
	require.Equal(t, obi.DefaultConfig.Traces.BatchMaxSize, got.Traces.BatchMaxSize)
	require.Equal(t, obi.DefaultConfig.Traces.BatchTimeout, got.Traces.BatchTimeout)
}

func requireDefaultMeterProvider(t *testing.T, got *obi.Config) {
	t.Helper()

	require.Equal(t, obi.DefaultConfig.OTELMetrics.MetricsEndpoint, got.OTELMetrics.MetricsEndpoint)
	require.Equal(t, obi.DefaultConfig.OTELMetrics.MetricsProtocol, got.OTELMetrics.MetricsProtocol)
	require.Equal(t, obi.DefaultConfig.OTELMetrics.GetInterval(), got.OTELMetrics.GetInterval())
	require.Equal(t, obi.DefaultConfig.OTELMetrics.HistogramAggregation, got.OTELMetrics.HistogramAggregation)
	require.Equal(t, obi.DefaultConfig.Prometheus.Port, got.Prometheus.Port)
}
