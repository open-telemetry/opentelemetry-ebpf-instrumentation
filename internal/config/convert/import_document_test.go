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

func TestDocumentToRuntimeRejectsUnsupportedDocumentFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "attribute limits",
			yaml: "attribute_limits: {}\n",
			want: "attribute_limits is not supported by the OBI runtime converter",
		},
		{
			name: "disabled",
			yaml: "disabled: true\n",
			want: "disabled is not supported by the OBI runtime converter",
		},
		{
			name: "distribution",
			yaml: "distribution:\n  vendor:\n    option: true\n",
			want: "distribution is not supported by the OBI runtime converter",
		},
		{
			name: "instrumentation development",
			yaml: "instrumentation/development: {}\n",
			want: "instrumentation/development is not supported by the OBI runtime converter",
		},
		{
			name: "logger provider",
			yaml: "logger_provider: {}\n",
			want: "logger_provider is not supported by the OBI runtime converter",
		},
		{
			name: "propagator",
			yaml: "propagator:\n  composite_list: \"\"\n",
			want: "propagator is not supported by the OBI runtime converter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc, _, err := schema.ParseStandaloneYAML([]byte(
				"file_format: \"1.0\"\n" +
					tt.yaml +
					"extensions:\n  obi:\n    version: \"2.0\"\n",
			))
			require.NoError(t, err)

			_, err = DocumentToRuntime(doc)
			require.EqualError(t, err, tt.want)
		})
	}
}

func TestDocumentToRuntimeAcceptsEmptySupportedDocumentFields(t *testing.T) {
	t.Parallel()

	doc, _, err := schema.ParseStandaloneYAML([]byte(`
file_format: "1.0"
disabled: false
distribution: {}
propagator: {}
extensions:
  obi:
    version: "2.0"
`))
	require.NoError(t, err)

	_, err = DocumentToRuntime(doc)
	require.NoError(t, err)
}

func TestDocumentToRuntimeRejectsUnsupportedMetricReaderShapes(t *testing.T) {
	t.Parallel()

	cfg := defaultRuntimeConfig()
	cfg.OTELMetrics.MetricsEndpoint = "https://metrics.example:4317"
	cfg.OTELMetrics.Interval = 914 * time.Millisecond
	cfg.Prometheus.Port = 917

	doc, _ := RuntimeToV2(&cfg)
	doc.MeterProvider.Readers = append(doc.MeterProvider.Readers, doc.MeterProvider.Readers[0])

	_, err := DocumentToRuntime(doc)
	require.ErrorContains(t, err, "meter_provider.readers")
}

func TestDocumentToRuntimeRejectsUnsupportedTracerProviderShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		field  string
		mutate func(*otelconfx.TracerProvider)
	}{
		{
			name:  "span limits",
			field: "tracer_provider.limits",
			mutate: func(provider *otelconfx.TracerProvider) {
				limit := 12
				provider.Limits = &otelconfx.SpanLimits{
					AttributeCountLimit: &limit,
				}
			},
		},
		{
			name:  "tracer configurator",
			field: "tracer_provider.tracer_configurator/development",
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

			_, err := DocumentToRuntime(doc)
			require.ErrorContains(t, err, tt.field)
		})
	}
}

func TestDocumentToRuntimeRejectsUnsupportedMeterProviderShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		field  string
		mutate func(*otelconfx.MeterProvider)
	}{
		{
			name:  "exemplar filter",
			field: "meter_provider.exemplar_filter",
			mutate: func(provider *otelconfx.MeterProvider) {
				filter := otelconfx.ExemplarFilterAlwaysOn
				provider.ExemplarFilter = &filter
			},
		},
		{
			name:  "meter configurator",
			field: "meter_provider.meter_configurator/development",
			mutate: func(provider *otelconfx.MeterProvider) {
				provider.MeterConfiguratorDevelopment = &otelconfx.ExperimentalMeterConfigurator{}
			},
		},
		{
			name:  "views",
			field: "meter_provider.views",
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

			_, err := DocumentToRuntime(doc)
			require.ErrorContains(t, err, tt.field)
		})
	}
}

func TestDocumentToRuntimeRejectsUnsupportedTraceOTLPGrpcTLS(t *testing.T) {
	t.Parallel()

	for _, tt := range unsupportedTLSFields() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := documentWithRuntimeTelemetry()
			tt.mutate(doc.TracerProvider.Processors[0].Batch.Exporter.OTLPGrpc.Tls)

			_, err := DocumentToRuntime(doc)
			require.ErrorContains(t, err, ".tls."+tt.field)
		})
	}
}

func TestDocumentToRuntimeRejectsUnsupportedMetricOTLPGrpcTLS(t *testing.T) {
	t.Parallel()

	for _, tt := range unsupportedTLSFields() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			doc := documentWithRuntimeTelemetry()
			tt.mutate(doc.MeterProvider.Readers[0].Periodic.Exporter.OTLPGrpc.Tls)

			_, err := DocumentToRuntime(doc)
			require.ErrorContains(t, err, ".tls."+tt.field)
		})
	}
}

func TestDocumentToRuntimeImportsOTLPHTTPExporters(t *testing.T) {
	t.Parallel()

	doc := documentWithRuntimeTelemetry()
	traceEndpoint := "https://traces.example/v1/traces"
	traceEncoding := otelconfx.OTLPHttpEncodingJson
	traceHeadersList := "from-list=trace%20list,override=old"
	traceOverride := "trace-direct"
	doc.TracerProvider.Processors[0].Batch.Exporter = otelconfx.SpanExporter{
		OTLPHttp: &otelconfx.OTLPHttpExporter{
			Endpoint:    &traceEndpoint,
			Encoding:    &traceEncoding,
			HeadersList: &traceHeadersList,
			Headers: []otelconfx.NameStringValuePair{
				{Name: "override", Value: &traceOverride},
			},
		},
	}

	metricEndpoint := "https://metrics.example/v1/metrics"
	metricEncoding := otelconfx.OTLPHttpEncodingProtobuf
	metricHeadersList := "from-list=metric-list,override=old"
	metricOverride := "metric-direct"
	doc.MeterProvider.Readers[0].Periodic.Exporter = otelconfx.PushMetricExporter{
		OTLPHttp: &otelconfx.OTLPHttpMetricExporter{
			Endpoint:    &metricEndpoint,
			Encoding:    &metricEncoding,
			HeadersList: &metricHeadersList,
			Headers: []otelconfx.NameStringValuePair{
				{Name: "override", Value: &metricOverride},
			},
		},
	}

	got, err := DocumentToRuntime(doc)
	require.NoError(t, err)

	require.Equal(t, traceEndpoint, got.Traces.TracesEndpoint)
	require.Equal(t, otelcfg.ProtocolHTTPJSON, got.Traces.TracesProtocol)
	traceHeaders := map[string]string{}
	require.NotNil(t, got.Traces.InjectHeaders)
	got.Traces.InjectHeaders(traceHeaders)
	require.Equal(t, map[string]string{
		"from-list": "trace list",
		"override":  "trace-direct",
	}, traceHeaders)

	require.Equal(t, metricEndpoint, got.OTELMetrics.MetricsEndpoint)
	require.Equal(t, otelcfg.ProtocolHTTPProtobuf, got.OTELMetrics.MetricsProtocol)
	metricHeaders := map[string]string{}
	require.NotNil(t, got.OTELMetrics.InjectHeaders)
	got.OTELMetrics.InjectHeaders(metricHeaders)
	require.Equal(t, map[string]string{
		"from-list": "metric-list",
		"override":  "metric-direct",
	}, metricHeaders)
}

func TestDocumentToRuntimeRejectsInvalidOTLPHeadersList(t *testing.T) {
	t.Parallel()

	doc := documentWithRuntimeTelemetry()
	headersList := "invalid header=value"
	doc.TracerProvider.Processors[0].Batch.Exporter.OTLPGrpc.HeadersList = &headersList

	_, err := DocumentToRuntime(doc)
	require.ErrorContains(t, err, "tracer_provider.processors[0].batch.exporter.otlp_grpc.headers_list")
}

func TestDocumentToRuntimeImportsDeclarativeExporterDefaults(t *testing.T) {
	t.Parallel()

	doc := documentWithRuntimeTelemetry()
	doc.TracerProvider.Processors[0].Batch.Exporter.OTLPGrpc.Endpoint = nil
	doc.MeterProvider.Readers[0].Periodic.Exporter.OTLPGrpc.Endpoint = nil
	doc.MeterProvider.Readers[0].Periodic.Interval = nil
	doc.MeterProvider.Readers[1].Pull.Exporter.PrometheusDevelopment.Port = nil

	got, err := DocumentToRuntime(doc)
	require.NoError(t, err)

	require.Equal(t, defaultOTLPGRPCEndpoint, got.Traces.TracesEndpoint)
	require.Equal(t, defaultOTLPGRPCEndpoint, got.OTELMetrics.MetricsEndpoint)
	require.Equal(t, defaultMetricExportInterval, got.OTELMetrics.Interval)
	require.Equal(t, defaultPrometheusPort, got.Prometheus.Port)
}

func TestDocumentToRuntimeImportsGRPCTransportSecurity(t *testing.T) {
	t.Parallel()

	doc := documentWithRuntimeTelemetry()
	traceEndpoint := "traces.example:4317"
	metricEndpoint := "metrics.example:4317"
	insecure := true
	secure := false
	doc.TracerProvider.Processors[0].Batch.Exporter.OTLPGrpc.Endpoint = &traceEndpoint
	doc.TracerProvider.Processors[0].Batch.Exporter.OTLPGrpc.Tls.Insecure = &insecure
	doc.MeterProvider.Readers[0].Periodic.Exporter.OTLPGrpc.Endpoint = &metricEndpoint
	doc.MeterProvider.Readers[0].Periodic.Exporter.OTLPGrpc.Tls.Insecure = &secure

	got, err := DocumentToRuntime(doc)
	require.NoError(t, err)

	require.Equal(t, "http://traces.example:4317", got.Traces.TracesEndpoint)
	require.Equal(t, "https://metrics.example:4317", got.OTELMetrics.MetricsEndpoint)
}

func TestDocumentToRuntimeImportsSupportedResourceAttributes(t *testing.T) {
	t.Parallel()

	doc := documentWithRuntimeTelemetry()
	attributesList := "host.name=list-host,host.id=list-id,service.name=list-service,service.namespace=shop"
	doc.Resource.AttributesList = &attributesList
	doc.Resource.Attributes = []otelconfx.AttributeNameValue{
		{Name: "host.name", Value: "direct-host"},
		{Name: "service.name", Value: "checkout"},
	}

	got, err := DocumentToRuntime(doc)
	require.NoError(t, err)

	require.Equal(t, "direct-host", got.Attributes.InstanceID.OverrideHostname)
	require.Equal(t, "list-id", got.Attributes.HostID.Override)
	require.Equal(t, "checkout", got.ServiceName)
	require.Equal(t, "shop", got.ServiceNamespace)
}

func TestDocumentToRuntimeRejectsUnsupportedResourceAttribute(t *testing.T) {
	t.Parallel()

	doc := documentWithRuntimeTelemetry()
	doc.Resource.Attributes = []otelconfx.AttributeNameValue{
		{Name: "service.version", Value: "1.2.3"},
	}

	_, err := DocumentToRuntime(doc)
	require.ErrorContains(t, err, `resource attribute "service.version"`)
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
	field  string
	mutate func(*otelconfx.GrpcTls)
} {
	return []struct {
		name   string
		field  string
		mutate func(*otelconfx.GrpcTls)
	}{
		{
			name:  "CA file",
			field: "ca_file",
			mutate: func(tls *otelconfx.GrpcTls) {
				caFile := "/tmp/ca.pem"
				tls.CaFile = &caFile
			},
		},
		{
			name:  "cert file",
			field: "cert_file",
			mutate: func(tls *otelconfx.GrpcTls) {
				certFile := "/tmp/cert.pem"
				tls.CertFile = &certFile
			},
		},
		{
			name:  "key file",
			field: "key_file",
			mutate: func(tls *otelconfx.GrpcTls) {
				keyFile := "/tmp/key.pem"
				tls.KeyFile = &keyFile
			},
		},
	}
}
