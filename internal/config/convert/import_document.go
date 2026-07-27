// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	otelconfx "go.opentelemetry.io/contrib/otelconf/x"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/obi"
)

// DocumentToRuntime converts a standalone v2 document into an OBI runtime
// configuration. It imports the OBI extension plus the document-level
// OpenTelemetry sections emitted by RuntimeToV2.
func DocumentToRuntime(src *schema.Document) (*obi.Config, error) {
	if src == nil {
		return nil, errors.New("missing OBI document")
	}
	if fields := src.OpenTelemetryExtensionFields(); len(fields) != 0 {
		return nil, fmt.Errorf(
			"OpenTelemetry extension fields are not supported: %s",
			strings.Join(fields, ", "),
		)
	}

	cfg, err := V2ToRuntime(src.Extensions.OBI)
	if err != nil {
		return nil, err
	}

	applyV2Resource(cfg, src.Resource)
	applyV2TracerProvider(cfg, src.TracerProvider)
	applyV2MeterProvider(cfg, src.MeterProvider)
	if err := applyV2LogLevel(cfg, src); err != nil {
		return nil, err
	}

	return cfg, nil
}

func applyV2LogLevel(cfg *obi.Config, src *schema.Document) error {
	if !src.HasLogLevel() || src.LogLevel == nil {
		return nil
	}

	level, err := logLevelFromSeverityNumber(*src.LogLevel)
	if err != nil {
		return err
	}
	cfg.LogLevel = level
	return nil
}

func logLevelFromSeverityNumber(severity otelconfx.SeverityNumber) (obi.LogLevel, error) {
	switch strings.ToLower(string(severity)) {
	case "trace", "trace2", "trace3", "trace4",
		"debug", "debug2", "debug3", "debug4":
		return obi.LogLevelDebug, nil
	case "info", "info2", "info3", "info4":
		return obi.LogLevelInfo, nil
	case "warn", "warn2", "warn3", "warn4":
		return obi.LogLevelWarn, nil
	case "error", "error2", "error3", "error4",
		"fatal", "fatal2", "fatal3", "fatal4":
		return obi.LogLevelError, nil
	default:
		return "", fmt.Errorf("unsupported log_level %q", severity)
	}
}

func applyV2Resource(cfg *obi.Config, resource *otelconfx.Resource) {
	if resource == nil || !exportedResource(resource) {
		return
	}

	for _, attr := range resource.Attributes {
		value, ok := stringResourceAttribute(attr)
		if !ok {
			continue
		}

		switch attr.Name {
		case "host.name":
			cfg.Attributes.InstanceID.OverrideHostname = value
		case "host.id":
			cfg.Attributes.HostID.Override = value
		}
	}
}

func exportedResource(resource *otelconfx.Resource) bool {
	return resource.AttributesList == nil &&
		resource.DetectionDevelopment == nil &&
		resource.SchemaUrl == nil
}

func stringResourceAttribute(attr otelconfx.AttributeNameValue) (string, bool) {
	if attr.Type != nil && *attr.Type != otelconfx.AttributeTypeString {
		return "", false
	}

	value, ok := attr.Value.(string)
	return value, ok
}

func applyV2TracerProvider(cfg *obi.Config, provider *otelconfx.TracerProvider) {
	if provider == nil || !exportedTracerProvider(provider) {
		return
	}

	if sampler, ok := samplerConfigFromV2(provider.Sampler); ok {
		cfg.Traces.SamplerConfig = sampler
	}

	batch, ok := exportedBatchSpanProcessor(provider)
	if !ok {
		return
	}

	if batch.MaxQueueSize != nil {
		cfg.Traces.QueueSize = *batch.MaxQueueSize
	}
	if batch.MaxExportBatchSize != nil {
		cfg.Traces.BatchMaxSize = *batch.MaxExportBatchSize
	}
	if batch.ScheduleDelay != nil {
		cfg.Traces.BatchTimeout = time.Duration(*batch.ScheduleDelay) * time.Millisecond
	}
	if batch.Exporter.OTLPGrpc.Endpoint != nil {
		cfg.Traces.TracesEndpoint = *batch.Exporter.OTLPGrpc.Endpoint
	}
	cfg.Traces.TracesProtocol = otelcfg.ProtocolGRPC
}

func exportedTracerProvider(provider *otelconfx.TracerProvider) bool {
	return provider.Limits == nil &&
		provider.TracerConfiguratorDevelopment == nil
}

func exportedBatchSpanProcessor(provider *otelconfx.TracerProvider) (*otelconfx.BatchSpanProcessor, bool) {
	if len(provider.Processors) != 1 {
		return nil, false
	}

	processor := provider.Processors[0]
	if processor.Batch == nil || processor.Simple != nil {
		return nil, false
	}

	exporter := processor.Batch.Exporter
	if processor.Batch.ExportTimeout != nil ||
		exporter.OTLPGrpc == nil ||
		exporter.OTLPHttp != nil ||
		exporter.OTLPFileDevelopment != nil ||
		!zeroValue(exporter.Console) ||
		exporter.AdditionalProperties != nil ||
		!exportedOTLPGrpcExporter(exporter.OTLPGrpc) {
		return nil, false
	}

	return processor.Batch, true
}

func exportedOTLPGrpcExporter(exporter *otelconfx.OTLPGrpcExporter) bool {
	return exporter.Compression == nil &&
		exporter.Headers == nil &&
		exporter.HeadersList == nil &&
		exporter.Timeout == nil &&
		exportedGrpcTLS(exporter.Tls)
}

func samplerConfigFromV2(sampler *otelconfx.Sampler) (services.SamplerConfig, bool) {
	if sampler == nil {
		return services.SamplerConfig{}, false
	}
	if sampler.CompositeDevelopment != nil ||
		sampler.JaegerRemoteDevelopment != nil ||
		sampler.ProbabilityDevelopment != nil ||
		sampler.AdditionalProperties != nil {
		return services.SamplerConfig{}, false
	}

	alwaysOff := !zeroValue(sampler.AlwaysOff)
	alwaysOn := !zeroValue(sampler.AlwaysOn)
	traceIDRatio := sampler.TraceIDRatioBased != nil
	parentBased := sampler.ParentBased != nil
	if countTrue(alwaysOff, alwaysOn, traceIDRatio, parentBased) != 1 {
		return services.SamplerConfig{}, false
	}

	switch {
	case alwaysOn:
		return services.SamplerConfig{Name: services.SamplerAlwaysOn}, true
	case alwaysOff:
		return services.SamplerConfig{Name: services.SamplerAlwaysOff}, true
	case traceIDRatio:
		return traceIDRatioSamplerConfig(sampler.TraceIDRatioBased, services.SamplerTraceIDRatio)
	default:
		return parentBasedSamplerConfig(sampler.ParentBased)
	}
}

func parentBasedSamplerConfig(sampler *otelconfx.ParentBasedSampler) (services.SamplerConfig, bool) {
	if sampler.Root == nil ||
		sampler.LocalParentSampled != nil ||
		sampler.LocalParentNotSampled != nil ||
		sampler.RemoteParentSampled != nil ||
		sampler.RemoteParentNotSampled != nil {
		return services.SamplerConfig{}, false
	}

	root, ok := samplerConfigFromV2(sampler.Root)
	if !ok {
		return services.SamplerConfig{}, false
	}

	switch root.Name {
	case services.SamplerAlwaysOn:
		return services.SamplerConfig{Name: services.SamplerParentBasedAlwaysOn}, true
	case services.SamplerAlwaysOff:
		return services.SamplerConfig{Name: services.SamplerParentBasedAlwaysOff}, true
	case services.SamplerTraceIDRatio:
		return services.SamplerConfig{
			Name: services.SamplerParentBasedTraceIDRatio,
			Arg:  root.Arg,
		}, true
	default:
		return services.SamplerConfig{}, false
	}
}

func traceIDRatioSamplerConfig(
	sampler *otelconfx.TraceIDRatioBasedSampler,
	name services.SamplerName,
) (services.SamplerConfig, bool) {
	if sampler == nil || sampler.Ratio == nil {
		return services.SamplerConfig{}, false
	}

	return services.SamplerConfig{
		Name: name,
		Arg:  strconv.FormatFloat(*sampler.Ratio, 'f', -1, 64),
	}, true
}

func applyV2MeterProvider(cfg *obi.Config, provider *otelconfx.MeterProvider) {
	if provider == nil || !exportedMeterProvider(provider) {
		return
	}

	periodic, pull, ok := exportedMetricReaders(provider.Readers)
	if !ok {
		return
	}

	if periodic != nil {
		applyV2PeriodicMetricReader(cfg, periodic)
	}
	if pull != nil {
		applyV2PullMetricReader(cfg, pull)
	}
}

func exportedMeterProvider(provider *otelconfx.MeterProvider) bool {
	return provider.ExemplarFilter == nil &&
		provider.MeterConfiguratorDevelopment == nil &&
		len(provider.Views) == 0
}

func exportedMetricReaders(
	readers []otelconfx.MetricReader,
) (*otelconfx.PeriodicMetricReader, *otelconfx.PullMetricReader, bool) {
	if len(readers) > 2 {
		return nil, nil, false
	}

	var periodic *otelconfx.PeriodicMetricReader
	var pull *otelconfx.PullMetricReader
	for _, reader := range readers {
		switch {
		case reader.Periodic != nil && reader.Pull == nil:
			if periodic != nil || !exportedPeriodicMetricReader(reader.Periodic) {
				return nil, nil, false
			}
			periodic = reader.Periodic
		case reader.Pull != nil && reader.Periodic == nil:
			if pull != nil || !exportedPullMetricReader(reader.Pull) {
				return nil, nil, false
			}
			pull = reader.Pull
		default:
			return nil, nil, false
		}
	}

	return periodic, pull, true
}

func exportedPeriodicMetricReader(reader *otelconfx.PeriodicMetricReader) bool {
	exporter := reader.Exporter
	return reader.CardinalityLimits == nil &&
		reader.Producers == nil &&
		reader.Timeout == nil &&
		exporter.OTLPGrpc != nil &&
		exporter.OTLPHttp == nil &&
		exporter.OTLPFileDevelopment == nil &&
		exporter.Console == nil &&
		exporter.AdditionalProperties == nil &&
		exportedOTLPGrpcMetricExporter(exporter.OTLPGrpc)
}

func exportedOTLPGrpcMetricExporter(exporter *otelconfx.OTLPGrpcMetricExporter) bool {
	return exporter.Compression == nil &&
		exporter.Headers == nil &&
		exporter.HeadersList == nil &&
		exporter.TemporalityPreference == nil &&
		exporter.Timeout == nil &&
		exportedGrpcTLS(exporter.Tls)
}

func exportedPullMetricReader(reader *otelconfx.PullMetricReader) bool {
	exporter := reader.Exporter
	return reader.CardinalityLimits == nil &&
		reader.Producers == nil &&
		exporter.PrometheusDevelopment != nil &&
		exporter.AdditionalProperties == nil &&
		exportedPrometheusDevelopmentExporter(exporter.PrometheusDevelopment)
}

func exportedPrometheusDevelopmentExporter(exporter *otelconfx.ExperimentalPrometheusMetricExporter) bool {
	return exporter.Host == nil &&
		exporter.TranslationStrategy == nil &&
		exporter.WithResourceConstantLabels == nil &&
		exporter.WithoutScopeInfo == nil &&
		exporter.WithoutTargetInfo == nil
}

func applyV2PeriodicMetricReader(cfg *obi.Config, reader *otelconfx.PeriodicMetricReader) {
	if reader.Interval != nil {
		cfg.OTELMetrics.Interval = time.Duration(*reader.Interval) * time.Millisecond
	}

	exporter := reader.Exporter.OTLPGrpc
	if exporter.Endpoint != nil {
		cfg.OTELMetrics.MetricsEndpoint = *exporter.Endpoint
	}
	if exporter.DefaultHistogramAggregation != nil {
		cfg.OTELMetrics.HistogramAggregation = otelcfg.HistogramAggregation(*exporter.DefaultHistogramAggregation)
	}
	cfg.OTELMetrics.MetricsProtocol = otelcfg.ProtocolGRPC
}

func applyV2PullMetricReader(cfg *obi.Config, reader *otelconfx.PullMetricReader) {
	exporter := reader.Exporter.PrometheusDevelopment
	if exporter.Port != nil {
		cfg.Prometheus.Port = *exporter.Port
	}
}

func exportedGrpcTLS(tls *otelconfx.GrpcTls) bool {
	if tls == nil {
		return true
	}

	return tls.CaFile == nil &&
		tls.CertFile == nil &&
		tls.KeyFile == nil
}

func countTrue(values ...bool) int {
	var count int
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}
