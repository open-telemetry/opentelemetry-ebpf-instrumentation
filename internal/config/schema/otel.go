// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

// Resource describes OpenTelemetry resource attributes exported with the
// document.
type Resource struct {
	Attributes map[string]any `yaml:"attributes,omitempty"`
}

// TracerProvider describes the declarative OpenTelemetry tracer provider
// emitted by the converter.
type TracerProvider struct {
	Processors []TraceProcessor `yaml:"processors"`
	Sampler    *Sampler         `yaml:"sampler,omitempty"`
}

// TraceProcessor describes one trace processor entry.
type TraceProcessor struct {
	Batch TraceBatchProcessor `yaml:"batch"`
}

// TraceBatchProcessor describes an OpenTelemetry batch span processor.
type TraceBatchProcessor struct {
	MaxQueueSize       int                `yaml:"max_queue_size"`
	MaxExportBatchSize int                `yaml:"max_export_batch_size"`
	ScheduleDelay      Milliseconds       `yaml:"schedule_delay"`
	Exporter           TraceBatchExporter `yaml:"exporter"`
}

// TraceBatchExporter describes the exporter used by a trace batch processor.
type TraceBatchExporter struct {
	OTLPGRPC OTLPGRPCExporter `yaml:"otlp_grpc"`
}

// OTLPGRPCExporter describes an OTLP/gRPC exporter.
type OTLPGRPCExporter struct {
	Endpoint                    string                       `yaml:"endpoint"`
	DefaultHistogramAggregation otelcfg.HistogramAggregation `yaml:"default_histogram_aggregation,omitempty"`
	Retry                       *Retry                       `yaml:"retry,omitempty"`
	TLS                         TLS                          `yaml:"tls"`
}

// UnmarshalYAML parses and validates OTLP/gRPC exporter settings.
func (e *OTLPGRPCExporter) UnmarshalYAML(value *yaml.Node) error {
	type exporter OTLPGRPCExporter
	var out exporter
	if err := value.Decode(&out); err != nil {
		return err
	}
	switch out.DefaultHistogramAggregation {
	case "", otelcfg.HistogramAggregationExplicit, otelcfg.HistogramAggregationExponential:
	default:
		return fmt.Errorf("invalid default_histogram_aggregation %q", out.DefaultHistogramAggregation)
	}
	*e = OTLPGRPCExporter(out)
	return nil
}

// Retry describes exporter retry backoff settings.
type Retry struct {
	InitialInterval Duration `yaml:"initial_interval"`
	MaxInterval     Duration `yaml:"max_interval"`
	MaxElapsedTime  Duration `yaml:"max_elapsed_time"`
}

// TLS describes exporter TLS settings.
type TLS struct {
	Insecure           bool `yaml:"insecure"`
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

// Sampler describes the OpenTelemetry sampler emitted by the converter.
type Sampler struct {
	Name services.SamplerName `yaml:"name,omitempty"`
	Arg  string               `yaml:"arg,omitempty"`
}

// MeterProvider describes the declarative OpenTelemetry meter provider emitted
// by the converter.
type MeterProvider struct {
	Readers []MeterReader `yaml:"readers"`
}

// MeterReader describes one meter reader entry.
type MeterReader struct {
	Periodic *PeriodicReader `yaml:"periodic,omitempty"`
	Pull     *PullReader     `yaml:"pull,omitempty"`
}

// PeriodicReader describes a periodic metric reader.
type PeriodicReader struct {
	Interval Milliseconds   `yaml:"interval"`
	Exporter MetricExporter `yaml:"exporter"`
}

// MetricExporter describes an exporter used by a metric reader.
type MetricExporter struct {
	OTLPGRPC OTLPGRPCExporter `yaml:"otlp_grpc"`
}

// PullReader describes a pull-based metric reader.
type PullReader struct {
	Exporter PullExporter `yaml:"exporter"`
}

// PullExporter describes a pull metric exporter.
type PullExporter struct {
	Prometheus PrometheusDevelopmentExporter `yaml:"prometheus/development"`
}

// PrometheusDevelopmentExporter describes a Prometheus pull exporter.
type PrometheusDevelopmentExporter struct {
	Port int `yaml:"port"`
}
