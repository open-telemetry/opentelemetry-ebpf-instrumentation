// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package decfg is a placeholder for the future global and per-service support
// of the OpenTelemetry Declarative configuration format.
// https://github.com/open-telemetry/opentelemetry-configuration/tree/main/schema
package decfg

import "go.opentelemetry.io/obi/pkg/export"

// MeterProvider is a placeholder for the progressive support of global and per-service
// definition of the meter_provider section of the OpenTelemetry configuration format:
// https://github.com/open-telemetry/opentelemetry-configuration/blob/main/schema/meter_provider.yaml
// Due to the nature of OBI, it might contain some fields that are exclusive to OBI. They are prefixed with "obi_"
type MeterProvider struct {
	// Features of metrics that can be exported. Accepted values: application, network, application_process,
	// application_span, application_service_graph, ...
	// envDefault is provided to avoid breaking changes
	Features export.Features `yaml:"obi_features" env:"OTEL_EBPF_METRICS_FEATURES,expand" envDefault:"${OTEL_EBPF_METRIC_FEATURES}" envSeparator:","`
}
