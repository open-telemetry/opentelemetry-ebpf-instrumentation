// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi // import "go.opentelemetry.io/obi/pkg/obi"

type AppNetworkConfig struct {
	// TODO pino: if this is true it enables all metrics, otherwise it will enable only the true metrics
	// Enable app network metrics.
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_APP_NETWORK_METRICS" validate:"boolean"`

	// Enables the calculation of srtt of a given instrumented service
	Rtt bool `yaml:"rtt" env:"OTEL_EBPF_APP_NETWORK_METRICS_RTT" validate:"boolean"`
	// Print the app network metrics in the Standard Output, if true
	Print bool `yaml:"print_flows" env:"OTEL_EBPF_APP_NETWORK_METRICS_PRINT" validate:"boolean"`
}

var DefaultAppNetworkConfig = AppNetworkConfig{
	Enabled: false,
	Rtt:     false,
	Print:   false,
}
