// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi // import "go.opentelemetry.io/obi/pkg/obi"

type AppNetworkConfig struct {
	// It enables app network metrics.
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_APP_NETWORK_METRICS_ENABLED" validate:"boolean"`

	// Enables the calculation of tcp srtt of a given instrumented service
	TCPRtt bool `yaml:"rtt" env:"OTEL_EBPF_APP_NETWORK_METRICS_TCP_RTT" validate:"boolean"`
}

var DefaultAppNetworkConfig = AppNetworkConfig{
	Enabled: false,
	TCPRtt:  false,
}
