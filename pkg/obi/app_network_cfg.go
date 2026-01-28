// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi // import "go.opentelemetry.io/obi/pkg/obi"

type AppNetworkConfig struct {
	// It enables app network metrics.
	Enabled bool `yaml:"enable" env:"OTEL_EBPF_APP_NETWORK_METRICS" validate:"boolean"`

	// Enables the calculation of srtt of a given instrumented service
	Rtt bool `yaml:"rtt" env:"OTEL_EBPF_APP_NETWORK_METRICS_RTT" validate:"boolean"`
}

var DefaultAppNetworkConfig = AppNetworkConfig{
	Enabled: false,
	Rtt:     false,
}
