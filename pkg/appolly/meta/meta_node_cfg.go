// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta // import "go.opentelemetry.io/obi/pkg/appolly/meta"

import "time"

type RetryConfig struct {
	Timeout       time.Duration `yaml:"timeout" env:"OTEL_EBPF_METADATA_RETRY_TIMEOUT" validate:"gte=0"`
	StartInterval time.Duration `yaml:"start_interval" env:"OTEL_EBPF_METADATA_RETRY_START_INTERVAL" validate:"gte=0"`
	MaxInterval   time.Duration `yaml:"max_interval" env:"OTEL_EBPF_METADATA_RETRY_MAX_INTERVAL" validate:"gte=0"`
}

var DefaultRetryConfig = RetryConfig{
	Timeout:       30 * time.Second,
	StartInterval: 500 * time.Millisecond,
	MaxInterval:   5 * time.Second,
}
