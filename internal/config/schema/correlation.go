// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

// Correlation describes standalone telemetry correlation settings.
type Correlation struct {
	LogTraceAnnotation LogTraceAnnotation `yaml:"log_trace_annotation"`
}

// LogTraceAnnotation describes log trace annotation settings.
type LogTraceAnnotation struct {
	Enabled     bool        `yaml:"enabled"`
	Cache       Cache       `yaml:"cache"`
	AsyncWriter AsyncWriter `yaml:"async_writer"`
}

// AsyncWriter describes asynchronous writer worker and channel settings.
type AsyncWriter struct {
	Workers    int `yaml:"workers"`
	ChannelLen int `yaml:"channel_len"`
}
