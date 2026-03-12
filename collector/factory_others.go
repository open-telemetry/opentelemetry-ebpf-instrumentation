// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux && (amd64 || arm64))

package collector // import "go.opentelemetry.io/obi/collector"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

// unsupportedConfig is a no-op config used on non-supported platforms.
type unsupportedConfig struct{}

func (u *unsupportedConfig) Validate() error { return nil }

func defaultConfig() component.Config {
	return &unsupportedConfig{}
}

func BuildTracesReceiver() receiver.CreateTracesFunc {
	return func(_ context.Context,
		_ receiver.Settings,
		_ component.Config,
		_ consumer.Traces,
	) (receiver.Traces, error) {
		return nil, errUnsupportedPlatform
	}
}

func BuildMetricsReceiver() receiver.CreateMetricsFunc {
	return func(_ context.Context,
		_ receiver.Settings,
		_ component.Config,
		_ consumer.Metrics,
	) (receiver.Metrics, error) {
		return nil, errUnsupportedPlatform
	}
}
