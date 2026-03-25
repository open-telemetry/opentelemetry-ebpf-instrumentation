// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package collector // import "go.opentelemetry.io/obi/collector"

import (
	"errors"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/receiver"
)

var (
	typeStr = component.MustNewType("obi")

	errInvalidConfig = errors.New("invalid config")

	// errUnsupportedPlatform is returned by the receiver factory on platforms where OBI
	// is not supported (non-Linux or non-amd64/arm64).
	errUnsupportedPlatform = errors.New("OBI receiver is only supported on Linux amd64/arm64")
)

// NewFactory creates a factory for the receiver.
// The receiver supports both traces and metrics pipelines.
// When both are configured, a single OBI instance handles both.
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		typeStr,
		defaultConfig,
		receiver.WithTraces(BuildTracesReceiver(), component.StabilityLevelAlpha),
		receiver.WithMetrics(BuildMetricsReceiver(), component.StabilityLevelAlpha),
	)
}
