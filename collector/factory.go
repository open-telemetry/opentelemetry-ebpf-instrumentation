// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package collector // import "go.opentelemetry.io/obi/collector"

import (
	"errors"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver"

	"go.opentelemetry.io/obi/pkg/obi"
)

var (
	typeStr = component.MustNewType("obi")

	errInvalidConfig = errors.New("invalid config")
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

func defaultConfig() component.Config {
	cfg := obi.DefaultConfig
	// These are placeholders for the consumers, without these obi config will be invalid.
	// The actual consumers are set when the receiver is created.
	cfg.Traces.TracesConsumer = consumertest.NewNop()
	cfg.OTELMetrics.MetricsConsumer = consumertest.NewNop()
	return &cfg
}
