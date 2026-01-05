// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

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
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		typeStr,
		defaultConfig,
		receiver.WithTraces(BuildTracesReceiver(), component.StabilityLevelAlpha))
}

func defaultConfig() component.Config {
	cfg := obi.DefaultConfig
	// This is a placeholder for the TracesConsumer, without this obi config will be invalid.
	cfg.Traces.TracesConsumer = consumertest.NewNop()
	return &cfg
}
