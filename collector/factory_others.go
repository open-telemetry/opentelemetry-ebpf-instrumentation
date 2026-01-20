// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package collector // import "go.opentelemetry.io/obi/collector"

import (
	"context"
	"errors"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

var errNotLinux = errors.New("OBI receiver is only supported on Linux")

func BuildTracesReceiver() receiver.CreateTracesFunc {
	return func(_ context.Context,
		_ receiver.Settings,
		_ component.Config,
		_ consumer.Traces,
	) (receiver.Traces, error) {
		return nil, errNotLinux
	}
}

func BuildMetricsReceiver() receiver.CreateMetricsFunc {
	return func(_ context.Context,
		_ receiver.Settings,
		_ component.Config,
		_ consumer.Metrics,
	) (receiver.Metrics, error) {
		return nil, errNotLinux
	}
}
