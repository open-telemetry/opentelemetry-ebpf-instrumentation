// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"context"
	"errors"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

func BuildTracesReceiver(options ...Option) receiver.CreateTracesFunc {
	return func(_ context.Context,
		_ receiver.Settings,
		_ component.Config,
		_ consumer.Traces,
	) (xreceiver.Profiles, error) {
		return nil, errors.New("OBI receiver is only supported on Linux")

	}
}
