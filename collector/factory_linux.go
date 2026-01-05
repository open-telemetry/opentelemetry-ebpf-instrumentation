// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"context"
	"log/slog"

	"go.uber.org/zap/exp/zapslog"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"

	"go.opentelemetry.io/obi/collector/internal"
	"go.opentelemetry.io/obi/pkg/obi"
)

func BuildTracesReceiver() receiver.CreateTracesFunc {
	return func(ctx context.Context,
		rs receiver.Settings,
		baseCfg component.Config,
		nextConsumer consumer.Traces,
	) (receiver.Traces, error) {
		slog.SetDefault(slog.New(zapslog.NewHandler(rs.Logger.Core())))

		cfg, ok := baseCfg.(*obi.Config)
		if !ok {
			return nil, errInvalidConfig
		}
		cfg.Traces.TracesConsumer = nextConsumer

		return internal.NewController(cfg)
	}
}
