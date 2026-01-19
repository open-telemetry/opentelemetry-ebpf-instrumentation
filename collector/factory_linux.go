// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package collector // import "go.opentelemetry.io/obi/collector"

import (
	"context"
	"log/slog"
	"sync"

	"go.uber.org/zap/exp/zapslog"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"

	"go.opentelemetry.io/obi/collector/internal"
	"go.opentelemetry.io/obi/pkg/obi"
)

var loggerOnce sync.Once

func initLogger(rs receiver.Settings) {
	loggerOnce.Do(func() {
		slog.SetDefault(slog.New(zapslog.NewHandler(rs.Logger.Core())))
	})
}

func BuildTracesReceiver() receiver.CreateTracesFunc {
	return func(_ context.Context,
		rs receiver.Settings,
		baseCfg component.Config,
		nextConsumer consumer.Traces,
	) (receiver.Traces, error) {
		initLogger(rs)

		cfg, ok := baseCfg.(*obi.Config)
		if !ok {
			return nil, errInvalidConfig
		}
		cfg.Traces.TracesConsumer = nextConsumer

		return internal.NewController(rs.ID, cfg)
	}
}

func BuildMetricsReceiver() receiver.CreateMetricsFunc {
	return func(_ context.Context,
		rs receiver.Settings,
		baseCfg component.Config,
		nextConsumer consumer.Metrics,
	) (receiver.Metrics, error) {
		initLogger(rs)

		cfg, ok := baseCfg.(*obi.Config)
		if !ok {
			return nil, errInvalidConfig
		}
		cfg.OTELMetrics.MetricsConsumer = nextConsumer

		return internal.NewController(rs.ID, cfg)
	}
}
