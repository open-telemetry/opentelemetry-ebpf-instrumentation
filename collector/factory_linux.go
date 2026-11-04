// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector // import "go.opentelemetry.io/obi/collector"

import (
	"context"
	"log/slog"
	"sync"

	"go.uber.org/zap/exp/zapslog"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pipeline"
	"go.opentelemetry.io/collector/receiver"

	"go.opentelemetry.io/obi/collector/internal"
	"go.opentelemetry.io/obi/pkg/kube/klogbridge"
	"go.opentelemetry.io/obi/pkg/obi"
)

var loggerOnce sync.Once

func initLogger(rs receiver.Settings) {
	loggerOnce.Do(func() {
		slog.SetDefault(slog.New(zapslog.NewHandler(rs.Logger.Core())))
		klogbridge.Install()
	})
}

func BuildTracesReceiver() receiver.CreateTracesFunc {
	return func(_ context.Context,
		rs receiver.Settings,
		baseCfg component.Config,
		nextConsumer consumer.Traces,
	) (receiver.Traces, error) {
		initLogger(rs)

		cfg, ok := runtimeConfig(baseCfg)
		if !ok {
			return nil, errInvalidConfig
		}
		cfg.Traces.TracesExport = tracesExport(nextConsumer)

		v2 := false
		if receiverCfg, ok := baseCfg.(*receiverConfig); ok {
			v2 = receiverCfg.v2
		}
		return internal.NewController(rs.ID, cfg, v2, pipeline.SignalTraces)
	}
}

func BuildMetricsReceiver() receiver.CreateMetricsFunc {
	return func(_ context.Context,
		rs receiver.Settings,
		baseCfg component.Config,
		nextConsumer consumer.Metrics,
	) (receiver.Metrics, error) {
		initLogger(rs)

		cfg, ok := runtimeConfig(baseCfg)
		if !ok {
			return nil, errInvalidConfig
		}
		cfg.OTELMetrics.MetricsExport = metricsExport(nextConsumer)

		v2 := false
		if receiverCfg, ok := baseCfg.(*receiverConfig); ok {
			v2 = receiverCfg.v2
		}
		return internal.NewController(rs.ID, cfg, v2, pipeline.SignalMetrics)
	}
}

func BuildLogsReceiver() receiver.CreateLogsFunc {
	return func(_ context.Context,
		rs receiver.Settings,
		baseCfg component.Config,
		nextConsumer consumer.Logs,
	) (receiver.Logs, error) {
		initLogger(rs)

		cfg, ok := runtimeConfig(baseCfg)
		if !ok {
			return nil, errInvalidConfig
		}
		cfg.Logs.LogsExport = logsExport(nextConsumer)

		v2 := false
		if receiverCfg, ok := baseCfg.(*receiverConfig); ok {
			v2 = receiverCfg.v2
		}
		return internal.NewController(rs.ID, cfg, v2, pipeline.SignalLogs)
	}
}

func defaultConfig() component.Config {
	return &receiverConfig{runtime: defaultRuntimeConfig()}
}

func runtimeConfig(baseCfg component.Config) (*obi.Config, bool) {
	var cfg *obi.Config
	switch value := baseCfg.(type) {
	case *receiverConfig:
		if value != nil {
			cfg = value.runtime
		}
	case *obi.Config:
		cfg = value
	}
	if cfg == nil {
		return nil, false
	}
	// Each receiver binds its consumer on a copy of the validated config.
	runtime := *cfg
	return &runtime, true
}
