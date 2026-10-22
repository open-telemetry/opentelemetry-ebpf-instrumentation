// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector // import "go.opentelemetry.io/obi/collector"

import (
	"context"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

func tracesExport(consumer consumer.Traces) otelcfg.TracesExportFunc {
	return func(ctx context.Context, traces ptrace.Traces) error {
		return consumer.ConsumeTraces(ctx, traces)
	}
}

func metricsExport(consumer consumer.Metrics) otelcfg.MetricsExportFunc {
	return func(ctx context.Context, metrics pmetric.Metrics) error {
		return consumer.ConsumeMetrics(ctx, metrics)
	}
}
