// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector // import "go.opentelemetry.io/obi/collector"

import (
	"context"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

func tracesExport(consumer consumer.Traces) otelcfg.OTLPExportFunc {
	return func(ctx context.Context, data []byte) error {
		request := ptraceotlp.NewExportRequest()
		if err := request.UnmarshalProto(data); err != nil {
			return err
		}
		return consumer.ConsumeTraces(ctx, request.Traces())
	}
}

func metricsExport(consumer consumer.Metrics) otelcfg.OTLPExportFunc {
	return func(ctx context.Context, data []byte) error {
		request := pmetricotlp.NewExportRequest()
		if err := request.UnmarshalProto(data); err != nil {
			return err
		}
		return consumer.ConsumeMetrics(ctx, request.Metrics())
	}
}
