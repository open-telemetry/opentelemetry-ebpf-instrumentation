// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"

	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"

	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

func testOTLPMetricsExport(consume func(context.Context, pmetric.Metrics) error) otelcfg.OTLPExportFunc {
	return func(ctx context.Context, data []byte) error {
		request := pmetricotlp.NewExportRequest()
		if err := request.UnmarshalProto(data); err != nil {
			return err
		}
		return consume(ctx, request.Metrics())
	}
}
