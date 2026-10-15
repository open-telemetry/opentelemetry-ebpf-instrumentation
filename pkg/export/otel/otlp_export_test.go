// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"

	"go.opentelemetry.io/collector/pdata/pmetric"

	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

func testOTLPMetricsExport(consume func(context.Context, pmetric.Metrics) error) otelcfg.MetricsExportFunc {
	return consume
}
