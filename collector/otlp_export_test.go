// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
)

func TestTracesExport(t *testing.T) {
	traces := ptrace.NewTraces()
	traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty().SetName("test-span")
	data, err := ptraceotlp.NewExportRequestFromTraces(traces).MarshalProto()
	require.NoError(t, err)

	sink := &consumertest.TracesSink{}
	require.NoError(t, tracesExport(sink)(t.Context(), data))
	require.Equal(t, "test-span", sink.AllTraces()[0].ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Name())
}

func TestMetricsExport(t *testing.T) {
	metrics := pmetric.NewMetrics()
	metrics.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty().Metrics().AppendEmpty().SetName("test-metric")
	data, err := pmetricotlp.NewExportRequestFromMetrics(metrics).MarshalProto()
	require.NoError(t, err)

	sink := &consumertest.MetricsSink{}
	require.NoError(t, metricsExport(sink)(t.Context(), data))
	require.Equal(t, "test-metric", sink.AllMetrics()[0].ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0).Name())
}
