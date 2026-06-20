// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package imetrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var m dto.Metric
	require.NoError(t, c.Write(&m))
	return m.GetCounter().GetValue()
}

func TestPrometheusReporterBPFRingbufWriteStats(t *testing.T) {
	reg := prometheus.NewRegistry()
	reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, reg)

	reporter.BPFRingbufWriteStats(10, 2)
	assert.InDelta(t, 10, counterValue(t, reporter.bpfRingbufWriteCount), 0)
	assert.InDelta(t, 2, counterValue(t, reporter.bpfRingbufWriteFailures), 0)

	// The BPF counters are absolute running totals, so the reporter must record
	// only the delta since the previous scrape, not the absolute value again.
	reporter.BPFRingbufWriteStats(15, 5)
	assert.InDelta(t, 15, counterValue(t, reporter.bpfRingbufWriteCount), 0)
	assert.InDelta(t, 5, counterValue(t, reporter.bpfRingbufWriteFailures), 0)
}
