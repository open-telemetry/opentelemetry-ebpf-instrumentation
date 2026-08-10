// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package prom

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

func TestBPFStatsRuntimeClosesWithCollector(t *testing.T) {
	originalEnableStats := enableStats
	t.Cleanup(func() {
		enableStats = originalEnableStats
	})

	var closeCalls atomic.Int32
	var enableCalls atomic.Int32
	enableStats = func(uint32) (io.Closer, error) {
		enableCalls.Add(1)
		return closeFunc(func() error {
			closeCalls.Add(1)
			return nil
		}), nil
	}

	collector := newCollector(
		&global.ContextInfo{},
		&PrometheusConfig{},
		&perapp.MetricsConfig{},
		false,
	)
	collector.getProbeMetrics()
	collector.getProbeMetrics()

	require.Equal(t, int32(1), enableCalls.Load())
	require.Zero(t, closeCalls.Load())
	collector.close()
	require.Equal(t, int32(1), closeCalls.Load())
	collector.close()
	require.Equal(t, int32(1), closeCalls.Load())
}

func TestBPFStatsRuntimeEnableErrorDoesNotBreakCollectorClose(t *testing.T) {
	originalEnableStats := enableStats
	t.Cleanup(func() {
		enableStats = originalEnableStats
	})

	var enableCalls atomic.Int32
	enableStats = func(uint32) (io.Closer, error) {
		enableCalls.Add(1)
		return nil, errors.New("enable stats")
	}

	collector := newCollector(
		&global.ContextInfo{},
		&PrometheusConfig{},
		&perapp.MetricsConfig{},
		false,
	)
	collector.getProbeMetrics()

	require.Equal(t, int32(1), enableCalls.Load())
	require.NotPanics(t, collector.close)
}

func TestBPFStatsRuntimeClosesWhenInstanceEndsBeforeCollectorStarts(t *testing.T) {
	originalEnableStats := enableStats
	t.Cleanup(func() {
		enableStats = originalEnableStats
	})

	var enableCalls atomic.Int32
	var closeCalls atomic.Int32
	enableStats = func(uint32) (io.Closer, error) {
		enableCalls.Add(1)
		return closeFunc(func() error {
			closeCalls.Add(1)
			return nil
		}), nil
	}

	internalMetrics := imetrics.NewPrometheusReporter(
		&imetrics.InternalMetricsConfig{BpfMetricScrapeInterval: time.Hour},
		nil,
		prometheus.NewRegistry(),
	)
	ctx, cancel := context.WithCancel(t.Context())
	_, err := BPFMetrics(
		&global.ContextInfo{Metrics: internalMetrics},
		&PrometheusConfig{},
		&perapp.MetricsConfig{},
	)(ctx)
	require.NoError(t, err)
	require.Equal(t, int32(1), enableCalls.Load())

	cancel()
	require.Eventually(t, func() bool {
		return closeCalls.Load() == 1
	}, time.Second, 10*time.Millisecond)
}

type closeFunc func() error

func (fn closeFunc) Close() error {
	return fn()
}
