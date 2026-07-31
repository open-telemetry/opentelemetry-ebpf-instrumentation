// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package prom

import (
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

func TestGetProbeMetricsClosesStatsExactlyOnce(t *testing.T) {
	originalEnableStats := enableStats
	t.Cleanup(func() {
		enableStats = originalEnableStats
	})

	var closeCalls atomic.Int32
	enableStats = func(uint32) (io.Closer, error) {
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
	t.Cleanup(collector.close)
	collector.getProbeMetrics()

	require.Equal(t, int32(1), closeCalls.Load())
}

func TestEnableBPFStatsRuntimeReturnsCleanupOnError(t *testing.T) {
	originalEnableStats := enableStats
	t.Cleanup(func() {
		enableStats = originalEnableStats
	})

	enableStats = func(uint32) (io.Closer, error) {
		return nil, errors.New("enable stats")
	}

	collector := newCollector(
		&global.ContextInfo{},
		&PrometheusConfig{},
		&perapp.MetricsConfig{},
		false,
	)
	t.Cleanup(collector.close)
	cleanup := collector.enableBPFStatsRuntime()

	require.NotNil(t, cleanup)
	require.NotPanics(t, cleanup)
}

type closeFunc func() error

func (fn closeFunc) Close() error {
	return fn()
}
