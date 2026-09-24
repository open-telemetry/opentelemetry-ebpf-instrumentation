// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestCumulativeIntegerBaselineAndIncrements(t *testing.T) {
	var counter cumulativeInteger
	for _, sample := range []struct {
		increment float64
		total     uint64
	}{{900, 0}, {12, 12}, {0, 12}, {3, 15}} {
		total, err := counter.observe(runtimeCounter{Name: "alloc-rate", Increment: true, Value: sample.increment})
		require.NoError(t, err)
		require.Equal(t, sample.total, total)
	}
}

func TestCumulativeDurationBaselineAndFractionalMilliseconds(t *testing.T) {
	var counter cumulativeDuration
	for _, sample := range []struct {
		milliseconds float64
		seconds      float64
	}{{10_000, 0}, {1.25, 0.00125}, {0, 0.00125}, {2.5, 0.00375}} {
		seconds, err := counter.observe(runtimeCounter{Name: "time-in-jit", Increment: true, Value: sample.milliseconds})
		require.NoError(t, err)
		require.InDelta(t, sample.seconds, seconds, 1e-12)
	}
}

func TestCumulativeIntegerRejectsInvalidSamples(t *testing.T) {
	for _, value := range []float64{-1, 0.5, math.NaN(), math.Inf(1), math.Inf(-1), float64(math.MaxInt64)} {
		var counter cumulativeInteger
		_, err := counter.observe(runtimeCounter{Name: "alloc-rate", Increment: true, Value: value})
		require.Error(t, err)
		require.Equal(t, cumulativeInteger{}, counter, "invalid samples must not establish a baseline")
	}
	var counter cumulativeInteger
	_, err := counter.observe(runtimeCounter{Name: "alloc-rate", Value: 1})
	require.Error(t, err)
	require.Equal(t, cumulativeInteger{}, counter)

	counter = cumulativeInteger{total: math.MaxInt64 - 1, initialized: true}
	total, err := counter.observe(runtimeCounter{Name: "alloc-rate", Increment: true, Value: 1})
	require.NoError(t, err)
	require.Equal(t, uint64(math.MaxInt64), total)
	_, err = counter.observe(runtimeCounter{Name: "alloc-rate", Increment: true, Value: 1})
	require.ErrorContains(t, err, "overflow")
	require.Equal(t, uint64(math.MaxInt64), counter.total)
}

func TestCumulativeDurationRejectsInvalidSamples(t *testing.T) {
	for _, value := range []float64{-1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		var counter cumulativeDuration
		_, err := counter.observe(runtimeCounter{Name: "time-in-jit", Increment: true, Value: value})
		require.Error(t, err)
		require.Equal(t, cumulativeDuration{}, counter, "invalid samples must not establish a baseline")
	}
	var counter cumulativeDuration
	_, err := counter.observe(runtimeCounter{Name: "time-in-jit", Value: 1})
	require.Error(t, err)
	require.Equal(t, cumulativeDuration{}, counter)

	counter = cumulativeDuration{seconds: math.MaxFloat64, initialized: true}
	_, err = counter.observe(runtimeCounter{Name: "time-in-jit", Increment: true, Value: math.MaxFloat64})
	require.ErrorContains(t, err, "overflow")
	require.Equal(t, cumulativeDuration{seconds: math.MaxFloat64, initialized: true}, counter)
}

func TestCumulativeCountersIntegerSnapshots(t *testing.T) {
	var counters cumulativeCounters
	for _, tc := range []struct {
		name      string
		increment bool
		value     func(*runtimemetrics.DotnetRuntimeMetricSnapshot) *uint64
	}{
		{"alloc-rate", true, func(s *runtimemetrics.DotnetRuntimeMetricSnapshot) *uint64 { return s.GCHeapTotalAllocated }},
		{"threadpool-completed-items-count", true, func(s *runtimemetrics.DotnetRuntimeMetricSnapshot) *uint64 { return s.ThreadPoolWorkItemCount }},
		{"monitor-lock-contention-count", true, func(s *runtimemetrics.DotnetRuntimeMetricSnapshot) *uint64 { return s.MonitorLockContentions }},
		{"il-bytes-jitted", false, func(s *runtimemetrics.DotnetRuntimeMetricSnapshot) *uint64 { return s.JITCompiledILSize }},
		{"methods-jitted-count", false, func(s *runtimemetrics.DotnetRuntimeMetricSnapshot) *uint64 { return s.JITCompiledMethods }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var first, next runtimemetrics.DotnetRuntimeMetricSnapshot
			require.NoError(t, counters.observe(&first, runtimeCounter{Name: tc.name, Value: 100, Increment: tc.increment}))
			firstValue := uint64(100)
			if tc.increment {
				firstValue = 0
			}
			require.NotNil(t, tc.value(&first))
			require.Equal(t, firstValue, *tc.value(&first))
			require.NoError(t, counters.observe(&next, runtimeCounter{Name: tc.name, Value: 3, Increment: tc.increment}))
			require.NotNil(t, tc.value(&next))
			require.Equal(t, uint64(3), *tc.value(&next))
			require.Equal(t, firstValue, *tc.value(&first), "published values must not change")
		})
	}
}

func TestCumulativeCountersDurationSnapshots(t *testing.T) {
	var counters cumulativeCounters
	for _, tc := range []struct {
		name  string
		value func(*runtimemetrics.DotnetRuntimeMetricSnapshot) *float64
	}{
		{"total-pause-time-by-gc", func(s *runtimemetrics.DotnetRuntimeMetricSnapshot) *float64 { return s.GCPauseTime }},
		{"time-in-jit", func(s *runtimemetrics.DotnetRuntimeMetricSnapshot) *float64 { return s.JITCompilationTime }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var first, next runtimemetrics.DotnetRuntimeMetricSnapshot
			require.NoError(t, counters.observe(&first, runtimeCounter{Name: tc.name, Value: 100, Increment: true}))
			require.NotNil(t, tc.value(&first))
			require.Zero(t, *tc.value(&first))
			require.NoError(t, counters.observe(&next, runtimeCounter{Name: tc.name, Value: 1.25, Increment: true}))
			require.NotNil(t, tc.value(&next))
			require.InDelta(t, 0.00125, *tc.value(&next), 1e-12)
			require.Zero(t, *tc.value(&first), "published values must not change")
		})
	}
}

func TestCumulativeCountersRejectInvalidAbsoluteValues(t *testing.T) {
	for _, name := range []string{"il-bytes-jitted", "methods-jitted-count"} {
		for _, value := range []float64{-1, 0.5, math.NaN(), math.Inf(1), math.Inf(-1), float64(math.MaxInt64)} {
			var counters cumulativeCounters
			var snapshot runtimemetrics.DotnetRuntimeMetricSnapshot
			require.Error(t, counters.observe(&snapshot, runtimeCounter{Name: name, Value: value}))
			require.Equal(t, runtimemetrics.DotnetRuntimeMetricSnapshot{}, snapshot)
		}
		var counters cumulativeCounters
		var snapshot runtimemetrics.DotnetRuntimeMetricSnapshot
		require.Error(t, counters.observe(&snapshot, runtimeCounter{Name: name, Value: 1, Increment: true}))
		require.Equal(t, runtimemetrics.DotnetRuntimeMetricSnapshot{}, snapshot)
	}
}
