// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestObservePollingCounterWorkingSet(t *testing.T) {
	var snapshot runtimemetrics.DotnetRuntimeMetricSnapshot
	err := observePollingCounter(&snapshot, runtimeCounter{Name: "working-set", Value: 12.5})
	require.NoError(t, err)
	require.NotNil(t, snapshot.ProcessMemoryWorkingSet)
	require.Equal(t, int64(12_500_000), *snapshot.ProcessMemoryWorkingSet)
}

func TestObservePollingCounterCommittedMemory(t *testing.T) {
	var snapshot runtimemetrics.DotnetRuntimeMetricSnapshot
	err := observePollingCounter(&snapshot, runtimeCounter{Name: "gc-committed", Value: 2.5})
	require.NoError(t, err)
	require.NotNil(t, snapshot.GCCommittedMemory)
	require.Equal(t, int64(2_500_000), *snapshot.GCCommittedMemory)
	require.Nil(t, snapshot.ProcessMemoryWorkingSet)
}

func TestObservePollingCounterRejectsFractionalCounts(t *testing.T) {
	for _, name := range []string{
		"threadpool-thread-count", "threadpool-queue-length", "active-timer-count", "assembly-count",
	} {
		t.Run(name, func(t *testing.T) {
			var snapshot runtimemetrics.DotnetRuntimeMetricSnapshot
			err := observePollingCounter(&snapshot, runtimeCounter{Name: name, Value: 1.5})
			require.Error(t, err)
			require.Equal(t, runtimemetrics.DotnetRuntimeMetricSnapshot{}, snapshot)
		})
	}
}

func TestObservePollingCounterCounts(t *testing.T) {
	var snapshot runtimemetrics.DotnetRuntimeMetricSnapshot
	for name, field := range map[string]**int64{
		"threadpool-thread-count": &snapshot.ThreadPoolThreadCount,
		"threadpool-queue-length": &snapshot.ThreadPoolQueueLength,
		"active-timer-count":      &snapshot.TimerCount,
		"assembly-count":          &snapshot.AssemblyCount,
	} {
		t.Run(name, func(t *testing.T) {
			require.Nil(t, *field)
			for _, value := range []int64{3, 1, 0} {
				err := observePollingCounter(&snapshot, runtimeCounter{Name: name, Value: float64(value)})
				require.NoError(t, err)
				require.NotNil(t, *field)
				require.Equal(t, value, **field)
			}
		})
	}
}

func TestObserveHeapSizeCounters(t *testing.T) {
	for generation, name := range []string{"gen-0-size", "gen-1-size", "gen-2-size", "loh-size", "poh-size"} {
		t.Run(name, func(t *testing.T) {
			var snapshot runtimemetrics.DotnetRuntimeMetricSnapshot
			for _, value := range []float64{123456, 64, 0} {
				counter, err := decodeRuntimeCounter(map[string]any{"": map[string]any{"Payload": map[string]any{
					"Name": name, "CounterType": "Mean", "IntervalSec": float32(1), "Mean": value,
				}}})
				require.NoError(t, err)
				require.NoError(t, observePollingCounter(&snapshot, counter))
				require.Equal(t, int64(value), *snapshot.GCHeapSize[generation])
				for other, size := range snapshot.GCHeapSize {
					if other != generation {
						require.Nil(t, size)
					}
				}
			}
			for _, counter := range []runtimeCounter{
				{Name: name, Value: -1},
				{Name: name, Value: 0.5},
				{Name: name, Value: math.NaN()},
				{Name: name, Value: math.Inf(1)},
				{Name: name, Value: float64(math.MaxInt64)},
				{Name: name, Value: 1, Increment: true},
			} {
				require.Error(t, observePollingCounter(&snapshot, counter))
				require.Zero(t, *snapshot.GCHeapSize[generation], "invalid input must preserve the last value")
			}
		})
	}
}
