// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
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
