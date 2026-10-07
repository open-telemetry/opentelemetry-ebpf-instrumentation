// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestRuntimeCollectionProcessorCount(t *testing.T) {
	var collection runtimeCollection
	observe := func(counter runtimeCounter) *runtimemetrics.DotnetRuntimeMetricSnapshot {
		snapshot, err := collection.observe(counter)
		require.NoError(t, err)
		return snapshot
	}
	completeCycle := func() {
		for _, name := range []string{"gen-0-gc-count", "gen-1-gc-count", "gen-2-gc-count", "time-in-jit"} {
			require.Nil(t, observe(runtimeCounter{Name: name, Increment: true}))
		}
	}
	require.Nil(t, observe(runtimeCounter{Name: "processor-count", Value: 2}))
	require.Nil(t, observe(runtimeCounter{Name: "working-set", Value: 1}))
	completeCycle()
	first := observe(runtimeCounter{Name: "working-set", Value: 1})
	require.NotNil(t, first)
	require.NotNil(t, first.ProcessCPUCount)
	require.Equal(t, int64(2), *first.ProcessCPUCount)

	completeCycle()
	second := observe(runtimeCounter{Name: "working-set", Value: 1})
	require.NotNil(t, second)
	require.NotNil(t, second.ProcessCPUCount)
	require.Equal(t, int64(2), *second.ProcessCPUCount)

	require.Nil(t, observe(runtimeCounter{Name: "processor-count", Value: 4}))
	completeCycle()
	last := collection.finish()
	require.NotNil(t, last)
	require.NotNil(t, last.ProcessCPUCount)
	require.Equal(t, int64(4), *last.ProcessCPUCount)
	require.Equal(t, int64(2), *first.ProcessCPUCount)
	require.Equal(t, int64(2), *second.ProcessCPUCount)

	collection = runtimeCollection{}
	require.Nil(t, observe(runtimeCounter{Name: "working-set", Value: 1}))
	completeCycle()
	fresh := collection.finish()
	require.NotNil(t, fresh)
	require.Nil(t, fresh.ProcessCPUCount, "a fresh session must observe its own processor count")
}

func TestRuntimeCollectionIgnoresPartialStart(t *testing.T) {
	var collection runtimeCollection
	for _, counter := range []runtimeCounter{
		{Name: "gen-2-gc-count", Value: 100, Increment: true},
		{Name: "assembly-count", Value: 10},
	} {
		snapshot, err := collection.observe(counter)
		require.NoError(t, err)
		require.Nil(t, snapshot)
	}
	require.Equal(t, runtimeCollection{}, collection)
}

func TestRuntimeCollectionFinish(t *testing.T) {
	for _, tc := range []struct {
		name        string
		generations []string
		assembly    bool
		jitTime     bool
		complete    bool
	}{
		{"complete", []string{"gen-0-gc-count", "gen-1-gc-count", "gen-2-gc-count"}, true, true, true},
		{"missing assembly", []string{"gen-0-gc-count", "gen-1-gc-count", "gen-2-gc-count"}, false, true, true},
		{"missing final counter", []string{"gen-0-gc-count", "gen-1-gc-count", "gen-2-gc-count"}, true, false, false},
		{"incomplete GC", []string{"gen-0-gc-count", "gen-1-gc-count"}, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var collection runtimeCollection
			pending, err := collection.observe(runtimeCounter{Name: "working-set", Value: 12.5})
			require.NoError(t, err)
			require.Nil(t, pending)
			for _, name := range tc.generations {
				pending, err = collection.observe(runtimeCounter{Name: name, Increment: true})
				require.NoError(t, err)
				require.Nil(t, pending)
			}
			if tc.assembly {
				pending, err = collection.observe(runtimeCounter{Name: "assembly-count", Value: 10})
				require.NoError(t, err)
				require.Nil(t, pending)
			}
			if tc.jitTime {
				pending, err = collection.observe(runtimeCounter{Name: "time-in-jit", Value: 2.5, Increment: true})
				require.NoError(t, err)
				require.Nil(t, pending)
			}
			snapshot := collection.finish()
			if !tc.complete {
				require.Nil(t, snapshot)
				return
			}
			require.NotNil(t, snapshot)
			require.NotNil(t, snapshot.ProcessMemoryWorkingSet)
			require.Equal(t, int64(12_500_000), *snapshot.ProcessMemoryWorkingSet)
			if tc.assembly {
				require.NotNil(t, snapshot.AssemblyCount)
				require.Equal(t, int64(10), *snapshot.AssemblyCount)
			} else {
				require.Nil(t, snapshot.AssemblyCount)
			}
			require.NotNil(t, snapshot.JITCompilationTime)
			require.Zero(t, *snapshot.JITCompilationTime)
			require.Nil(t, snapshot.TimerCount)
			require.Nil(t, snapshot.ThreadPoolQueueLength)
			require.Nil(t, collection.finish(), "a final collection must only publish once")
		})
	}
}

func TestRuntimeCollectionBoundary(t *testing.T) {
	var collection runtimeCollection
	for _, counter := range []runtimeCounter{
		{Name: "working-set", Value: 12.5},
		{Name: "gen-0-gc-count", Increment: true},
		{Name: "gen-1-gc-count", Increment: true},
		{Name: "gen-2-gc-count", Increment: true},
		{Name: "assembly-count", Value: 10},
	} {
		snapshot, err := collection.observe(counter)
		require.NoError(t, err)
		require.Nil(t, snapshot)
	}
	snapshot, err := collection.observe(runtimeCounter{Name: "working-set", Value: 20})
	require.NoError(t, err)
	require.NotNil(t, snapshot)
	require.NotNil(t, snapshot.ProcessMemoryWorkingSet)
	require.Equal(t, int64(12_500_000), *snapshot.ProcessMemoryWorkingSet)
	require.NotNil(t, snapshot.AssemblyCount)
	require.Equal(t, int64(10), *snapshot.AssemblyCount)
	require.Nil(t, snapshot.TimerCount)
	for _, name := range []string{"gen-0-gc-count", "gen-1-gc-count", "gen-2-gc-count"} {
		pending, err := collection.observe(runtimeCounter{Name: name, Value: 1, Increment: true})
		require.NoError(t, err)
		require.Nil(t, pending)
	}
	next, err := collection.observe(runtimeCounter{Name: "working-set", Value: 5})
	require.NoError(t, err)
	require.NotNil(t, next)
	require.NotNil(t, next.ProcessMemoryWorkingSet)
	require.Equal(t, int64(20_000_000), *next.ProcessMemoryWorkingSet)
	require.Nil(t, next.AssemblyCount)
	require.NotNil(t, next.GCCollections[2])
	require.Equal(t, uint64(1), *next.GCCollections[2])
	require.Equal(t, int64(12_500_000), *snapshot.ProcessMemoryWorkingSet)
	require.Equal(t, int64(10), *snapshot.AssemblyCount)
	require.NotNil(t, snapshot.GCCollections[2])
	require.Zero(t, *snapshot.GCCollections[2])
}

func TestRuntimeCollectionCumulativeMissingIntervals(t *testing.T) {
	var collection runtimeCollection
	observe := func(counter runtimeCounter) *runtimemetrics.DotnetRuntimeMetricSnapshot {
		snapshot, err := collection.observe(counter)
		require.NoError(t, err)
		return snapshot
	}
	beginCycle := func() *runtimemetrics.DotnetRuntimeMetricSnapshot {
		completed := observe(runtimeCounter{Name: "working-set", Value: 1})
		for _, name := range []string{"gen-0-gc-count", "gen-1-gc-count", "gen-2-gc-count"} {
			require.Nil(t, observe(runtimeCounter{Name: name, Increment: true}))
		}
		return completed
	}
	require.Nil(t, beginCycle())
	require.Nil(t, observe(runtimeCounter{Name: "alloc-rate", Value: 100, Increment: true}))
	require.Nil(t, observe(runtimeCounter{Name: "total-pause-time-by-gc", Value: 100, Increment: true}))
	require.Nil(t, observe(runtimeCounter{Name: "il-bytes-jitted", Value: 100}))
	first := beginCycle()
	require.NotNil(t, first)
	require.NotNil(t, first.GCHeapTotalAllocated)
	require.NotNil(t, first.GCPauseTime)
	require.NotNil(t, first.JITCompiledILSize)
	require.Zero(t, *first.GCHeapTotalAllocated)
	require.Zero(t, *first.GCPauseTime)
	require.Equal(t, uint64(100), *first.JITCompiledILSize)

	missing := beginCycle()
	require.NotNil(t, missing)
	require.Nil(t, missing.GCHeapTotalAllocated)
	require.Nil(t, missing.GCPauseTime)
	require.Nil(t, missing.JITCompiledILSize)

	require.Nil(t, observe(runtimeCounter{Name: "alloc-rate", Value: 5, Increment: true}))
	require.Nil(t, observe(runtimeCounter{Name: "total-pause-time-by-gc", Value: 1.25, Increment: true}))
	require.Nil(t, observe(runtimeCounter{Name: "il-bytes-jitted", Value: 101}))
	resumed := beginCycle()
	require.NotNil(t, resumed)
	require.NotNil(t, resumed.GCHeapTotalAllocated)
	require.NotNil(t, resumed.GCPauseTime)
	require.NotNil(t, resumed.JITCompiledILSize)
	require.Equal(t, uint64(5), *resumed.GCHeapTotalAllocated)
	require.InDelta(t, 0.00125, *resumed.GCPauseTime, 1e-12)
	require.Equal(t, uint64(101), *resumed.JITCompiledILSize)
	require.Zero(t, *first.GCHeapTotalAllocated)
	require.Zero(t, *first.GCPauseTime)
}
