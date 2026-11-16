// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestRuntimeCollectionExceptionSnapshots(t *testing.T) {
	collection := runtimeCollection{exceptionTypes: &exceptionTypes{}}
	observe := func(counter runtimeCounter) *runtimemetrics.DotnetRuntimeMetricSnapshot {
		snapshot, err := collection.observeEvent(netTraceRuntimeEvent{counter: counter})
		require.NoError(t, err)
		return snapshot
	}
	throw := func() {
		snapshot, err := collection.observeEvent(netTraceRuntimeEvent{exceptionType: "Failure", exceptionCount: 1})
		require.NoError(t, err)
		require.Nil(t, snapshot, "throws accumulate until a counter interval completes")
	}
	complete := func() {
		for _, name := range []string{"gen-0-gc-count", "gen-1-gc-count", "gen-2-gc-count", "time-in-jit"} {
			require.Nil(t, observe(runtimeCounter{Name: name, Increment: true}))
		}
	}
	require.Nil(t, observe(runtimeCounter{Name: "working-set", Value: 1}))
	throw()
	complete()
	first := observe(runtimeCounter{Name: "working-set", Value: 1})
	require.NotNil(t, first)
	throw()
	require.Equal(t, map[string]uint64{"Failure": 1}, first.Exceptions)
	complete()
	last := collection.finish()
	require.NotNil(t, last)
	require.Equal(t, map[string]uint64{"Failure": 2}, last.Exceptions)
	throw()
	require.Equal(t, uint64(2), last.Exceptions["Failure"])
	require.Equal(t, uint64(1), first.Exceptions["Failure"])

	collection.exceptions["Failure"] = math.MaxInt64
	require.ErrorContains(t, collection.observeException("Failure", 1), "overflow")
	require.Equal(t, uint64(math.MaxInt64), collection.exceptions["Failure"])
}

func TestRuntimeCollectionExceptionDeltas(t *testing.T) {
	collection := runtimeCollection{exceptionTypes: &exceptionTypes{}}
	for _, count := range []uint64{3, 0, 2} {
		snapshot, err := collection.observeEvent(netTraceRuntimeEvent{exceptionType: "Failure", exceptionCount: count})
		require.NoError(t, err)
		require.Nil(t, snapshot)
	}
	require.Equal(t, uint64(5), collection.exceptions["Failure"])
	_, err := collection.observeEvent(netTraceRuntimeEvent{exceptionType: "Failure", exceptionCount: math.MaxInt64 - 4})
	require.ErrorContains(t, err, "overflow")
	require.Equal(t, uint64(5), collection.exceptions["Failure"])
}

func TestRuntimeCollectionExceptionDiagnostics(t *testing.T) {
	for _, unavailable := range []bool{false, true} {
		t.Run(strconv.FormatBool(unavailable), func(t *testing.T) {
			var types exceptionTypes
			collection := runtimeCollection{exceptionTypes: &types}
			_, err := collection.observeEvent(netTraceRuntimeEvent{exceptionType: "Failure", exceptionCount: 3})
			require.NoError(t, err)
			_, err = collection.observeEvent(netTraceRuntimeEvent{exceptionWarning: "subscription diagnostic", exceptionsUnavailable: unavailable})
			require.NoError(t, err)
			_, err = collection.observeEvent(netTraceRuntimeEvent{exceptionType: "Failure", exceptionCount: 2})
			require.NoError(t, err)
			if unavailable {
				require.Nil(t, collection.exceptions)
			} else {
				require.Equal(t, uint64(5), collection.exceptions["Failure"])
			}
			_, err = collection.observeEvent(netTraceRuntimeEvent{counter: runtimeCounter{Name: "processor-count", Value: 4}})
			require.NoError(t, err)
			require.NotNil(t, collection.processorCount)
			require.Equal(t, int64(4), *collection.processorCount)

			next := runtimeCollection{exceptionTypes: &types}
			_, err = next.observeEvent(netTraceRuntimeEvent{exceptionType: "Failure", exceptionCount: 2})
			require.NoError(t, err)
			require.Equal(t, uint64(2), next.exceptions["Failure"])
			require.Len(t, types.names, 1)
		})
	}
}

func TestRuntimeCollectionExceptionTypesAcrossSessions(t *testing.T) {
	var types exceptionTypes
	first := runtimeCollection{exceptionTypes: &types}
	for i := range maximumExceptionTypes {
		require.NoError(t, first.observeException("Failure"+strconv.Itoa(i), 1))
	}
	next := runtimeCollection{exceptionTypes: &types, exceptions: make(map[string]uint64)}
	for _, name := range []string{"working-set", "gen-0-gc-count", "gen-1-gc-count", "gen-2-gc-count", "time-in-jit"} {
		_, err := next.observeEvent(netTraceRuntimeEvent{counter: runtimeCounter{Name: name, Increment: name != "working-set"}})
		require.NoError(t, err)
	}
	quiet := next.finish()
	require.NotNil(t, quiet)
	require.NotNil(t, quiet.Exceptions)
	require.Empty(t, quiet.Exceptions)
	require.NoError(t, next.observeException("NewFailure", 1))
	require.NoError(t, next.observeException("Failure0", 1))
	require.Equal(t, map[string]uint64{exceptionTypeOther: 1, "Failure0": 1}, next.exceptions)
	require.Empty(t, quiet.Exceptions, "later throws must not mutate the quiet snapshot")
	require.Len(t, types.names, maximumExceptionTypes)
}

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

func TestRuntimeCollectionHeapSizes(t *testing.T) {
	var collection runtimeCollection
	observe := func(counter runtimeCounter) *runtimemetrics.DotnetRuntimeMetricSnapshot {
		snapshot, err := collection.observe(counter)
		require.NoError(t, err)
		return snapshot
	}
	observe(runtimeCounter{Name: "working-set", Value: 1})
	complete := func() {
		for _, name := range []string{"gen-0-gc-count", "gen-1-gc-count", "gen-2-gc-count", "time-in-jit"} {
			observe(runtimeCounter{Name: name, Increment: true})
		}
	}
	for generation, name := range []string{"gen-0-size", "gen-1-size", "gen-2-size", "loh-size", "poh-size"} {
		observe(runtimeCounter{Name: name, Value: float64(generation * 100)})
	}
	complete()
	first := observe(runtimeCounter{Name: "working-set", Value: 1})
	require.NotNil(t, first)
	for generation, value := range first.GCHeapSize {
		require.NotNil(t, value)
		require.Equal(t, int64(generation*100), *value)
	}
	observe(runtimeCounter{Name: "loh-size", Value: 10})
	complete()
	second := collection.finish()
	require.NotNil(t, second)
	require.Equal(t, int64(10), *second.GCHeapSize[3])
	require.Nil(t, second.GCHeapSize[0], "missing values do not carry into a new interval")
	require.Equal(t, int64(300), *first.GCHeapSize[3], "published snapshots remain immutable")
	collection = runtimeCollection{}
	observe(runtimeCounter{Name: "working-set", Value: 1})
	complete()
	require.Equal(t, [runtimemetrics.DotnetHeapGenerationCount]*int64{}, collection.finish().GCHeapSize)
}

func TestRuntimeCollectionFragmentation(t *testing.T) {
	var collection runtimeCollection
	observe := func(event netTraceRuntimeEvent) *runtimemetrics.DotnetRuntimeMetricSnapshot {
		snapshot, err := collection.observeEvent(event)
		require.NoError(t, err)
		return snapshot
	}
	completeRound := func() {
		for _, name := range []string{"gen-0-gc-count", "gen-1-gc-count", "gen-2-gc-count", "time-in-jit"} {
			require.Nil(t, observe(netTraceRuntimeEvent{counter: runtimeCounter{Name: name, Increment: true}}))
		}
	}
	workingSet := netTraceRuntimeEvent{counter: runtimeCounter{Name: "working-set", Value: 1}}
	require.Nil(t, observe(workingSet))
	identity := gcCollectionEvent{count: 1, depth: 2}
	for _, event := range []gcRuntimeEvent{
		{eventID: clrGCStartEventID, collection: identity},
		{eventID: clrGCGlobalHeapHistoryEventID, threadID: 1, globalHistory: gcGlobalHeapHistory{depth: 2, heapCount: 1}},
		{eventID: clrGCPerHeapHistoryEventID, threadID: 1, perHeapHistory: gcPerHeapHistory{fragmentation: [5]uint64{10, 20, 30, 40, 50}}},
		{eventID: clrGCEndEventID, collection: identity},
	} {
		require.Nil(t, observe(netTraceRuntimeEvent{gc: &event}), "GC events accumulate until a polling boundary")
	}
	completeRound()
	first := observe(workingSet)
	require.NotNil(t, first)
	for generation, value := range first.GCHeapFragmentation {
		require.NotNil(t, value)
		require.Equal(t, int64((generation+1)*10), *value)
	}
	completeRound()
	last := collection.finish()
	require.NotNil(t, last)
	require.Equal(t, first.GCHeapFragmentation, last.GCHeapFragmentation, "last-collection values persist across polling rounds")
	require.Nil(t, observe(netTraceRuntimeEvent{gc: &gcRuntimeEvent{eventID: clrGCEndEventID, collection: gcCollectionEvent{count: 2, depth: 2}}}))
	require.Equal(t, int64(10), *first.GCHeapFragmentation[0])
	require.Equal(t, int64(10), *last.GCHeapFragmentation[0])
	collection = runtimeCollection{}
	require.Nil(t, observe(workingSet))
	completeRound()
	fresh := collection.finish()
	require.NotNil(t, fresh)
	require.Equal(t, [runtimemetrics.DotnetHeapGenerationCount]*int64{}, fresh.GCHeapFragmentation, "a new session needs fresh GC history")
	_, err := collection.observeEvent(netTraceRuntimeEvent{gc: &gcRuntimeEvent{eventID: 999}})
	require.ErrorContains(t, err, "unexpected CLR GC event")
}
