// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"bytes"
	"math"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGCHeapBatch(t *testing.T) {
	batch := gcHeapBatch{
		collection: &gcHeapCollection{identity: gcCollectionEvent{clrInstanceID: 3}},
		heapCount:  2,
	}
	first := gcPerHeapHistory{clrInstanceID: 3, heapIndex: 0, fragmentation: [5]uint64{10, 20, 30, 40, 50}}
	require.NoError(t, batch.add(first))
	require.ErrorContains(t, batch.add(first), "duplicate")
	wrongInstance := first
	wrongInstance.clrInstanceID = 4
	require.ErrorContains(t, batch.add(wrongInstance), "instance")
	require.Equal(t, first.fragmentation, batch.fragmentation)
	require.Len(t, batch.seen, 1)
	second := gcPerHeapHistory{clrInstanceID: 3, heapIndex: 1, fragmentation: [5]uint64{1, 2, 3, 4, 5}}
	require.NoError(t, batch.add(second))
	require.Equal(t, [5]uint64{11, 22, 33, 44, 55}, batch.fragmentation)
	require.Len(t, batch.seen, 2)
	second.heapIndex = 2
	require.ErrorContains(t, batch.add(second), "exceed expected count")
	require.Equal(t, [5]uint64{11, 22, 33, 44, 55}, batch.fragmentation)
}

func TestGCHeapBatchOverflowIsAtomic(t *testing.T) {
	batch := gcHeapBatch{collection: &gcHeapCollection{}, heapCount: 2}
	first := gcPerHeapHistory{fragmentation: [5]uint64{10, math.MaxInt64}}
	require.NoError(t, batch.add(first))
	second := gcPerHeapHistory{heapIndex: 1, fragmentation: [5]uint64{7, 1}}
	require.ErrorContains(t, batch.add(second), "exporter range")
	require.Equal(t, first.fragmentation, batch.fragmentation, "earlier generations remain unchanged on overflow")
	require.Len(t, batch.seen, 1, "rejected heap is not recorded")
	second.fragmentation[1] = 0
	require.NoError(t, batch.add(second))
	require.Equal(t, [5]uint64{17, math.MaxInt64}, batch.fragmentation)
}

func TestGCFragmentationCompletionOrder(t *testing.T) {
	var state gcFragmentation
	full := gcCollectionEvent{count: 10, depth: 2}
	ephemeral := gcCollectionEvent{count: 11, depth: 1}
	require.NoError(t, state.start(full))
	require.NoError(t, state.beginHistory(7, gcGlobalHeapHistory{depth: 2, heapCount: 1}))
	require.NoError(t, state.addHeapHistory(7, gcPerHeapHistory{fragmentation: [5]uint64{100, 200, 300, 400, 500}}))
	require.Equal(t, [5]*int64{}, state.snapshot(), "history alone does not complete a collection")
	require.NoError(t, state.start(ephemeral))
	require.NoError(t, state.beginHistory(8, gcGlobalHeapHistory{depth: 1, heapCount: 1}))
	require.NoError(t, state.addHeapHistory(8, gcPerHeapHistory{fragmentation: [5]uint64{1, 2, 3, 4, 5}}))
	require.NoError(t, state.complete(ephemeral))
	saved := state.snapshot()
	require.Equal(t, int64(1), *saved[0])
	require.NoError(t, state.complete(full))
	for generation, value := range state.snapshot() {
		require.NotNil(t, value)
		require.Equal(t, int64((generation+1)*100), *value, "completion order takes precedence over collection ID")
	}
	require.Equal(t, int64(1), *saved[0], "published snapshots retain their values")
}

func TestGCFragmentationCompletionBeforeHistory(t *testing.T) {
	var state gcFragmentation
	first := gcCollectionEvent{count: 1, depth: 2}
	require.NoError(t, state.start(first))
	require.NoError(t, state.complete(first))
	require.Equal(t, [5]*int64{}, state.snapshot())
	require.NoError(t, state.beginHistory(9, gcGlobalHeapHistory{depth: 2, heapCount: 2}))
	require.NoError(t, state.addHeapHistory(9, gcPerHeapHistory{heapIndex: 3, fragmentation: [5]uint64{10}}))
	require.Equal(t, [5]*int64{}, state.snapshot(), "all heaps must arrive")
	require.NoError(t, state.addHeapHistory(9, gcPerHeapHistory{heapIndex: 7, fragmentation: [5]uint64{20}}))
	require.Equal(t, int64(30), *state.snapshot()[0])
	require.Empty(t, state.batches)
	second := gcCollectionEvent{count: 2, depth: 2}
	require.NoError(t, state.start(second))
	require.NoError(t, state.complete(second))
	require.Equal(t, [5]*int64{}, state.snapshot(), "missing latest history must not reuse older totals")
	require.NoError(t, state.beginHistory(9, gcGlobalHeapHistory{depth: 2, heapCount: 1}))
	require.NoError(t, state.addHeapHistory(9, gcPerHeapHistory{fragmentation: [5]uint64{4}}))
	require.Equal(t, int64(4), *state.snapshot()[0], "heap counts can change between collections")
}

func TestGCFragmentationMissingStart(t *testing.T) {
	var state gcFragmentation
	require.NoError(t, state.beginHistory(1, gcGlobalHeapHistory{depth: 2, heapCount: 1}))
	require.NoError(t, state.addHeapHistory(1, gcPerHeapHistory{fragmentation: [5]uint64{99}}))
	require.NoError(t, state.complete(gcCollectionEvent{count: 1, depth: 2}))
	require.Equal(t, [5]*int64{}, state.snapshot())
	identity := gcCollectionEvent{count: 2, depth: 0}
	require.NoError(t, state.start(identity))
	require.NoError(t, state.beginHistory(1, gcGlobalHeapHistory{heapCount: 1}))
	require.NoError(t, state.addHeapHistory(1, gcPerHeapHistory{}))
	require.NoError(t, state.complete(identity))
	for _, value := range state.snapshot() {
		require.NotNil(t, value)
		require.Zero(t, *value, "available zero differs from missing history")
	}
	require.NoError(t, state.complete(gcCollectionEvent{count: 3, depth: 2}))
	require.Equal(t, [5]*int64{}, state.snapshot(), "unknown completion invalidates the previous result")
}

func TestGCFragmentationRejectsInvalidTransitions(t *testing.T) {
	identity := gcCollectionEvent{count: 1, depth: 2, clrInstanceID: 3}
	global := gcGlobalHeapHistory{depth: 2, heapCount: 1, clrInstanceID: 3}
	t.Run("overlap and instance", func(t *testing.T) {
		var state gcFragmentation
		require.NoError(t, state.start(identity))
		require.ErrorContains(t, state.start(identity), "overlapping")
		other := identity
		other.clrInstanceID++
		require.ErrorContains(t, state.start(other), "instance changed")
		require.ErrorContains(t, state.complete(other), "instance changed")
		require.NoError(t, state.complete(identity))
		require.ErrorContains(t, state.complete(identity), "duplicate")
		require.ErrorContains(t, state.start(identity), "overlapping", "completion alone does not release missing history")
	})
	t.Run("history bounds and identity", func(t *testing.T) {
		var state gcFragmentation
		require.NoError(t, state.start(identity))
		for _, count := range []uint32{0, 4097} {
			invalid := global
			invalid.heapCount = count
			require.ErrorContains(t, state.beginHistory(1, invalid), "outside supported range")
		}
		invalid := global
		invalid.clrInstanceID++
		require.ErrorContains(t, state.beginHistory(1, invalid), "does not match")
		require.Empty(t, state.batches)
		require.NoError(t, state.beginHistory(1, global))
		require.ErrorContains(t, state.beginHistory(1, global), "overlapping")
		require.ErrorContains(t, state.beginHistory(2, global), "duplicate")
		require.NoError(t, state.addHeapHistory(1, gcPerHeapHistory{clrInstanceID: 3}))
		require.ErrorContains(t, state.beginHistory(1, global), "duplicate")
	})
	t.Run("ephemeral depth", func(t *testing.T) {
		var state gcFragmentation
		require.NoError(t, state.start(gcCollectionEvent{count: 1, depth: 1}))
		require.ErrorContains(t, state.beginHistory(1, gcGlobalHeapHistory{depth: 0, heapCount: 1}), "does not match")
	})
}

func TestGCFragmentationCapturedTrace(t *testing.T) {
	wire, err := os.ReadFile("testdata/gc-net10.nettrace")
	require.NoError(t, err)
	info, err := readNetTracePreamble(newNetTraceReader(bytes.NewReader(wire)))
	require.NoError(t, err)
	var state gcFragmentation
	completed := make(map[uint32]struct{})
	err = readRuntimeEvents(bytes.NewReader(wire), uint64(info.ProcessID), "", func(event netTraceRuntimeEvent) error {
		require.NotNil(t, event.gc)
		if err := state.observe(*event.gc); err != nil {
			return err
		}
		if snapshot := state.snapshot(); snapshot[0] != nil {
			for _, value := range snapshot {
				require.NotNil(t, value)
				require.GreaterOrEqual(t, *value, int64(0))
			}
			completed[state.latest.identity.count] = struct{}{}
		}
		return nil
	})
	require.NoError(t, err)
	require.Len(t, completed, 17, "every captured collection produces a complete result")
	require.Empty(t, state.batches)
}
