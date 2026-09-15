// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestGCRoundObserve(t *testing.T) {
	var round gcRound
	observeRound := func(increments [3]float64) *runtimemetrics.DotnetRuntimeMetricSnapshot {
		t.Helper()
		var snapshot *runtimemetrics.DotnetRuntimeMetricSnapshot
		for generation, increment := range increments {
			var err error
			snapshot, err = round.observe(runtimeCounter{
				Name: fmt.Sprintf("gen-%d-gc-count", generation), Value: increment, Increment: true,
			})
			require.NoError(t, err)
			if generation < 2 {
				require.Nil(t, snapshot, "partial rounds must not reach exporters")
			}
		}
		return snapshot
	}
	assertCounts := func(snapshot *runtimemetrics.DotnetRuntimeMetricSnapshot, expected [3]uint64) {
		t.Helper()
		require.NotNil(t, snapshot)
		for generation, count := range snapshot.GCCollections {
			require.NotNil(t, count)
			require.Equal(t, expected[generation], *count)
		}
	}

	baseline := observeRound([3]float64{100, 50, 20})
	assertCounts(baseline, [3]uint64{})
	assertCounts(observeRound([3]float64{3, 3, 3}), [3]uint64{0, 0, 3})
	assertCounts(observeRound([3]float64{2, 1, 0}), [3]uint64{1, 1, 3})
	assertCounts(baseline, [3]uint64{})

	// A higher-generation poll can see a GC that an earlier poll missed.
	require.Nil(t, observeRound([3]float64{0, 1, 1}))
	assertCounts(observeRound([3]float64{1, 0, 0}), [3]uint64{1, 1, 4})

	before := round
	snapshot, err := round.observe(runtimeCounter{Name: "working-set", Value: 42})
	require.NoError(t, err)
	require.Nil(t, snapshot)
	require.Equal(t, before, round)

	counter := runtimeCounter{Name: "gen-0-gc-count", Increment: true}
	snapshot, err = round.observe(counter)
	require.NoError(t, err)
	require.Nil(t, snapshot)
	_, err = round.observe(counter)
	require.ErrorContains(t, err, "incomplete GC sampling round")
}

func TestGCCountsObserve(t *testing.T) {
	var counts gcCounts
	for generation := range 3 {
		counter := runtimeCounter{Name: fmt.Sprintf("gen-%d-gc-count", generation), Value: 100, Increment: true}
		require.NoError(t, counts.observe(counter))
		require.Zero(t, counts.collections[generation])
		require.True(t, counts.initialized[generation])
		counter.Value = float64(generation + 1)
		require.NoError(t, counts.observe(counter))
		require.NoError(t, counts.observe(counter))
	}
	require.Equal(t, [3]uint64{2, 4, 6}, counts.collections)
	before := counts
	require.NoError(t, counts.observe(runtimeCounter{Name: "working-set", Value: 42}))
	require.Equal(t, before, counts)
	for _, value := range []float64{-1, 1.5, math.NaN(), math.Inf(1), 0x1p64} {
		err := counts.observe(runtimeCounter{Name: "gen-0-gc-count", Value: value, Increment: true})
		require.Error(t, err)
		require.Equal(t, before, counts)
	}
	require.Error(t, counts.observe(runtimeCounter{Name: "gen-0-gc-count", Value: 1}))
	require.Equal(t, before, counts)
	counts.collections[0] = ^uint64(0)
	require.ErrorContains(t, counts.observe(runtimeCounter{Name: "gen-0-gc-count", Value: 1, Increment: true}), "overflow")
	require.Equal(t, ^uint64(0), counts.collections[0])
}

func TestGCCountsSnapshot(t *testing.T) {
	var counts gcCounts
	empty := counts.snapshot()
	for _, count := range empty.GCCollections {
		require.Nil(t, count)
	}
	counter := runtimeCounter{Name: "gen-1-gc-count", Value: 100, Increment: true}
	require.NoError(t, counts.observe(counter))
	require.Nil(t, counts.snapshot().GCCollections[1], "gen1 needs the gen2 baseline")
	require.NoError(t, counts.observe(runtimeCounter{Name: "gen-2-gc-count", Increment: true}))
	baseline := counts.snapshot()
	require.Nil(t, baseline.GCCollections[0])
	require.NotNil(t, baseline.GCCollections[1])
	require.Zero(t, *baseline.GCCollections[1])
	require.NotNil(t, baseline.GCCollections[2])
	require.Zero(t, *baseline.GCCollections[2])
	counter.Value = 3
	require.NoError(t, counts.observe(counter))
	current := counts.snapshot()
	require.Equal(t, uint64(3), *current.GCCollections[1])
	require.Zero(t, *baseline.GCCollections[1], "published baseline remains unchanged")
	*current.GCCollections[1] = 42
	require.Equal(t, uint64(3), counts.collections[1], "snapshot owns its values")
}

func TestGCCountsSnapshotExclusiveGenerations(t *testing.T) {
	for _, tc := range []struct {
		inclusive [3]uint64
		exclusive [3]uint64
	}{
		{[3]uint64{3, 3, 3}, [3]uint64{0, 0, 3}},
		{[3]uint64{12, 7, 3}, [3]uint64{5, 4, 3}},
	} {
		counts := gcCounts{collections: tc.inclusive, initialized: [3]bool{true, true, true}}
		snapshot := counts.snapshot()
		for generation, want := range tc.exclusive {
			require.NotNil(t, snapshot.GCCollections[generation])
			require.Equal(t, want, *snapshot.GCCollections[generation])
		}
	}
	counts := gcCounts{collections: [3]uint64{1, 2, 3}, initialized: [3]bool{true, true, true}}
	snapshot := counts.snapshot()
	require.Nil(t, snapshot.GCCollections[0])
	require.Nil(t, snapshot.GCCollections[1])
	require.Equal(t, uint64(3), *snapshot.GCCollections[2])
}
