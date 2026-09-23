// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
		complete    bool
	}{
		{"complete", []string{"gen-0-gc-count", "gen-1-gc-count", "gen-2-gc-count"}, true, true},
		{"missing assembly", []string{"gen-0-gc-count", "gen-1-gc-count", "gen-2-gc-count"}, false, false},
		{"incomplete GC", []string{"gen-0-gc-count", "gen-1-gc-count"}, true, false},
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
			snapshot := collection.finish()
			if !tc.complete {
				require.Nil(t, snapshot)
				return
			}
			require.NotNil(t, snapshot)
			require.NotNil(t, snapshot.ProcessMemoryWorkingSet)
			require.Equal(t, int64(12_500_000), *snapshot.ProcessMemoryWorkingSet)
			require.NotNil(t, snapshot.AssemblyCount)
			require.Equal(t, int64(10), *snapshot.AssemblyCount)
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
