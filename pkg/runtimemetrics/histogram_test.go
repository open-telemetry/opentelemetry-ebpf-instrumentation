// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBucketBoundsSecondsMatchGoRuntimeHistogram(t *testing.T) {
	bounds := bucketBoundsSeconds()

	require.Len(t, bounds, 161)
	require.InDelta(t, math.Nextafter(0, math.Inf(-1)), bounds[0], 0)
	require.InDelta(t, math.Nextafter(64.0/1e9, 0), bounds[1], 0)
	require.InDelta(t, math.Nextafter(192.0/1e9, 128.0/1e9), bounds[3], 0)
	require.InDelta(t, math.Nextafter(256.0/1e9, 192.0/1e9), bounds[4], 0)
	require.InDelta(t, math.Nextafter(448.0/1e9, 384.0/1e9), bounds[7], 0)
	require.InDelta(t, math.Nextafter(512.0/1e9, 448.0/1e9), bounds[8], 0)
	require.InDelta(t,
		math.Nextafter(float64(uint64(1)<<47)/1e9, float64(uint64(7)<<44)/1e9),
		bounds[len(bounds)-1],
		0,
	)
	for i := 1; i < len(bounds); i++ {
		require.Less(t, bounds[i-1], bounds[i], "bounds %d and %d", i-1, i)
	}
}

func TestGoRuntimeHistogramDataMapsPopulationsAndClonesSlices(t *testing.T) {
	counts := make([]uint64, goRuntimeHistogramMaxBuckets)
	counts[0] = 2
	counts[len(counts)-1] = 3
	snapshot := GoRuntimeHistogramSnapshot{
		Kind:      GoHistogramKindGCPause,
		Counts:    counts,
		Underflow: 1,
		Overflow:  4,
	}

	data, err := snapshot.Data()
	require.NoError(t, err)
	require.Len(t, data.Bounds, 161)
	require.Len(t, data.BucketCounts, 162)
	require.Equal(t, uint64(1), data.BucketCounts[0])
	require.Equal(t, counts, data.BucketCounts[1:161])
	require.Equal(t, uint64(4), data.BucketCounts[161])

	counts[0] = 99
	require.Equal(t, uint64(2), data.BucketCounts[1])
	data.Bounds[0] = 99
	data.BucketCounts[0] = 99
	again, err := snapshot.Data()
	require.NoError(t, err)
	require.NotEqual(t, float64(99), again.Bounds[0])
	require.Equal(t, uint64(1), again.BucketCounts[0])
	require.Equal(t, uint64(99), again.BucketCounts[1])
}

func TestGoRuntimeHistogramDataCountAndLowerBoundSum(t *testing.T) {
	counts := make([]uint64, goRuntimeHistogramMaxBuckets)
	counts[0] = 2
	counts[1] = 3
	counts[len(counts)-1] = 5
	snapshot := GoRuntimeHistogramSnapshot{
		Counts:    counts,
		Underflow: 7,
		Overflow:  11,
	}

	data, err := snapshot.Data()

	require.NoError(t, err)
	require.Equal(t, uint64(28), data.Count)
	wantSum := 3*(64.0/1e9) +
		5*(float64(uint64(7)<<44)/1e9) +
		11*(float64(uint64(1)<<47)/1e9)
	require.InDelta(t, wantSum, data.Sum, 0)
	require.False(t, math.IsNaN(data.Sum))
	require.False(t, math.IsInf(data.Sum, 0))
}

func TestGoRuntimeHistogramDataRejectsInvalidPopulationCount(t *testing.T) {
	_, err := (GoRuntimeHistogramSnapshot{Counts: make([]uint64, goRuntimeHistogramMaxBuckets-1)}).Data()

	require.ErrorContains(t, err, "159")
}

func TestGoRuntimeHistogramDataRejectsCountOverflow(t *testing.T) {
	counts := make([]uint64, goRuntimeHistogramMaxBuckets)
	counts[0] = 1

	_, err := (GoRuntimeHistogramSnapshot{Counts: counts, Underflow: math.MaxUint64}).Data()

	require.ErrorContains(t, err, "overflow")
}
