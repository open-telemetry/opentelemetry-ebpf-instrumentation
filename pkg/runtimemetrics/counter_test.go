// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCounterDeltaIntegers(t *testing.T) {
	for _, tc := range []struct {
		name        string
		initialized bool
		previous    int64
		current     int64
		want        int64
	}{
		{"first sample", false, 0, 10, 10},
		{"initial zero", false, 0, 0, 0},
		{"increase", true, 10, 15, 5},
		{"unchanged", true, 10, 10, 0},
		{"reset", true, 10, 3, 3},
		{"reset to zero", true, 10, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var signed *int64
			var unsigned *uint64
			previous := uint64(tc.previous)
			if tc.initialized {
				signed, unsigned = &tc.previous, &previous
			}
			require.Equal(t, tc.want, CounterDelta(signed, tc.current))
			require.Equal(t, uint64(tc.want), CounterDelta(unsigned, uint64(tc.current)))
		})
	}
}

func TestCounterDeltaIntegerPrecision(t *testing.T) {
	signed := int64(1 << 53)
	require.Equal(t, int64(1), CounterDelta(&signed, signed+1))
	unsigned := uint64(1 << 63)
	require.Equal(t, uint64(1), CounterDelta(&unsigned, unsigned+1))
}

func TestCounterDeltaFractionalValues(t *testing.T) {
	for _, tc := range []struct {
		name        string
		initialized bool
		previous    float64
		current     float64
		want        float64
	}{
		{"first sample", false, 0, 0.125, 0.125},
		{"initial zero", false, 0, 0, 0},
		{"increase", true, 0.125, 0.375, 0.25},
		{"unchanged", true, 0.125, 0.125, 0},
		{"reset", true, 0.5, 0.125, 0.125},
		{"reset to zero", true, 0.5, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var previous *float64
			if tc.initialized {
				previous = &tc.previous
			}
			require.InDelta(t, tc.want, CounterDelta(previous, tc.current), 1e-12)
		})
	}
}
