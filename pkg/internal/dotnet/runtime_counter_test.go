// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeRuntimeCounter(t *testing.T) {
	for _, counterType := range []string{"Mean", "Sum"} {
		t.Run(counterType, func(t *testing.T) {
			values := map[string]any{"": map[string]any{"Payload": map[string]any{
				"Name": "gen-2-gc-count", "CounterType": counterType, "IntervalSec": float32(2),
				"Mean": float64(12), "Increment": float64(3),
			}}}
			got, err := decodeRuntimeCounter(values)
			require.NoError(t, err)
			want := runtimeCounter{Name: "gen-2-gc-count", Value: 12, IntervalSec: 2}
			if counterType == "Sum" {
				want.Value, want.Increment = 3, true
			}
			require.Equal(t, want, got)
		})
	}
	for _, tc := range []struct {
		field string
		value any
	}{
		{"Name", ""},
		{"Name", 1},
		{"CounterType", "unknown"},
		{"IntervalSec", float32(0)},
		{"IntervalSec", float32(-1)},
		{"IntervalSec", float32(math.NaN())},
		{"IntervalSec", float32(math.Inf(1))},
		{"IntervalSec", float64(1)},
		{"Increment", nil},
		{"Increment", math.NaN()},
		{"Increment", math.Inf(1)},
	} {
		payload := map[string]any{
			"Name": "gen-2-gc-count", "CounterType": "Sum",
			"IntervalSec": float32(1), "Increment": float64(3),
		}
		payload[tc.field] = tc.value
		got, err := decodeRuntimeCounter(map[string]any{"": map[string]any{"Payload": payload}})
		require.Error(t, err, "invalid %s: %v", tc.field, tc.value)
		require.Zero(t, got)
	}
	for _, values := range []map[string]any{nil, {"": "wrong"}, {"": map[string]any{}}} {
		got, err := decodeRuntimeCounter(values)
		require.Error(t, err)
		require.Zero(t, got)
	}
}

func TestDecodeRuntimeCounterIgnoresUnusedCounters(t *testing.T) {
	for _, payload := range []map[string]any{
		{"Name": "working-set"},
		{"Name": "cpu-usage", "CounterType": "unknown", "IntervalSec": float32(0), "Mean": math.NaN()},
		{"Name": "alloc-rate", "CounterType": "Sum", "IntervalSec": float32(1), "Increment": "invalid"},
	} {
		t.Run(payload["Name"].(string), func(t *testing.T) {
			counter, err := decodeRuntimeCounter(map[string]any{"": map[string]any{"Payload": payload}})
			require.NoError(t, err)
			require.Zero(t, counter)
		})
	}
}
