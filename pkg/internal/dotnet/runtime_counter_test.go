// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeProcessorCount(t *testing.T) {
	for _, count := range []int32{1, 8, math.MaxInt32} {
		got, err := decodeProcessorCount(map[string]any{"processorCount": count})
		require.NoError(t, err)
		require.Equal(t, runtimeCounter{Name: "processor-count", Value: float64(count)}, got)
	}
	for _, value := range []any{nil, int32(0), int32(-1), int64(8), float64(8), "8"} {
		got, err := decodeProcessorCount(map[string]any{"processorCount": value})
		require.Error(t, err, "value: %v", value)
		require.Zero(t, got)
	}
	_, err := decodeProcessorCount(nil)
	require.Error(t, err)
}

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

func TestDecodeRuntimePollingCounters(t *testing.T) {
	for _, name := range []string{
		"working-set", "gc-committed", "threadpool-thread-count",
		"threadpool-queue-length", "active-timer-count", "assembly-count",
	} {
		t.Run(name, func(t *testing.T) {
			values := map[string]any{"": map[string]any{"Payload": map[string]any{
				"Name": name, "CounterType": "Mean", "IntervalSec": float32(1),
				"Mean": float64(12),
			}}}
			got, err := decodeRuntimeCounter(values)
			require.NoError(t, err)
			require.Equal(t, runtimeCounter{Name: name, Value: 12, IntervalSec: 1}, got)
		})
	}
}

func TestDecodeRuntimeCumulativeCounters(t *testing.T) {
	for _, source := range []struct {
		name      string
		increment bool
	}{
		{"alloc-rate", true},
		{"total-pause-time-by-gc", true},
		{"il-bytes-jitted", false},
		{"methods-jitted-count", false},
		{"time-in-jit", true},
		{"threadpool-completed-items-count", true},
		{"monitor-lock-contention-count", true},
	} {
		t.Run(source.name, func(t *testing.T) {
			payload := map[string]any{
				"Name": source.name, "CounterType": "Mean", "IntervalSec": float32(2), "Mean": float64(12),
			}
			if source.increment {
				payload["CounterType"], payload["Increment"] = "Sum", float64(12)
				delete(payload, "Mean")
			}
			counter, err := decodeRuntimeCounter(map[string]any{"": map[string]any{"Payload": payload}})
			require.NoError(t, err)
			require.Equal(t, runtimeCounter{Name: source.name, Value: 12, IntervalSec: 2, Increment: source.increment}, counter)
		})
	}
}

func TestDecodeRuntimeCounterIgnoresUnusedCounters(t *testing.T) {
	for _, payload := range []map[string]any{
		{"Name": "gc-fragmentation"},
		{"Name": "cpu-usage", "CounterType": "unknown", "IntervalSec": float32(0), "Mean": math.NaN()},
		{"Name": "exception-count", "CounterType": "Sum", "IntervalSec": float32(1), "Increment": "invalid"},
	} {
		t.Run(payload["Name"].(string), func(t *testing.T) {
			counter, err := decodeRuntimeCounter(map[string]any{"": map[string]any{"Payload": payload}})
			require.NoError(t, err)
			require.Zero(t, counter)
		})
	}
}
