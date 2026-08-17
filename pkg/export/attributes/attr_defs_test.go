// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestEnabledGroups(t *testing.T) {
	var group AttrGroups

	assert.False(t, group.Has(GroupPrometheus))
	assert.False(t, group.Has(GroupKubernetes))
	assert.False(t, group.Has(GroupNetCIDR))

	group.Add(GroupPrometheus)

	assert.True(t, group.Has(GroupPrometheus))
	assert.False(t, group.Has(GroupKubernetes))
	assert.False(t, group.Has(GroupNetCIDR))

	group.Add(GroupKubernetes)

	assert.True(t, group.Has(GroupPrometheus))
	assert.True(t, group.Has(GroupKubernetes))
	assert.False(t, group.Has(GroupNetCIDR))
}

func TestGoRuntimeDefinitions(t *testing.T) {
	tests := []struct {
		name Name
		want Name
	}{
		{
			name: GoRuntimeMemoryGCGoal,
			want: Name{
				Section: "go.memory.gc.goal",
				Prom:    "go_memory_gc_goal_bytes",
				OTEL:    "go.memory.gc.goal",
				Unit:    "By",
				Type:    InstrumentUpDownCounter,
			},
		},
		{
			name: GoRuntimeGoroutineCount,
			want: Name{
				Section: "go.goroutine.count",
				Prom:    "go_goroutine_count",
				OTEL:    "go.goroutine.count",
				Unit:    "{goroutine}",
				Type:    InstrumentUpDownCounter,
			},
		},
		{
			name: GoRuntimeMemoryGCPauseDuration,
			want: Name{
				Section: "go.memory.gc.pause.duration",
				Prom:    "go_memory_gc_pause_duration_seconds",
				OTEL:    "go.memory.gc.pause.duration",
				Unit:    "s",
				Type:    InstrumentHistogram,
			},
		},
		{
			name: GoRuntimeScheduleDuration,
			want: Name{
				Section: "go.schedule.duration",
				Prom:    "go_schedule_duration_seconds",
				OTEL:    "go.schedule.duration",
				Unit:    "s",
				Type:    InstrumentHistogram,
			},
		},
	}

	definitions := getDefinitions(0, NewGroupAttributes(nil))
	for _, test := range tests {
		t.Run(test.want.OTEL, func(t *testing.T) {
			assert.Equal(t, test.want.Section, test.name.Section)
			assert.Equal(t, test.want.OTEL, test.name.OTEL)
			assert.Equal(t, test.want.Prom, test.name.Prom)
			assert.Equal(t, test.want.Unit, test.name.Unit)
			assert.Equal(t, test.want.Type, test.name.Type)

			definition, ok := definitions[test.name.Section]
			require.True(t, ok)
			assert.Contains(t, definition.All(), attr.ServiceName)
			assert.Contains(t, definition.All(), attr.ServiceNamespace)
		})
	}
}
