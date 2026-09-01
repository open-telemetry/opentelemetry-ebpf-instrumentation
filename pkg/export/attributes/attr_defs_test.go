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

// service.name and service.namespace are resource attributes per the semantic
// conventions, so they are not reported as metric attributes by default. The
// `app` extra-attribute group restores them for backends that read service
// identity off the series rather than joining through target_info.
func TestServiceAttributesAreNotMetricDefaults(t *testing.T) {
	section := HTTPServerDuration.Section

	// GroupPrometheus pulls in the prometheusAttributes subgroup, which used to
	// re-enable service.namespace and made the default inconsistent between the
	// two exporters.
	for _, tc := range []struct {
		name   string
		groups AttrGroups
	}{
		{name: "otel", groups: 0},
		{name: "prometheus", groups: GroupPrometheus},
	} {
		t.Run("off by default: "+tc.name, func(t *testing.T) {
			definitions := getDefinitions(tc.groups, NewGroupAttributes(nil))
			definition, ok := definitions[section]
			require.True(t, ok)

			// still selectable, just not part of the default set
			assert.Contains(t, definition.All(), attr.ServiceName)
			assert.Contains(t, definition.All(), attr.ServiceNamespace)

			assert.NotContains(t, definition.Default(), attr.ServiceName)
			assert.NotContains(t, definition.Default(), attr.ServiceNamespace)
		})
	}

	t.Run("restored by the app extra-attribute group", func(t *testing.T) {
		definitions := getDefinitions(0, NewGroupAttributes(map[string][]attr.Name{
			"app": {attr.ServiceName, attr.ServiceNamespace},
		}))
		definition, ok := definitions[section]
		require.True(t, ok)

		assert.Contains(t, definition.Default(), attr.ServiceName)
		assert.Contains(t, definition.Default(), attr.ServiceNamespace)
	})
}

func TestCPythonRuntimeDefinitions(t *testing.T) {
	tests := []Name{
		CPythonGCCollections,
		CPythonGCCollectedObjects,
		CPythonGCUncollectableObjects,
	}

	definitions := getDefinitions(0, NewGroupAttributes(nil))
	for _, metric := range tests {
		definition, ok := definitions[metric.Section]
		require.True(t, ok)
		assert.Contains(t, definition.All(), attr.ServiceName)
		assert.Contains(t, definition.All(), attr.ServiceNamespace)
		assert.Contains(t, definition.All(), attr.CPythonGCGeneration)
	}
}
