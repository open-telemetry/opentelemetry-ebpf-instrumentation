// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
)

func TestParseNodejsEventLoopEvent(t *testing.T) {
	const ktime = 2 * 3600 * 1_000_000_000 // 2h since boot

	values := NodejsEventLoopValues{
		ELUIdleNs:     1_000_000_000,
		ELUActiveNs:   250_000_000,
		DelayMinNs:    9_000_000,
		DelayMaxNs:    153_000_000,
		DelayMeanNs:   12_000_000,
		DelayStddevNs: 10_000_000,
		DelayP50Ns:    11_000_000,
		DelayP90Ns:    12_700_000,
		DelayP99Ns:    13_300_000,
		DelayCount:    181,
	}

	event := ParseNodejsEventLoopEvent(ktime, 55, 99, values)

	assert.Equal(t, app.PID(55), event.PID)
	assert.Equal(t, uint32(99), event.PIDNamespaceID)
	assert.Equal(t, values, event.NodejsEventLoopValues)
	require.WithinDuration(t, timing.KernelTime(ktime), event.Time, 100*time.Millisecond)
}

// The GC type strings are the semconv v8js.gc.type values; the numeric
// codes are the OBI wire codes assigned in fdextractor.js — deliberately
// not the version-dependent Node constants.
func TestNodejsGCTypeSemconvValues(t *testing.T) {
	assert.Equal(t, "minor", NodejsGCTypeMinor.String())
	assert.Equal(t, "major", NodejsGCTypeMajor.String())
	assert.Equal(t, "incremental", NodejsGCTypeIncremental.String())
	assert.Equal(t, "weakcb", NodejsGCTypeWeakCB.String())
	assert.Equal(t, "unknown", NodejsGCTypeUnknown.String())
	assert.Equal(t, "unknown", NodejsGCType(200).String())
}

func TestParseNodejsGCEvent(t *testing.T) {
	const ktime = 2 * 3600 * 1_000_000_000

	event := ParseNodejsGCEvent(ktime, 55, 99, 2, 350_000_000)

	assert.Equal(t, app.PID(55), event.PID)
	assert.Equal(t, uint32(99), event.PIDNamespaceID)
	assert.Equal(t, NodejsGCTypeMajor, event.GCType)
	assert.Equal(t, uint64(350_000_000), event.DurationNs)
	require.WithinDuration(t, timing.KernelTime(ktime), event.Time, 100*time.Millisecond)

	// unknown wire codes decode to Unknown; the dispatch layer drops them
	assert.Equal(t, NodejsGCTypeUnknown, ParseNodejsGCEvent(ktime, 55, 99, 9, 1).GCType)
}

// Only the well-known members of the semconv v8js.heap.space.name enum are
// exported. V8 reports more spaces (read_only_space, shared_space,
// trusted_space, ...) depending on the engine version; those are dropped
// before export (see semconvHeapSpaces for the rationale).
func TestIsSemconvHeapSpace(t *testing.T) {
	for _, name := range []string{"new_space", "old_space", "code_space", "map_space", "large_object_space"} {
		assert.True(t, IsSemconvHeapSpace(name), name)
	}
	for _, name := range []string{"read_only_space", "shared_space", "new_large_object_space", ""} {
		assert.False(t, IsSemconvHeapSpace(name), name)
	}
}

func TestParseNodejsHeapSpaceEvent(t *testing.T) {
	const ktime = 2 * 3600 * 1_000_000_000

	values := NodejsHeapSpaceValues{
		SpaceSize:          200 << 20,
		SpaceUsedSize:      150 << 20,
		SpaceAvailableSize: 30 << 20,
		PhysicalSpaceSize:  200 << 20,
	}
	event := ParseNodejsHeapSpaceEvent(ktime, 55, 99, "old_space", values)

	assert.Equal(t, app.PID(55), event.PID)
	assert.Equal(t, uint32(99), event.PIDNamespaceID)
	assert.Equal(t, "old_space", event.SpaceName)
	assert.Equal(t, values, event.NodejsHeapSpaceValues)
	require.WithinDuration(t, timing.KernelTime(ktime), event.Time, 100*time.Millisecond)
}
