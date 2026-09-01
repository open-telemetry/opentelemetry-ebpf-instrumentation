// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveDebugLayout(t *testing.T) {
	base, ok := selectLayout(0x030d0ff0, false)
	require.True(t, ok)
	prefix, gc := validDebugOffsets(base)

	resolved, err := resolveDebugLayout(base, prefix, gc)

	require.NoError(t, err)
	assert.Equal(t, uint64(1024), resolved.runtimeSize)
	assert.Equal(t, uint64(64), resolved.runtimeFinalizing)
	assert.Equal(t, uint64(88), resolved.runtimeInterpretersMain)
	assert.Equal(t, uint64(128), resolved.interpreterGC)
	assert.Equal(t, uint64(256), resolved.gcSize)
	assert.Equal(t, uint64(200), resolved.gcCollecting)
}

func TestResolveDebugLayoutRejectsInvalidMetadata(t *testing.T) {
	base, ok := selectLayout(0x030d0ff0, false)
	require.True(t, ok)
	validPrefix, validGC := validDebugOffsets(base)

	tests := []struct {
		name   string
		base   layoutProfile
		prefix []byte
		gc     []byte
	}{
		{name: "short prefix", base: base, prefix: validPrefix[:debugOffsets.PrefixSize-1], gc: validGC},
		{name: "invalid cookie", base: base, prefix: append([]byte(nil), validPrefix...), gc: validGC},
		{name: "missing interpreter GC field", base: base, prefix: validPrefix, gc: validGC},
		{name: "invalid build mode", base: base, prefix: append([]byte(nil), validPrefix...), gc: validGC},
		{name: "layout family mismatch", base: base, prefix: append([]byte(nil), validPrefix...), gc: validGC},
		{name: "short GC metadata", base: base, prefix: validPrefix, gc: validGC[:inlineDebugGCSize-1]},
		{name: "misaligned offset", base: base, prefix: append([]byte(nil), validPrefix...), gc: validGC},
		{name: "offset outside structure", base: base, prefix: append([]byte(nil), validPrefix...), gc: validGC},
	}

	tests[1].prefix[0] = 'X'
	tests[2].base.debugInterpreterGCField = -1
	putDebugWord(tests[3].prefix, debugOffsets.FreeThreaded, 2)
	putDebugWord(tests[4].prefix, debugOffsets.Version, uint64(base.version+0x100))
	putDebugWord(tests[6].prefix, debugOffsets.RuntimeFinalizing, 65)
	putDebugWord(tests[7].prefix, debugOffsets.RuntimeSize, base.debugGCOffset)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveDebugLayout(tt.base, tt.prefix, tt.gc)
			require.ErrorIs(t, err, errUnsupportedLayout)
		})
	}
}

func validDebugOffsets(base layoutProfile) ([]byte, []byte) {
	prefix := make([]byte, debugOffsets.PrefixSize)
	copy(prefix, debugOffsets.Cookie)
	putDebugWord(prefix, debugOffsets.Version, uint64(base.version))
	putDebugWord(prefix, debugOffsets.FreeThreaded, 0)
	putDebugWord(prefix, debugOffsets.RuntimeSize, 1024)
	putDebugWord(prefix, debugOffsets.RuntimeFinalizing, 64)
	putDebugWord(prefix, debugOffsets.RuntimeInterpreters, 80)
	putDebugWord(prefix, debugOffsets.InterpreterSize, 1024)
	putDebugWord(prefix, base.debugInterpreterGCField, 128)

	gc := make([]byte, inlineDebugGCSize)
	putDebugWord(gc, debugOffsets.GCSize, 256)
	putDebugWord(gc, debugOffsets.GCCollecting, base.gcGenerationStats+uint64(base.payloadSize))
	return prefix, gc
}

func putDebugWord(data []byte, offset int, value uint64) {
	binary.LittleEndian.PutUint64(data[offset:offset+8], value)
}
