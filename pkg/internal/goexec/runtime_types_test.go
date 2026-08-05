// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindGoAutoSDKTypeInfo(t *testing.T) {
	for name, elfFile := range map[string]*elf.File{
		"debug":    spanContextELF,
		"stripped": smallSpanContextELF,
		"pie":      pieSpanContextELF,
	} {
		t.Run(name, func(t *testing.T) {
			info, err := findGoAutoSDKTypeInfo(elfFile)
			require.NoError(t, err)
			require.True(t, info.Valid())
			assert.NotZero(t, info.TraceContextKeyType)
			assert.NotZero(t, info.NonRecordingSpanType)
			assert.NotZero(t, info.RecordingSpanType)
			assert.NotZero(t, info.AttributeOptionType)
			assert.NotZero(t, info.TimestampOptionType)
			assert.Equal(t, uint64(16), info.NonRecordingSpanContextPos)
			assert.NotZero(t, info.RecordingSpanContextPos)
			assert.Equal(t, uint64(0), info.SpanContextTraceIDPos)
			assert.Equal(t, uint64(16), info.SpanContextSpanIDPos)
			assert.Equal(t, uint64(24), info.SpanContextTraceFlagsPos)
			assert.Equal(t, uint64(56), info.SpanContextRemotePos)
		})
	}
}

func TestFindGoAutoSDKTypeInfoWithoutExternalParentTypes(t *testing.T) {
	info, err := findGoAutoSDKTypeInfo(minimalAutoSDKELF)
	require.NoError(t, err)
	require.True(t, info.Valid())
	assert.Zero(t, info.NonRecordingSpanType)
	assert.NotZero(t, info.AttributeOptionType)
	assert.NotZero(t, info.TimestampOptionType)
}

func TestGoAutoSDKTypeInfoValidAllowsZeroFieldOffsets(t *testing.T) {
	info := GoAutoSDKTypeInfo{
		TraceContextKeyType:  0x100,
		NonRecordingSpanType: 0x200,
		Resolved:             true,
	}

	assert.True(t, info.Valid())
}

func TestGoAutoSDKTypeInfoValidAllowsMissingExternalParentType(t *testing.T) {
	info := GoAutoSDKTypeInfo{
		TraceContextKeyType: 0x100,
		Resolved:            true,
	}

	assert.True(t, info.Valid())
}

func TestDecodeGoRuntimeStructFieldOffset(t *testing.T) {
	assert.Equal(t, uint64(16), decodeGoRuntimeStructFieldOffset(32, true))
	assert.Equal(t, uint64(32), decodeGoRuntimeStructFieldOffset(32, false))
}
