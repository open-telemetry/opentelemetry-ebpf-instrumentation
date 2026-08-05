// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package goexec

import (
	"debug/elf"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"
)

//go:noinline
func clientSpanKindOption() trace.SpanStartOption {
	return trace.WithSpanKind(trace.SpanKindClient)
}

//go:noinline
func serverSpanKindOption() trace.SpanStartOption {
	return trace.WithSpanKind(trace.SpanKindServer)
}

//go:noinline
func newRootOption() trace.SpanStartOption {
	return trace.WithNewRoot()
}

func TestFunctionOffsetsContainingFindsInlinedSpanKindClosures(t *testing.T) {
	client := clientSpanKindOption()
	server := serverSpanKindOption()
	runtime.KeepAlive(client)
	runtime.KeepAlive(server)

	executable, err := os.Executable()
	require.NoError(t, err)
	elfFile, err := elf.Open(executable)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, elfFile.Close())
	})

	offsets, err := functionOffsetsContaining(elfFile, ".WithSpanKind.func")
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(offsets), 2)

	entries := make(map[uint64]struct{}, len(offsets))
	for _, offset := range offsets {
		assert.NotZero(t, offset.Entry)
		entries[offset.Entry] = struct{}{}
	}
	assert.Len(t, entries, len(offsets))
}

func TestFunctionOffsetsContainingFindsInlinedNewRootClosure(t *testing.T) {
	option := newRootOption()
	runtime.KeepAlive(option)

	executable, err := os.Executable()
	require.NoError(t, err)
	elfFile, err := elf.Open(executable)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, elfFile.Close())
	})

	offsets, err := functionOffsetsContaining(elfFile, ".WithNewRoot.func")
	require.NoError(t, err)
	require.NotEmpty(t, offsets)
	for _, offset := range offsets {
		assert.NotZero(t, offset.Entry)
	}
}
