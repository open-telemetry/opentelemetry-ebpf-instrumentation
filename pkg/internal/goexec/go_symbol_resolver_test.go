// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

//go:noinline
func goSymbolCaller() uintptr {
	pc, _, _, _ := runtime.Caller(0)
	return pc
}

func openGoSymbolResolver(t *testing.T, path string) *GoSymbolResolver {
	t.Helper()
	file, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })
	resolver, err := NewGoSymbolResolver(file)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resolver.Close() })
	return resolver
}

func TestGoSymbolResolverMatchesRuntime(t *testing.T) {
	pc := goSymbolCaller()
	want, _ := runtime.CallersFrames([]uintptr{pc}).Next()
	executable, err := os.Executable()
	require.NoError(t, err)
	resolver := openGoSymbolResolver(t, executable)

	for range 2 {
		frame, ok := resolver.PCToFrame(uint64(pc - 1))
		require.True(t, ok)
		require.Equal(t, GoFrame{Function: want.Function, File: want.File, Line: want.Line}, frame)
		resolver.SetDontNeed()
	}
	_, ok := resolver.PCToFrame(0)
	require.False(t, ok)
}

func TestGoSymbolResolverFramesOutliveClose(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	file, err := os.Open(executable)
	require.NoError(t, err)
	defer file.Close()
	resolver, err := NewGoSymbolResolver(file)
	require.NoError(t, err)

	frame, ok := resolver.PCToFrame(uint64(goSymbolCaller()))
	require.True(t, ok)
	require.NoError(t, resolver.Close())
	require.NoError(t, resolver.Close())

	require.Contains(t, frame.Function, "goSymbolCaller")
	require.Contains(t, frame.File, "go_symbol_resolver_test.go")
	_, ok = resolver.PCToFrame(uint64(goSymbolCaller()))
	require.False(t, ok)
}

func TestGoSymbolResolverTruncatedExecutable(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	source, err := os.Open(executable)
	require.NoError(t, err)
	defer source.Close()
	// Map an unexecuted copy so executable write protection cannot prevent truncation.
	path := filepath.Join(t.TempDir(), "truncated-elf")
	destination, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = io.Copy(destination, source)
	require.NoError(t, err)
	require.NoError(t, destination.Close())

	resolver := openGoSymbolResolver(t, path)
	pc := uint64(goSymbolCaller())
	_, ok := resolver.PCToFrame(pc)
	require.True(t, ok)
	resolver.SetDontNeed()
	require.NoError(t, os.Truncate(path, 0))

	_, ok = resolver.PCToFrame(pc)
	require.False(t, ok)
}
