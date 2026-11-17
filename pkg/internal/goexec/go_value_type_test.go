// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"testing"
	"unsafe"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/stretchr/testify/require"
)

func TestValueTypeNilPointer(t *testing.T) {
	var value any
	func() {
		defer func() { value = recover() }()
		var p *int
		_ = *p //nolint:govet // Exercises the runtime nil-pointer panic path.
	}()

	panicError, ok := value.(error)
	require.True(t, ok)
	require.Equal(t, "runtime error: invalid memory address or nil pointer dereference", panicError.Error())

	// An empty interface holds the type pointer followed by the data pointer.
	words := *(*[2]uintptr)(unsafe.Pointer(&value))
	typeAddr := uint64(words[0])
	require.NotZero(t, typeAddr)

	executable, err := os.Executable()
	require.NoError(t, err)
	resolver := openGoSymbolResolver(t, executable)
	typ, ok := resolver.ValueType(typeAddr)
	require.True(t, ok)
	require.Equal(t, uint8(reflect.String), typ.Kind)
	require.True(t, typ.Methods)
	require.Equal(t, "runtime.errorString.Error", typ.ErrorFunc)
	require.Equal(t, runtime.Version(), typ.GoVersion)

	message := reflect.ValueOf(value).String()
	messageAddr := uint64(uintptr(unsafe.Pointer(unsafe.StringData(message))))
	data, ok := resolver.ReadOnlyData(messageAddr, uint64(len(message)))
	runtime.KeepAlive(value)
	require.True(t, ok)
	require.Equal(t, "invalid memory address or nil pointer dereference", string(data))
}

func TestValueTypeMappedFileFault(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "mapped"))
	require.NoError(t, err)
	defer file.Close()
	require.NoError(t, file.Truncate(int64(os.Getpagesize())))
	data, err := syscall.Mmap(int(file.Fd()), 0, os.Getpagesize(), syscall.PROT_READ, syscall.MAP_SHARED)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, syscall.Munmap(data)) })
	require.NoError(t, file.Truncate(0))

	var value any
	func() {
		previous := debug.SetPanicOnFault(true)
		defer debug.SetPanicOnFault(previous)
		defer func() { value = recover() }()
		panic(data[0])
	}()
	require.NotNil(t, value)
	executable, err := os.Executable()
	require.NoError(t, err)
	resolver := openGoSymbolResolver(t, executable)
	words := *(*[2]uintptr)(unsafe.Pointer(&value))
	typ, ok := resolver.ValueType(uint64(words[0]))
	runtime.KeepAlive(value)
	require.True(t, ok)
	require.Equal(t, uint8(reflect.Struct), typ.Kind)
	require.Equal(t, "runtime.errorAddressString.Error", typ.ErrorFunc)
}

var readOnlyDataWritableFixture = uint64(42)

func TestReadOnlyDataRejectsWritableData(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	resolver := openGoSymbolResolver(t, executable)
	addr := uint64(uintptr(unsafe.Pointer(&readOnlyDataWritableFixture)))
	size := uint64(unsafe.Sizeof(readOnlyDataWritableFixture))

	// Confirm the bytes are file-backed before checking their permissions.
	_, err = readVirtualMemory(resolver.executable, addr, size)
	require.NoError(t, err)
	data, ok := resolver.ReadOnlyData(addr, size)
	require.False(t, ok)
	require.Nil(t, data)
}

func TestValueTypePredeclared(t *testing.T) {
	type Count int
	executable, err := os.Executable()
	require.NoError(t, err)
	resolver := openGoSymbolResolver(t, executable)

	for _, tc := range []struct {
		name        string
		value       any
		predeclared bool
	}{
		{name: "int", value: 42, predeclared: true},
		{name: "int8", value: int8(-128), predeclared: true},
		{name: "int16", value: int16(-32768), predeclared: true},
		{name: "int32", value: int32(-1 << 31), predeclared: true},
		{name: "int64", value: int64(-1 << 63), predeclared: true},
		{name: "uint", value: uint(42), predeclared: true},
		{name: "uint8", value: uint8(255), predeclared: true},
		{name: "uint16", value: uint16(65535), predeclared: true},
		{name: "uint32", value: uint32(1<<32 - 1), predeclared: true},
		{name: "uint64", value: ^uint64(0), predeclared: true},
		{name: "uintptr", value: uintptr(42), predeclared: true},
		{name: "bool", value: true, predeclared: true},
		{name: "Count", value: Count(42), predeclared: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			words := *(*[2]uintptr)(unsafe.Pointer(&tc.value))
			typ, ok := resolver.ValueType(uint64(words[0]))
			require.True(t, ok)
			require.Equal(t, uint8(reflect.TypeOf(tc.value).Kind()), typ.Kind)
			require.Equal(t, tc.predeclared, typ.Predeclared)
			require.False(t, typ.Methods)
			require.Empty(t, typ.ErrorFunc)
		})
	}
}

func TestValueTypeErrorLayouts(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)
	resolver := openGoSymbolResolver(t, executable)

	for _, tc := range []struct {
		name      string
		trigger   func()
		kind      reflect.Kind
		errorFunc string
	}{
		{
			name: "nil channel",
			trigger: func() {
				var ch chan int
				close(ch)
			},
			kind:      reflect.String,
			errorFunc: "runtime.plainError.Error",
		},
		{
			name: "bounds error",
			trigger: func() {
				var values []int
				_ = values[0] //nolint:govet // Exercises the runtime bounds-error panic path.
			},
			kind:      reflect.Struct,
			errorFunc: "runtime.boundsError.Error",
		},
		{
			name:      "errors.New",
			trigger:   func() { panic(errors.New("boom")) },
			kind:      reflect.Pointer,
			errorFunc: "errors.(*errorString).Error",
		},
		{
			name:      "fmt.Errorf single wrapper",
			trigger:   func() { panic(fmt.Errorf("failed: %w", errors.New("boom"))) },
			kind:      reflect.Pointer,
			errorFunc: "fmt.(*wrapError).Error",
		},
		{
			name:      "fmt.Errorf multiple wrappers",
			trigger:   func() { panic(fmt.Errorf("%w and %w", errors.New("first"), errors.New("second"))) },
			kind:      reflect.Pointer,
			errorFunc: "fmt.(*wrapErrors).Error",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var value any
			func() {
				defer func() { value = recover() }()
				tc.trigger()
			}()
			require.NotNil(t, value)
			words := *(*[2]uintptr)(unsafe.Pointer(&value))
			typ, ok := resolver.ValueType(uint64(words[0]))
			require.True(t, ok)
			require.Equal(t, uint8(tc.kind), typ.Kind)
			require.True(t, typ.Methods)
			require.Equal(t, tc.errorFunc, typ.ErrorFunc)
		})
	}
}

func TestValueTypeCache(t *testing.T) {
	path, err := os.Executable()
	require.NoError(t, err)
	file, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })
	resolver, err := NewGoSymbolResolver(file)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resolver.Close() })
	// A small capacity exercises eviction with real executable-backed types.
	resolver.valueTypes, err = simplelru.NewLRU[uint64, GoValueType](2, nil)
	require.NoError(t, err)
	values := []any{5, true, errors.New("boom")}
	addresses := make([]uint64, len(values))
	for i := range values {
		addresses[i] = uint64((*[2]uintptr)(unsafe.Pointer(&values[i]))[0])
		_, ok := resolver.ValueType(addresses[i])
		require.True(t, ok)
	}
	require.Equal(t, 2, resolver.valueTypes.Len())
	require.False(t, resolver.valueTypes.Contains(addresses[0]))
	want, ok := resolver.ValueType(addresses[2])
	require.True(t, ok)
	_, ok = resolver.ValueType(0)
	require.False(t, ok)
	require.Equal(t, 2, resolver.valueTypes.Len())

	// Cached metadata remains usable without further executable reads.
	require.NoError(t, file.Close())
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				got, found := resolver.ValueType(addresses[2])
				if !found || got != want {
					t.Error("cached metadata differs")
				}
			}
		})
	}
	workers.Wait()
	// An evicted type needs a fresh read, which fails on the closed descriptor.
	_, ok = resolver.ValueType(addresses[0])
	require.False(t, ok)
	require.NoError(t, resolver.Close())
	require.Nil(t, resolver.valueTypes)
	_, ok = resolver.ValueType(addresses[2])
	require.False(t, ok)
	runtime.KeepAlive(values)
}
