// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpfcommon

import (
	"debug/elf"
	"debug/gosym"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

func TestGoSymbolRegistrySharesExecutableTable(t *testing.T) {
	table, _ := testGoSymbolTable(t)
	registry := NewGoSymbolRegistry()
	loadCalls := 0
	load := func() (GoSymbolSource, error) {
		loadCalls++
		return testGoSymbolSource(table), nil
	}

	registerGoSymbols(t, registry, 101, load)
	registerGoSymbols(t, registry, 202, load)

	key := goExecutableID{device: 7, inode: 11}
	require.Len(t, registry.executables, 1)
	require.Len(t, registry.pids, 2)
	assert.Nil(t, registry.executables[key].resolver)
	assert.Equal(t, 1, loadCalls)
}

func TestGoSymbolRegistryUsesPerProcessLoadBias(t *testing.T) {
	table, fn := testGoSymbolTable(t)
	registry := NewGoSymbolRegistry()
	const (
		firstBias  = uint64(0x7f0000000000)
		secondBias = uint64(0x6e0000000000)
	)

	require.NoError(t, registry.AddExecutable(7, 11, symbolTableLoader(table)))
	registry.BindPID(101, 7, 11, firstBias)
	require.NoError(t, registry.AddExecutable(7, 11, symbolTableLoader(table)))
	registry.BindPID(202, 7, 11, secondBias)

	first, err := stackText(registry, 101, []uint64{fn.Entry + firstBias + 1})
	require.NoError(t, err)
	second, err := stackText(registry, 202, []uint64{fn.Entry + secondBias + 1})
	require.NoError(t, err)

	assert.Equal(t, expectedFrame(t, table, fn.Entry), first)
	assert.Equal(t, first, second)
}

func TestGoSymbolRegistryRebindingPIDUpdatesLoadBias(t *testing.T) {
	table, fn := testGoSymbolTable(t)
	registry := NewGoSymbolRegistry()
	const (
		firstBias  = uint64(0x7f0000000000)
		secondBias = uint64(0x6e0000000000)
	)

	require.NoError(t, registry.AddExecutable(7, 11, symbolTableLoader(table)))
	registry.BindPID(101, 7, 11, firstBias)
	registry.BindPID(101, 7, 11, secondBias)
	stack, err := stackText(registry, 101, []uint64{fn.Entry + secondBias + 1})
	require.NoError(t, err)

	assert.Equal(t, expectedFrame(t, table, fn.Entry), stack)
	require.Len(t, registry.pids, 1)
}

func TestGoSymbolRegistryOpenFailureAddsNoExecutable(t *testing.T) {
	registry := NewGoSymbolRegistry()

	err := registry.AddExecutable(8, 12, func() (GoSymbolSource, error) {
		return GoSymbolSource{}, assert.AnError
	})
	registry.BindPID(101, 8, 12, 0)

	require.ErrorIs(t, err, assert.AnError)
	_, lookupErr := stackText(registry, 101, nil)
	require.Error(t, lookupErr)
	assert.Empty(t, registry.executables)
}

func TestGoSymbolRegistryRemovePIDUsesExactHostPID(t *testing.T) {
	table, _ := testGoSymbolTable(t)
	registry := NewGoSymbolRegistry()
	registerGoSymbols(t, registry, 101, symbolTableLoader(table))
	registerGoSymbols(t, registry, 202, symbolTableLoader(table))

	registry.RemovePID(101)

	_, firstErr := stackText(registry, 101, nil)
	_, secondErr := stackText(registry, 202, nil)
	require.Error(t, firstErr)
	require.NoError(t, secondErr)
	assert.Len(t, registry.executables, 1)
}

func TestGoSymbolRegistryRemoveExecutable(t *testing.T) {
	table, _ := testGoSymbolTable(t)
	registry := NewGoSymbolRegistry()
	registerGoSymbols(t, registry, 101, symbolTableLoader(table))

	registry.RemoveExecutable(7, 11)

	assert.Empty(t, registry.executables)
	_, err := stackText(registry, 101, nil)
	require.Error(t, err)
	registry.RemoveExecutable(7, 11)
}

func TestGoSymbolRegistryRetainsResolvedFramesBeforeUnknownPC(t *testing.T) {
	table, fn := testGoSymbolTable(t)
	registry := NewGoSymbolRegistry()
	registerGoSymbols(t, registry, 101, symbolTableLoader(table))

	stack, err := stackText(registry, 101, []uint64{fn.Entry + 1, math.MaxUint64})

	require.NoError(t, err)
	assert.Equal(t, expectedFrame(t, table, fn.Entry), stack)
}

func TestGoSymbolRegistryStopsAtZeroOrLoadBiasUnderflow(t *testing.T) {
	table, fn := testGoSymbolTable(t)
	registry := NewGoSymbolRegistry()
	const bias = uint64(0x7f0000000000)
	require.NoError(t, registry.AddExecutable(7, 11, symbolTableLoader(table)))
	registry.BindPID(101, 7, 11, bias)

	stack, err := stackText(registry, 101, []uint64{0, fn.Entry + bias + 1})
	require.NoError(t, err)
	assert.Empty(t, stack)

	stack, err = stackText(registry, 101, []uint64{bias})
	require.NoError(t, err)
	assert.Empty(t, stack)
}

func TestGoSymbolRegistryResolvesFaultingPCAfterSigpanic(t *testing.T) {
	registry := NewGoSymbolRegistry()
	defer registry.Close()
	// 30 is the first byte of the faulting function: 29 belongs to no function
	resolver := mapSymbolResolver{
		9:  {Function: "runtime.panicmem", File: "runtime/panic.go", Line: 262},
		19: {Function: "runtime.sigpanic", File: "runtime/signal_unix.go", Line: 917},
		30: {Function: "main.(*store).Name", File: "main.go", Line: 12},
		39: {Function: "main.handler", File: "main.go", Line: 20},
	}
	registerGoSymbols(t, registry, 1, func() (GoSymbolSource, error) {
		return GoSymbolSource{Open: func() (GoSymbolResolver, error) { return resolver, nil }, Close: func() error { return nil }}, nil
	})

	stack, err := stackText(registry, 1, []uint64{10, 20, 30, 40})
	require.NoError(t, err)
	assert.Equal(t, "runtime.panicmem\n\truntime/panic.go:262\n"+
		"runtime.sigpanic\n\truntime/signal_unix.go:917\n"+
		"main.(*store).Name\n\tmain.go:12\n"+
		"main.handler\n\tmain.go:20", stack)
}

func testGoSymbolTable(t *testing.T) (*gosym.Table, *gosym.Func) {
	t.Helper()

	goSymbolRegistryFixture()
	executable, err := os.Executable()
	require.NoError(t, err)
	elfFile, err := elf.Open(executable)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, elfFile.Close()) })

	pcln := elfFile.Section(".gopclntab")
	require.NotNil(t, pcln)
	data, err := pcln.Data()
	require.NoError(t, err)
	table, err := gosym.NewTable(nil, gosym.NewLineTable(data, elfFile.Section(".text").Addr))
	require.NoError(t, err)
	for i := range table.Funcs {
		if strings.HasSuffix(table.Funcs[i].Name, ".goSymbolRegistryFixture") {
			return table, &table.Funcs[i]
		}
	}
	t.Fatal("Go symbol fixture function was not found")
	return nil, nil
}

func expectedFrame(t *testing.T, table *gosym.Table, pc uint64) string {
	t.Helper()

	file, line, fn := table.PCToLine(pc)
	require.NotNil(t, fn)
	require.NotEmpty(t, file)
	require.Positive(t, line)
	return fmt.Sprintf("%s\n\t%s:%d", fn.Name, file, line)
}

func symbolTableLoader(table *gosym.Table) func() (GoSymbolSource, error) {
	return func() (GoSymbolSource, error) { return testGoSymbolSource(table), nil }
}

type testGoSymbolResolver struct{ table *gosym.Table }

func (r testGoSymbolResolver) PCToFrame(pc uint64) (goexec.GoFrame, bool) {
	file, line, function := r.table.PCToLine(pc)
	if function == nil || file == "" || line <= 0 {
		return goexec.GoFrame{}, false
	}
	return goexec.GoFrame{Function: function.Name, File: file, Line: line}, true
}

func (testGoSymbolResolver) SetDontNeed() {}

func (testGoSymbolResolver) Close() error { return nil }

func testGoSymbolSource(table *gosym.Table) GoSymbolSource {
	return GoSymbolSource{
		Open:  func() (GoSymbolResolver, error) { return testGoSymbolResolver{table}, nil },
		Close: func() error { return nil },
	}
}

//go:noinline
func goSymbolRegistryFixture() {}
