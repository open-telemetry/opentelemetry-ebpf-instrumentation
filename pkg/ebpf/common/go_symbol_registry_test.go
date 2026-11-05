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
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

func TestGoSymbolRegistrySharesExecutableTable(t *testing.T) {
	info := testGoExecutableInfo(t)
	registry := NewGoSymbolRegistry()
	t.Cleanup(func() { require.NoError(t, registry.Close()) })
	require.NoError(t, registry.AddExecutable(info))
	key := goExecutableID{device: info.Dev(), inode: info.Ino()}
	file := registry.executables[key].file
	require.NoError(t, registry.AddExecutable(info))
	registry.BindPID(101, info.Dev(), info.Ino(), 0)
	registry.BindPID(202, info.Dev(), info.Ino(), 0)

	require.Len(t, registry.executables, 1)
	require.Len(t, registry.pids, 2)
	assert.Nil(t, registry.executables[key].resolver)
	assert.Same(t, file, registry.executables[key].file)
}

func TestGoSymbolRegistryUsesPerProcessLoadBias(t *testing.T) {
	table, fn := testGoSymbolTable(t)
	registry := NewGoSymbolRegistry()
	const (
		firstBias  = uint64(0x7f0000000000)
		secondBias = uint64(0x6e0000000000)
	)

	registerGoSymbols(t, registry, 101, testGoSymbolResolver{table})
	registry.BindPID(101, 7, 11, firstBias)
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

	registerGoSymbols(t, registry, 101, testGoSymbolResolver{table})
	registry.BindPID(101, 7, 11, firstBias)
	registry.BindPID(101, 7, 11, secondBias)
	stack, err := stackText(registry, 101, []uint64{fn.Entry + secondBias + 1})
	require.NoError(t, err)

	assert.Equal(t, expectedFrame(t, table, fn.Entry), stack)
	require.Len(t, registry.pids, 1)
}

func TestGoSymbolRegistryOpenFailureAddsNoExecutable(t *testing.T) {
	registry := NewGoSymbolRegistry()

	err := registry.AddExecutable(exec.New(exec.Init{ProExeLinkPath: "/does-not-exist", Dev: 8, Ino: 12}))
	registry.BindPID(101, 8, 12, 0)

	require.ErrorIs(t, err, os.ErrNotExist)
	_, lookupErr := stackText(registry, 101, nil)
	require.Error(t, lookupErr)
	assert.Empty(t, registry.executables)
}

func TestGoSymbolRegistryRemovePIDUsesExactHostPID(t *testing.T) {
	table, _ := testGoSymbolTable(t)
	registry := NewGoSymbolRegistry()
	registerGoSymbols(t, registry, 101, testGoSymbolResolver{table})
	registerGoSymbols(t, registry, 202, testGoSymbolResolver{table})

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
	registerGoSymbols(t, registry, 101, testGoSymbolResolver{table})

	registry.RemoveExecutable(7, 11)

	assert.Empty(t, registry.executables)
	_, err := stackText(registry, 101, nil)
	require.Error(t, err)
	registry.RemoveExecutable(7, 11)
}

func TestGoSymbolRegistryRetainsResolvedFramesBeforeUnknownPC(t *testing.T) {
	table, fn := testGoSymbolTable(t)
	registry := NewGoSymbolRegistry()
	registerGoSymbols(t, registry, 101, testGoSymbolResolver{table})

	stack, err := stackText(registry, 101, []uint64{fn.Entry + 1, math.MaxUint64})

	require.NoError(t, err)
	assert.Equal(t, expectedFrame(t, table, fn.Entry), stack)
}

func TestGoSymbolRegistryStopsAtZeroOrLoadBiasUnderflow(t *testing.T) {
	table, fn := testGoSymbolTable(t)
	registry := NewGoSymbolRegistry()
	const bias = uint64(0x7f0000000000)
	registerGoSymbols(t, registry, 101, testGoSymbolResolver{table})
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
		4:  {Function: "fmt.Errorf", File: "fmt/errors.go", Line: 26},
		9:  {Function: "runtime.panicmem", File: "runtime/panic.go", Line: 262},
		19: {Function: "runtime.sigpanic", File: "runtime/signal_unix.go", Line: 917},
		30: {Function: "main.(*store).Name", File: "main.go", Line: 12},
		39: {Function: "main.handler", File: "main.go", Line: 20},
	}
	registerGoSymbols(t, registry, 1, resolver)

	stack, err := stackText(registry, 1, []uint64{5, 10, 20, 30, 40})
	require.NoError(t, err)
	assert.Equal(t, "runtime.panicmem\n\truntime/panic.go:262\n"+
		"runtime.sigpanic\n\truntime/signal_unix.go:917\n"+
		"main.(*store).Name\n\tmain.go:12\n"+
		"main.handler\n\tmain.go:20", stack)
}

type mapSymbolResolver map[uint64]goexec.GoFrame

func (r mapSymbolResolver) PCToFrame(pc uint64) (goexec.GoFrame, bool) {
	frame, ok := r[pc]
	return frame, ok
}

func (mapSymbolResolver) ValueType(uint64) (goexec.GoValueType, bool) {
	return goexec.GoValueType{}, false
}

func (mapSymbolResolver) ReadOnlyData(uint64, uint64) ([]byte, bool) {
	return nil, false
}

func (mapSymbolResolver) SetDontNeed() {}
func (mapSymbolResolver) Close() error { return nil }

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

type testGoSymbolResolver struct{ table *gosym.Table }

func (r testGoSymbolResolver) PCToFrame(pc uint64) (goexec.GoFrame, bool) {
	file, line, function := r.table.PCToLine(pc)
	if function == nil || file == "" || line <= 0 {
		return goexec.GoFrame{}, false
	}
	return goexec.GoFrame{Function: function.Name, File: file, Line: line}, true
}

func (testGoSymbolResolver) ValueType(uint64) (goexec.GoValueType, bool) {
	return goexec.GoValueType{}, false
}

func (testGoSymbolResolver) ReadOnlyData(uint64, uint64) ([]byte, bool) {
	return nil, false
}

func (testGoSymbolResolver) SetDontNeed() {}

func (testGoSymbolResolver) Close() error { return nil }

func testGoExecutableInfo(t *testing.T) *exec.FileInfo {
	t.Helper()
	path, err := os.Executable()
	require.NoError(t, err)
	return testGoFileInfo(t, path)
}

func testGoFileInfo(t *testing.T, path string) *exec.FileInfo {
	t.Helper()
	stat, err := os.Stat(path)
	require.NoError(t, err)
	identity := stat.Sys().(*syscall.Stat_t)
	return exec.New(exec.Init{ProExeLinkPath: path, Dev: identity.Dev, Ino: identity.Ino})
}

//go:noinline
func goSymbolRegistryFixture() {}
