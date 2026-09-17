// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package goexec

import (
	"debug/elf"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveRuntimeMetricGlobalsStripped(t *testing.T) {
	objcopy, err := exec.LookPath("objcopy")
	require.NoError(t, err)
	for _, build := range []struct {
		name, mode, cgo, ldflags string
	}{
		{"exe", "exe", "0", ""},
		{"pie", "pie", "0", ""},
		{"external-pie", "pie", "1", "-linkmode=external"},
	} {
		t.Run(build.name, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "main.go")
			original := filepath.Join(dir, "original")
			stripped := filepath.Join(dir, "stripped")
			require.NoError(t, os.WriteFile(source, []byte("package main\nfunc main() {}\n"), 0o600))
			command := exec.Command("go", "build", "-buildmode="+build.mode, "-ldflags="+build.ldflags, "-o", original, source)
			command.Env = append(os.Environ(), "CGO_ENABLED="+build.cgo)
			output, err := command.CombinedOutput()
			require.NoError(t, err, "%s", output)

			oracle, err := elf.Open(original)
			require.NoError(t, err)
			t.Cleanup(func() { _ = oracle.Close() })
			symbols, err := oracle.Symbols()
			require.NoError(t, err)
			var want, wantMemstats uint64
			for _, symbol := range symbols {
				if symbol.Name == "runtime.gomaxprocs" {
					want = symbol.Value
				}
				if symbol.Name == "runtime.memstats" {
					wantMemstats = symbol.Value
				}
			}
			require.NotZero(t, want)
			require.NotZero(t, wantMemstats)

			// Strip a copy of the same link so the symbol oracle's addresses stay valid.
			output, err = exec.Command(objcopy, "--strip-all", original, stripped).CombinedOutput()
			require.NoError(t, err, "%s", output)
			f, err := elf.Open(stripped)
			require.NoError(t, err)
			t.Cleanup(func() { _ = f.Close() })
			_, err = f.Symbols()
			require.ErrorIs(t, err, elf.ErrNoSymbols)
			originalText, err := oracle.Section(".text").Data()
			require.NoError(t, err)
			strippedText, err := f.Section(".text").Data()
			require.NoError(t, err)
			require.Equal(t, originalText, strippedText)

			table, err := findGoSymbolTable(f)
			require.NoError(t, err)
			require.Nil(t, table.LookupFunc("runtime.GOMAXPROCS"))
			function := table.LookupFunc("runtime.procresize")
			require.NotNil(t, function)
			code, err := readVirtualMemoryWithFlags(f, function.Entry, function.End-function.Entry, elf.PF_X)
			require.NoError(t, err)
			address, err := resolveGOMAXPROCSFromCode(f, function.Entry, code)
			require.NoError(t, err)
			require.Equal(t, want, address)

			// Exercise the connected fallback and its conversion to a process address.
			// Other mandatory globals are still missing, so recovery reports an error.
			const loadBias = uint64(0x70000000)
			partial, err := resolveRuntimeMetricSymbols(f, loadBias)
			require.EqualError(t, err, "stripped Go runtime global address recovery is not implemented")
			require.Equal(t, want+loadBias, partial.GOMAXPROCSAddr)
			require.Equal(t, wantMemstats+loadBias, partial.MemstatsAddr)
			require.Zero(t, partial.GCControllerAddr)
			_, err = resolveRuntimeMetricSymbols(f, math.MaxUint64)
			require.EqualError(t, err, "gomaxprocs process address overflows")

			t.Run("linker-stripped", func(t *testing.T) {
				linkedPath := filepath.Join(dir, "linker-stripped")
				command := exec.Command("go", "build", "-buildmode="+build.mode, "-ldflags="+build.ldflags+" -s -w", "-o", linkedPath, source)
				command.Env = append(os.Environ(), "CGO_ENABLED="+build.cgo)
				output, err := command.CombinedOutput()
				require.NoError(t, err, "%s", output)
				linked, err := elf.Open(linkedPath)
				require.NoError(t, err)
				t.Cleanup(func() { _ = linked.Close() })
				_, err = linked.Symbols()
				require.ErrorIs(t, err, elf.ErrNoSymbols)
				table, err := findGoSymbolTable(linked)
				require.NoError(t, err)
				require.Nil(t, table.LookupFunc("runtime.GOMAXPROCS"))
				function := table.LookupFunc("runtime.procresize")
				require.NotNil(t, function)
				code, err := readVirtualMemoryWithFlags(linked, function.Entry, function.End-function.Entry, elf.PF_X)
				require.NoError(t, err)
				address, err := resolveGOMAXPROCSFromCode(linked, function.Entry, code)
				require.NoError(t, err)
				// This is a separate link: its layout can differ from the symbol oracle.
				// Exact-address verification is covered by the objcopy case above.
				require.NotZero(t, address)
				partial, err := resolveRuntimeMetricSymbols(linked, loadBias)
				require.EqualError(t, err, "stripped Go runtime global address recovery is not implemented")
				require.Greater(t, partial.MemstatsAddr, loadBias)
			})
		})
	}
}

func TestRuntimeMetricMemstatsBase(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		heapStats, offset, want uint64
		wantError               string
	}{
		{"first field", 0x2000, 0, 0x2000, ""},
		{"older layout", 0x2000 + 5960, 5960, 0x2000, ""},
		{"subtraction underflow", 0x2000, 0x2008, 0, "invalid memstats.heapStats field offset"},
		{"zero base", 0x2000, 0x2000, 0, "invalid memstats.heapStats field offset"},
		{"misaligned field", 0x2001, 0, 0, "invalid memstats.heapStats storage"},
		{"misaligned base", 0x2008, 1, 0, "invalid memstats storage"},
		{"base outside segment", 0x2000, 8, 0, "invalid memstats storage"},
		{"field at segment end", 0x4000, 0, 0, "invalid memstats.heapStats storage"},
		{"field fits exactly", 0x3ff8, 0, 0x3ff8, ""},
		{"address overflow", math.MaxUint64 - 7, 0, 0, "invalid memstats.heapStats storage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
				Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_W,
				Vaddr: 0x2000, Filesz: 0x100, Memsz: 0x2000,
			}}}}
			got, err := runtimeMetricMemstatsBase(f, tc.heapStats, tc.offset)
			if tc.wantError != "" {
				require.EqualError(t, err, tc.wantError)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.want, got)
		})
	}
}

func TestUniqueRuntimeMetricAddress(t *testing.T) {
	for _, tc := range []struct {
		name       string
		candidates []uint64
		want       uint64
		errorText  string
	}{
		{"missing", nil, 0, "runtime global address not found"},
		{"single", []uint64{0x2000}, 0x2000, ""},
		{"repeated", []uint64{0x2000, 0x2000}, 0x2000, ""},
		{"conflicting", []uint64{0x2000, 0x3000}, 0, "ambiguous runtime global address"},
		{"conflict after repeated", []uint64{0x2000, 0x2000, 0x3000}, 0, "ambiguous runtime global address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, err := uniqueRuntimeMetricAddress(tc.candidates)
			if tc.errorText != "" {
				require.EqualError(t, err, tc.errorText)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.want, address)
		})
	}
}

func TestRuntimeMetricWritableRange(t *testing.T) {
	const readWrite = elf.PF_R | elf.PF_W
	for _, tc := range []struct {
		name    string
		address uint64
		size    uint64
		flags   elf.ProgFlag
		want    bool
	}{
		{"segment start", 0x1000, 4, readWrite, true},
		{"BSS beyond file bytes", 0x1800, 4, readWrite, true},
		{"exact end", 0x1ffc, 4, readWrite, true},
		{"crosses end", 0x1ffe, 4, readWrite, false},
		{"at end", 0x2000, 4, readWrite, false},
		{"before start", 0xfff, 4, readWrite, false},
		{"empty range", 0x1000, 0, readWrite, false},
		{"read only", 0x1000, 4, elf.PF_R, false},
		{"write only", 0x1000, 4, elf.PF_W, false},
		{"address overflow", math.MaxUint64 - 1, 4, readWrite, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
				Type: elf.PT_LOAD, Flags: tc.flags,
				Vaddr: 0x1000, Filesz: 0x800, Memsz: 0x1000,
			}}}}
			require.Equal(t, tc.want, runtimeMetricWritableRange(f, tc.address, tc.size))
		})
	}

	t.Run("non-loadable segment", func(t *testing.T) {
		f := &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
			Type: elf.PT_NOTE, Flags: readWrite, Vaddr: 0x1000, Memsz: 0x1000,
		}}}}
		require.False(t, runtimeMetricWritableRange(f, 0x1000, 4))
	})
	t.Run("segment address overflow", func(t *testing.T) {
		f := &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
			Type: elf.PT_LOAD, Flags: readWrite, Vaddr: math.MaxUint64 - 7, Memsz: 16,
		}}}}
		require.False(t, runtimeMetricWritableRange(f, math.MaxUint64-7, 4))
	})
}
