// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package goexec

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRuntimeMetricValidSizeClassTable(t *testing.T) {
	// The runtime's table includes a reserved zero followed by allocation sizes.
	sizes := []uint16{
		0, 8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176,
		192, 208, 224, 240, 256, 288, 320, 352, 384, 416, 448, 480, 512, 576, 640,
		704, 768, 896, 1024, 1152, 1280, 1408, 1536, 1792, 2048, 2304, 2688,
		3072, 3200, 3456, 4096, 4864, 5376, 6144, 6528, 6784, 6912, 8192,
		9472, 9728, 10240, 10880, 12288, 13568, 14336, 16384, 18432, 19072,
		20480, 21760, 24576, 27264, 28672, 32768,
	}
	const tableAddress = uint64(0x2000)
	for _, tc := range []struct {
		name     string
		index    int
		value    uint16
		address  uint64
		fileSize uint64
		flags    elf.ProgFlag
		want     bool
	}{
		{"valid", -1, 0, tableAddress, 136, elf.PF_R, true},
		{"valid writable", -1, 0, tableAddress, 136, elf.PF_R | elf.PF_W, true},
		{"nonzero reserved entry", 0, 8, tableAddress, 136, elf.PF_R, false},
		{"wrong first size", 1, 16, tableAddress, 136, elf.PF_R, false},
		{"duplicate size", 8, 80, tableAddress, 136, elf.PF_R, false},
		{"decreasing size", 8, 64, tableAddress, 136, elf.PF_R, false},
		{"unaligned size", 8, 97, tableAddress, 136, elf.PF_R, false},
		{"wrong last size", 67, 32760, tableAddress, 136, elf.PF_R, false},
		{"truncated table", -1, 0, tableAddress, 135, elf.PF_R, false},
		{"zero-filled storage", -1, 0, tableAddress, 0, elf.PF_R, false},
		{"unreadable storage", -1, 0, tableAddress, 136, elf.PF_W, false},
		{"zero address", -1, 0, 0, 136, elf.PF_R, false},
		{"misaligned address", -1, 0, tableAddress + 1, 136, elf.PF_R, false},
		{"address before segment", -1, 0, tableAddress - 2, 136, elf.PF_R, false},
		{"address overflow", -1, 0, math.MaxUint64 - 1, 136, elf.PF_R, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, len(sizes)*2)
			for index, size := range sizes {
				binary.LittleEndian.PutUint16(data[index*2:], size)
			}
			if tc.index >= 0 {
				binary.LittleEndian.PutUint16(data[tc.index*2:], tc.value)
			}
			f := &elf.File{
				FileHeader: elf.FileHeader{ByteOrder: binary.LittleEndian},
				Progs: []*elf.Prog{{
					ProgHeader: elf.ProgHeader{
						Type: elf.PT_LOAD, Flags: tc.flags, Vaddr: tableAddress,
						Filesz: tc.fileSize, Memsz: uint64(len(data)),
					},
					ReaderAt: bytes.NewReader(data),
				}},
			}
			require.Equal(t, tc.want, runtimeMetricValidSizeClassTable(f, tc.address))
		})
	}
}

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
			var want, wantMemstats, wantGCController, wantWork, wantSizeClasses, wantSched, wantAllgLen uint64
			for _, symbol := range symbols {
				if symbol.Name == "runtime.gomaxprocs" {
					want = symbol.Value
				}
				if symbol.Name == "runtime.memstats" {
					wantMemstats = symbol.Value
				}
				if symbol.Name == "runtime.gcController" {
					wantGCController = symbol.Value
				}
				if symbol.Name == "runtime.work" {
					wantWork = symbol.Value
				}
				if symbol.Name == runtimeMetricSizeClassToSizesSymbol || symbol.Name == runtimeMetricInternalSizeClassToSizesSymbol {
					wantSizeClasses = symbol.Value
				}
				if symbol.Name == runtimeMetricSchedSymbol {
					wantSched = symbol.Value
				}
				if symbol.Name == runtimeMetricAllgLenSymbol {
					wantAllgLen = symbol.Value
				}
			}
			require.NotZero(t, want)
			require.NotZero(t, wantMemstats)
			require.NotZero(t, wantGCController)
			require.NotZero(t, wantWork)
			require.NotZero(t, wantSizeClasses)
			require.NotZero(t, wantSched)
			require.NotZero(t, wantAllgLen)

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
			sizeClassAddress, err := resolveRuntimeMetricSizeClassTableFromCode(f, table)
			require.NoError(t, err)
			require.Equal(t, wantSizeClasses, sizeClassAddress)
			schedAddress, err := resolveRuntimeMetricSchedFromCode(f, table)
			require.NoError(t, err)
			require.Equal(t, wantSched, schedAddress)
			allgLenAddress, err := resolveRuntimeMetricAllgLen(f, table)
			require.NoError(t, err)
			require.Equal(t, wantAllgLen, allgLenAddress)

			// Exercise the connected fallback and its conversion to a process address.
			const loadBias = uint64(0x70000000)
			recovered, err := resolveRuntimeMetricSymbols(f, loadBias)
			require.NoError(t, err)
			require.Equal(t, want+loadBias, recovered.GOMAXPROCSAddr)
			require.Equal(t, wantMemstats+loadBias, recovered.MemstatsAddr)
			require.Equal(t, wantGCController+loadBias, recovered.GCControllerAddr)
			require.Equal(t, wantWork+loadBias, recovered.WorkAddr)
			require.Equal(t, wantSizeClasses+loadBias, recovered.SizeClassToSizesAddr)
			require.Equal(t, wantSched+loadBias, recovered.SchedAddr)
			require.Equal(t, wantAllgLen+loadBias, recovered.AllgLenAddr)
			_, err = resolveRuntimeMetricSymbols(f, math.MaxUint64)
			require.EqualError(t, err, "gomaxprocs process address overflows")

			t.Run("missing-allglen-anchor", func(t *testing.T) {
				data, err := os.ReadFile(stripped)
				require.NoError(t, err)
				name := []byte("runtime.allgadd\x00")
				require.True(t, bytes.Contains(data, name))
				data = bytes.ReplaceAll(data, name, []byte("missing.allgadd\x00"))
				missing, err := elf.NewFile(bytes.NewReader(data))
				require.NoError(t, err)
				t.Cleanup(func() { _ = missing.Close() })
				got, err := resolveRuntimeMetricSymbols(missing, loadBias)
				require.NoError(t, err)
				want := recovered
				want.AllgLenAddr = 0
				require.Equal(t, want, got)
			})

			t.Run("missing-scheduler-anchor", func(t *testing.T) {
				data, err := os.ReadFile(stripped)
				require.NoError(t, err)
				name := []byte("runtime.oneNewExtraM\x00")
				require.True(t, bytes.Contains(data, name))
				data = bytes.ReplaceAll(data, name, []byte("missing.oneNewExtraM\x00"))
				missing, err := elf.NewFile(bytes.NewReader(data))
				require.NoError(t, err)
				t.Cleanup(func() { _ = missing.Close() })
				got, err := resolveRuntimeMetricSymbols(missing, loadBias)
				require.NoError(t, err)
				require.Zero(t, got.SchedAddr)
				require.Equal(t, recovered.GOMAXPROCSAddr, got.GOMAXPROCSAddr)
				require.Equal(t, recovered.MemstatsAddr, got.MemstatsAddr)
				require.Equal(t, recovered.GCControllerAddr, got.GCControllerAddr)
				require.Equal(t, recovered.WorkAddr, got.WorkAddr)
				require.Equal(t, recovered.SizeClassToSizesAddr, got.SizeClassToSizesAddr)
			})

			t.Run("missing-size-class-anchors", func(t *testing.T) {
				data, err := os.ReadFile(stripped)
				require.NoError(t, err)
				// Keep metadata lengths and addresses intact while hiding both anchors.
				for _, name := range []string{"runtime.mallocgc", "runtime.lockVerifyMSize"} {
					originalName := []byte(name + "\x00")
					if table.LookupFunc(name) != nil {
						require.True(t, bytes.Contains(data, originalName))
					}
					data = bytes.ReplaceAll(data, originalName, []byte("missing"+name[len("runtime"):]+"\x00"))
				}
				missing, err := elf.NewFile(bytes.NewReader(data))
				require.NoError(t, err)
				t.Cleanup(func() { _ = missing.Close() })
				got, err := resolveRuntimeMetricSymbols(missing, loadBias)
				require.NoError(t, err)
				require.Zero(t, got.SizeClassToSizesAddr)
				require.Equal(t, recovered.GOMAXPROCSAddr, got.GOMAXPROCSAddr)
				require.Equal(t, recovered.MemstatsAddr, got.MemstatsAddr)
				require.Equal(t, recovered.GCControllerAddr, got.GCControllerAddr)
				require.Equal(t, recovered.WorkAddr, got.WorkAddr)
			})

			t.Run("missing-work-anchor", func(t *testing.T) {
				data, err := os.ReadFile(stripped)
				require.NoError(t, err)
				// Rename only the metadata name, preserving its length and all addresses.
				name := []byte("runtime.putfull\x00")
				require.True(t, bytes.Contains(data, name))
				data = bytes.ReplaceAll(data, name, []byte("runtime.no_full\x00"))
				missing, err := elf.NewFile(bytes.NewReader(data))
				require.NoError(t, err)
				t.Cleanup(func() { _ = missing.Close() })
				got, err := resolveRuntimeMetricSymbols(missing, loadBias)
				require.NoError(t, err)
				require.Zero(t, got.WorkAddr)
				require.Equal(t, recovered.GOMAXPROCSAddr, got.GOMAXPROCSAddr)
				require.Equal(t, recovered.MemstatsAddr, got.MemstatsAddr)
				require.Equal(t, recovered.GCControllerAddr, got.GCControllerAddr)
			})

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
				recovered, err := resolveRuntimeMetricSymbols(linked, loadBias)
				require.NoError(t, err)
				require.Equal(t, address+loadBias, recovered.GOMAXPROCSAddr)
				require.Greater(t, recovered.MemstatsAddr, loadBias)
				require.Greater(t, recovered.GCControllerAddr, loadBias)
				require.Greater(t, recovered.WorkAddr, loadBias)
				require.Greater(t, recovered.SizeClassToSizesAddr, loadBias)
				require.Greater(t, recovered.SchedAddr, loadBias)
				require.Greater(t, recovered.AllgLenAddr, loadBias)
			})
		})
	}
}

func TestRuntimeMetricSchedBase(t *testing.T) {
	for _, tc := range []struct {
		name                string
		field, offset, want uint64
		wantError           string
	}{
		{"first field", 0x2000, 0, 0x2000, ""},
		{"nonzero offset", 0x2010, 16, 0x2000, ""},
		{"subtraction underflow", 0x2000, 0x2008, 0, "invalid sched.goidgen field offset"},
		{"zero base", 0x2000, 0x2000, 0, "invalid sched.goidgen field offset"},
		{"misaligned field", 0x2001, 0, 0, "invalid sched.goidgen storage"},
		{"misaligned base", 0x2008, 1, 0, "invalid sched storage"},
		{"base outside storage", 0x2000, 8, 0, "invalid sched storage"},
		{"field fits exactly", 0x3ff8, 0, 0x3ff8, ""},
		{"field outside storage", 0x4000, 0, 0, "invalid sched.goidgen storage"},
		{"address overflow", math.MaxUint64 - 7, 0, 0, "invalid sched.goidgen storage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
				Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_W, Vaddr: 0x2000, Memsz: 0x2000,
			}}}}
			got, err := runtimeMetricSchedBase(f, tc.field, tc.offset)
			if tc.wantError == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tc.wantError)
			}
			require.Equal(t, tc.want, got)
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
