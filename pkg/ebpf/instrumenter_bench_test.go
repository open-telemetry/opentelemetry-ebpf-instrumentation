// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

const benchProbeSymbolsPerMap = 2

// largeSymtabELF writes an ELF64 file whose .symtab holds symbolCount
// unrelated functions plus the given named ones, and returns its path.
func largeSymtabELF(tb testing.TB, symbolCount int, named []string) string {
	tb.Helper()

	strtab := []byte{0}
	symbols := make([]elf.Sym64, 0, symbolCount+len(named)+1)
	symbols = append(symbols, elf.Sym64{})

	addSymbol := func(name string, value uint64) {
		symbols = append(symbols, elf.Sym64{
			Name: uint32(len(strtab)), Info: byte(elf.STT_FUNC), Value: value, Size: 8,
		})
		strtab = append(strtab, name...)
		strtab = append(strtab, 0)
	}

	for i := range symbolCount {
		addSymbol(fmt.Sprintf("unrelated_symbol_%08d", i), uint64(i))
	}
	for i, name := range named {
		addSymbol(name, uint64(symbolCount+i))
	}

	headerSize := binary.Size(elf.Header64{})
	sectionSize := binary.Size(elf.Section64{})
	strtabOffset := headerSize + 3*sectionSize
	symtabOffset := strtabOffset + len(strtab)

	var ident [elf.EI_NIDENT]byte
	copy(ident[:], elf.ELFMAG)
	ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		ident[elf.EI_DATA] = byte(elf.ELFDATA2MSB)
	}
	ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)

	var data bytes.Buffer
	for _, value := range []any{
		elf.Header64{
			Ident: ident, Version: uint32(elf.EV_CURRENT), Shoff: uint64(headerSize),
			Ehsize: uint16(headerSize), Shentsize: uint16(sectionSize), Shnum: 3,
		},
		[]elf.Section64{
			{},
			{Type: uint32(elf.SHT_STRTAB), Off: uint64(strtabOffset), Size: uint64(len(strtab))},
			{
				Type: uint32(elf.SHT_SYMTAB), Off: uint64(symtabOffset),
				Size: uint64(len(symbols) * elf.Sym64Size), Link: 1, Entsize: elf.Sym64Size,
			},
		},
		strtab,
		symbols,
	} {
		require.NoError(tb, binary.Write(&data, binary.NativeEndian, value))
	}

	path := filepath.Join(tb.TempDir(), "large-symtab.elf")
	require.NoError(tb, os.WriteFile(path, data.Bytes(), 0o600))

	return path
}

// BenchmarkGatherOffsets compares resolving N probe maps of one module with
// one scan per map (the previous behavior) against a single scan.
func BenchmarkGatherOffsets(b *testing.B) {
	const symbolCount = 1_000_000

	for _, mapCount := range []int{1, 2, 3} {
		var named []string
		probeMaps := make([]map[string][]*ebpfcommon.ProbeDesc, mapCount)
		for i := range probeMaps {
			probeMaps[i] = map[string][]*ebpfcommon.ProbeDesc{}
			for j := range benchProbeSymbolsPerMap {
				name := fmt.Sprintf("probe_%d_%d", i, j)
				named = append(named, name)
				probeMaps[i][name] = []*ebpfcommon.ProbeDesc{{}}
			}
		}

		path := largeSymtabELF(b, symbolCount, named)
		log := slog.New(slog.DiscardHandler)

		b.Run(fmt.Sprintf("maps=%d/scan-per-map", mapCount), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				for _, probes := range probeMaps {
					errs, err := gatherOffsets(path, []map[string][]*ebpfcommon.ProbeDesc{probes}, log)
					require.NoError(b, err)
					require.NoError(b, errs[0])
				}
			}
		})

		b.Run(fmt.Sprintf("maps=%d/single-scan", mapCount), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				errs, err := gatherOffsets(path, probeMaps, log)
				require.NoError(b, err)
				for _, e := range errs {
					require.NoError(b, e)
				}
			}
		})
	}
}
