// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type symbolTableFixture struct {
	typ     elf.SectionType
	strings []byte
	symbols []elf.Sym64
}

func symbolELFFixture(tb testing.TB, tables ...symbolTableFixture) (*elf.File, string) {
	tb.Helper()

	headerSize, sectionSize := binary.Size(elf.Header64{}), binary.Size(elf.Section64{})
	sections := make([]elf.Section64, 1+2*len(tables))
	offset := headerSize + len(sections)*sectionSize
	for i, table := range tables {
		strIndex := 1 + 2*i
		sections[strIndex] = elf.Section64{Type: uint32(elf.SHT_STRTAB), Off: uint64(offset), Size: uint64(len(table.strings))}
		offset += len(table.strings)
		sections[strIndex+1] = elf.Section64{
			Type: uint32(table.typ), Off: uint64(offset), Size: uint64(len(table.symbols) * elf.Sym64Size),
			Link: uint32(strIndex), Entsize: elf.Sym64Size,
		}
		offset += len(table.symbols) * elf.Sym64Size
	}
	var ident [elf.EI_NIDENT]byte
	copy(ident[:], elf.ELFMAG)
	ident[elf.EI_CLASS], ident[elf.EI_DATA], ident[elf.EI_VERSION] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		ident[elf.EI_DATA] = byte(elf.ELFDATA2MSB)
	}
	var data bytes.Buffer
	require.NoError(tb, binary.Write(&data, binary.NativeEndian, elf.Header64{
		Ident: ident, Version: uint32(elf.EV_CURRENT), Shoff: uint64(headerSize),
		Ehsize: uint16(headerSize), Shentsize: uint16(sectionSize), Shnum: uint16(len(sections)),
	}))
	require.NoError(tb, binary.Write(&data, binary.NativeEndian, sections))
	for _, table := range tables {
		data.Write(table.strings)
		require.NoError(tb, binary.Write(&data, binary.NativeEndian, table.symbols))
	}
	path := filepath.Join(tb.TempDir(), "symbols.elf")
	require.NoError(tb, os.WriteFile(path, data.Bytes(), 0o600))
	f, err := elf.Open(path)
	require.NoError(tb, err)
	tb.Cleanup(func() { require.NoError(tb, f.Close()) })
	return f, path
}

func decodedExeSymbols(f *elf.File, names []string, types ...elf.SymType) (map[string]Sym, error) {
	result := map[string]Sym{}
	if len(types) == 0 {
		types = []elf.SymType{elf.STT_FUNC}
	}
	for _, read := range []func() ([]elf.Symbol, error){f.Symbols, f.DynamicSymbols} {
		symbols, err := read()
		if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			return nil, err
		}
		for _, symbol := range symbols {
			for _, name := range names {
				for _, typ := range types {
					if symbol.Name == name && elf.ST_TYPE(symbol.Info) == typ {
						result[name] = resolveSymbol(f, symbol)
					}
				}
			}
		}
	}
	return result, nil
}

func TestFindExeSymbolsTables(t *testing.T) {
	table := symbolTableFixture{
		typ: elf.SHT_SYMTAB, strings: []byte("\x00prefix_target\x00object\x00target_extra\x00target\x00unterminated"),
		symbols: []elf.Sym64{
			{Name: 8, Info: byte(elf.STT_FUNC), Value: 0x1001, Size: 1}, // Null entry must be skipped.
			{Name: 8, Info: byte(elf.STT_FUNC), Value: 0x1010, Size: 16},
			{Name: 15, Info: byte(elf.STT_OBJECT), Value: 0x2000, Size: 8},
			{Name: 22, Info: byte(elf.STT_FUNC), Value: 0x1020, Size: 20},
			{Name: 35, Info: elf.ST_INFO(elf.STB_GLOBAL, elf.STT_FUNC), Value: 0x1030, Size: 24},
			{Name: 42, Info: byte(elf.STT_FUNC), Value: 0x1040},
			{Name: ^uint32(0), Info: byte(elf.STT_FUNC), Value: 0x1050},
		},
	}
	dynamic := symbolTableFixture{
		typ: elf.SHT_DYNSYM, strings: []byte("\x00target\x00dynamic\x00zero\x00"),
		symbols: []elf.Sym64{
			{},
			{Name: 1, Info: byte(elf.STT_FUNC), Value: 0x1060, Size: 32},
			{Name: 8, Info: byte(elf.STT_FUNC), Value: 0x1070, Size: 40},
			{Name: 16, Info: byte(elf.STT_FUNC)},
		},
	}
	for _, tables := range [][]symbolTableFixture{nil, {table}, {dynamic}, {dynamic, table}} {
		f, _ := symbolELFFixture(t, tables...)
		f.Progs = []*elf.Prog{{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_X, Vaddr: 0x1000, Off: 0x200, Memsz: 0x1000}}}
		for _, types := range [][]elf.SymType{nil, {elf.STT_OBJECT}, {elf.STT_FUNC, elf.STT_OBJECT}} {
			for _, names := range [][]string{nil, {"missing"}, {"target", "target", "object", "dynamic", "zero"}, {"target\x00dynamic"}} {
				want, err := decodedExeSymbols(f, names, types...)
				require.NoError(t, err)
				got, err := FindExeSymbols(f, names, types...)
				require.NoError(t, err)
				assert.Equal(t, want, got, "names=%q, types=%v", names, types)
			}
			got, err := FindExeSymbols(f, []string{"target"})
			require.NoError(t, err)
			if len(tables) > 0 {
				value := uint64(0x1030)
				if f.SectionByType(elf.SHT_DYNSYM) != nil {
					value = 0x1060
				}
				assert.Equal(t, value, got["target"].Value)
				assert.Equal(t, value-0x1000+0x200, got["target"].Off)
			}
		}
	}
}

func TestFindExeSymbolsLongStrings(t *testing.T) {
	const target = "target"
	for _, padding := range []int{(64 << 10) - 4, 64 << 10, (128 << 10) + 3} {
		strtab := "\x00" + strings.Repeat("x", padding) + target + "\x00"
		f, _ := symbolELFFixture(t, symbolTableFixture{
			typ: elf.SHT_SYMTAB, strings: []byte(strtab),
			symbols: []elf.Sym64{
				{},
				{Name: uint32(padding + 1), Info: byte(elf.STT_FUNC), Value: 42, Size: 8},
				{Name: 1, Info: byte(elf.STT_FUNC), Value: 50, Size: 16},
			},
		})
		for _, names := range [][]string{{target}, {strtab[1 : len(strtab)-1]}} {
			want, err := decodedExeSymbols(f, names)
			require.NoError(t, err)
			got, err := FindExeSymbols(f, names)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		}
	}
}

func TestFindExeSymbolsMalformedTables(t *testing.T) {
	for _, typ := range []elf.SectionType{elf.SHT_SYMTAB, elf.SHT_DYNSYM} {
		for _, tc := range []struct {
			name   string
			mutate func(*elf.File)
		}{
			{"zero link", func(f *elf.File) { f.SectionByType(typ).Link = 0 }},
			{"invalid link", func(f *elf.File) { f.SectionByType(typ).Link = uint32(len(f.Sections)) }},
			{"partial symbol", func(f *elf.File) { f.SectionByType(typ).Size-- }},
			{"truncated symbols", func(f *elf.File) { f.SectionByType(typ).Size += elf.Sym64Size }},
			{"truncated strings", func(f *elf.File) { f.Sections[1].Size += 1 << 20 }},
		} {
			t.Run(fmt.Sprintf("%s/%s", typ, tc.name), func(t *testing.T) {
				f, path := symbolELFFixture(t, symbolTableFixture{
					typ: typ, strings: []byte("\x00target\x00"),
					symbols: []elf.Sym64{{}, {Name: 1, Info: byte(elf.STT_FUNC), Value: 42, Size: 8}},
				})
				tc.mutate(f)
				writer, err := os.OpenFile(path, os.O_WRONLY, 0)
				require.NoError(t, err)
				for i, section := range f.Sections {
					var header bytes.Buffer
					require.NoError(t, binary.Write(&header, binary.NativeEndian, elf.Section64{
						Type: uint32(section.Type), Off: section.Offset, Size: section.Size,
						Link: section.Link, Entsize: section.Entsize,
					}))
					_, err := writer.WriteAt(header.Bytes(), int64(binary.Size(elf.Header64{})+i*binary.Size(elf.Section64{})))
					require.NoError(t, err)
				}
				require.NoError(t, writer.Close())
				_, err = decodedExeSymbols(f, []string{"target"})
				require.Error(t, err)
				got, err := FindExeSymbols(f, []string{"target"})
				require.Error(t, err)
				assert.Nil(t, got)
			})
		}
	}
}

func largeSymbolELFFixture(tb testing.TB, count int) (*elf.File, string) {
	tb.Helper()

	table := symbolTableFixture{typ: elf.SHT_SYMTAB, strings: []byte{0}, symbols: make([]elf.Sym64, count+1)}
	for i := 1; i <= count; i++ {
		table.symbols[i] = elf.Sym64{Name: uint32(len(table.strings)), Info: byte(elf.STT_FUNC), Value: uint64(i), Size: 8}
		table.strings = fmt.Appendf(table.strings, "unrelated_symbol_%08d\x00", i)
	}
	table.symbols[count].Name = uint32(len(table.strings))
	table.strings = append(table.strings, "SSL_read\x00"...)
	return symbolELFFixture(tb, table)
}

func TestFindExeSymbolsAllocations(t *testing.T) {
	const maxLookupAllocations = 100

	f, _ := largeSymbolELFFixture(t, 10_000)
	var symbols map[string]Sym
	var err error
	allocations := testing.AllocsPerRun(3, func() {
		symbols, err = FindExeSymbols(f, []string{"SSL_read", "SSL_write"})
	})
	require.NoError(t, err)
	require.Len(t, symbols, 1)
	assert.Equal(t, uint64(10_000), symbols["SSL_read"].Value)
	assert.Less(t, allocations, float64(maxLookupAllocations), "lookup must not allocate for unrelated symbols")
}

// benchmarkSymbolNames returns name lists shaped like the probe lists passed by
// the tracers: mixed lengths, shared prefixes and names longer than 32 bytes.
func benchmarkSymbolNames(count int) []string {
	names := []string{"SSL_read", "SSL_write", "SSL_shutdown", "SSL_set_bio", "SSL_free"}
	for i := len(names); i < count; i++ {
		names = append(names, fmt.Sprintf("net/http.(*conn%d).serve.func%d", i, i%10))
	}
	return names[:count]
}

func BenchmarkFindExeSymbols(b *testing.B) {
	for _, count := range []int{10_000, 100_000, 1_000_000} {
		for _, nameCount := range []int{5, 50} {
			b.Run(fmt.Sprintf("symbols=%d/names=%d", count, nameCount), func(b *testing.B) {
				f, _ := largeSymbolELFFixture(b, count)
				names := benchmarkSymbolNames(nameCount)
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					symbols, err := FindExeSymbols(f, names)
					require.NoError(b, err)
					require.Len(b, symbols, 1)
				}
			})
		}
	}
}

func TestFindExeSymbolsNamesSurviveUnmap(t *testing.T) {
	f, _ := largeSymbolELFFixture(t, 100)
	symbols, err := FindExeSymbols(f, []string{"SSL_read"})
	require.NoError(t, err)
	require.Len(t, symbols, 1)
	assert.Equal(t, "SSL_read", symbols["SSL_read"].Name)
	_, err = f.SectionByType(elf.SHT_SYMTAB).Data()
	require.NoError(t, err)
}

func TestFindExeSymbolsNativeByteOrder(t *testing.T) {
	f, _ := symbolELFFixture(t,
		symbolTableFixture{
			typ: elf.SHT_SYMTAB, strings: []byte("\x00prefix_target\x00object\x00"),
			symbols: []elf.Sym64{
				{},
				{Name: 8, Info: byte(elf.STT_FUNC), Value: 0x12345010, Size: 0x123},
				{Name: 15, Info: byte(elf.STT_OBJECT), Value: 0x87654321, Size: 0x456},
			},
		},
		symbolTableFixture{
			typ: elf.SHT_DYNSYM, strings: []byte("\x00target\x00"),
			symbols: []elf.Sym64{{}, {Name: 1, Info: byte(elf.STT_FUNC), Value: 0x12345020, Size: 0x789}},
		},
	)
	f.Progs = []*elf.Prog{{ProgHeader: elf.ProgHeader{
		Type: elf.PT_LOAD, Flags: elf.PF_X, Vaddr: 0x12345000, Off: 0x200, Memsz: 0x1000,
	}}}
	names := []string{"target", "object"}
	want, err := decodedExeSymbols(f, names, elf.STT_FUNC, elf.STT_OBJECT)
	require.NoError(t, err)
	got, err := FindExeSymbols(f, names, elf.STT_FUNC, elf.STT_OBJECT)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, want, got)
	assert.Equal(t, uint64(0x220), got["target"].Off)
	assert.Equal(t, uint64(0x789), got["target"].Len)
}
