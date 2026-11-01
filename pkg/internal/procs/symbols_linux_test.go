// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
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

func symbolELFFixture(tb testing.TB, class elf.Class, order binary.ByteOrder, tables ...symbolTableFixture) *elf.File {
	tb.Helper()

	headerSize, sectionSize, symbolSize := binary.Size(elf.Header64{}), binary.Size(elf.Section64{}), elf.Sym64Size
	if class == elf.ELFCLASS32 {
		headerSize, sectionSize, symbolSize = binary.Size(elf.Header32{}), binary.Size(elf.Section32{}), elf.Sym32Size
	}
	sections := make([]elf.Section64, 1+2*len(tables))
	offset := headerSize + len(sections)*sectionSize
	for i, table := range tables {
		strIndex := 1 + 2*i
		sections[strIndex] = elf.Section64{Type: uint32(elf.SHT_STRTAB), Off: uint64(offset), Size: uint64(len(table.strings))}
		offset += len(table.strings)
		sections[strIndex+1] = elf.Section64{
			Type: uint32(table.typ), Off: uint64(offset), Size: uint64(len(table.symbols) * symbolSize),
			Link: uint32(strIndex), Entsize: uint64(symbolSize),
		}
		offset += len(table.symbols) * symbolSize
	}

	var ident [elf.EI_NIDENT]byte
	copy(ident[:], elf.ELFMAG)
	ident[elf.EI_CLASS], ident[elf.EI_DATA], ident[elf.EI_VERSION] = byte(class), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	if order == binary.BigEndian {
		ident[elf.EI_DATA] = byte(elf.ELFDATA2MSB)
	}
	var data bytes.Buffer
	if class == elf.ELFCLASS64 {
		require.NoError(tb, binary.Write(&data, order, elf.Header64{
			Ident: ident, Version: uint32(elf.EV_CURRENT), Shoff: uint64(headerSize),
			Ehsize: uint16(headerSize), Shentsize: uint16(sectionSize), Shnum: uint16(len(sections)),
		}))
		require.NoError(tb, binary.Write(&data, order, sections))
	} else {
		require.NoError(tb, binary.Write(&data, order, elf.Header32{
			Ident: ident, Version: uint32(elf.EV_CURRENT), Shoff: uint32(headerSize),
			Ehsize: uint16(headerSize), Shentsize: uint16(sectionSize), Shnum: uint16(len(sections)),
		}))
		for _, section := range sections {
			require.NoError(tb, binary.Write(&data, order, elf.Section32{
				Type: section.Type, Off: uint32(section.Off), Size: uint32(section.Size),
				Link: section.Link, Entsize: uint32(section.Entsize),
			}))
		}
	}
	for _, table := range tables {
		data.Write(table.strings)
		if class == elf.ELFCLASS64 {
			require.NoError(tb, binary.Write(&data, order, table.symbols))
			continue
		}
		for _, symbol := range table.symbols {
			require.NoError(tb, binary.Write(&data, order, elf.Sym32{
				Name: symbol.Name, Value: uint32(symbol.Value), Size: uint32(symbol.Size),
				Info: symbol.Info, Other: symbol.Other, Shndx: symbol.Shndx,
			}))
		}
	}
	f, err := elf.NewFile(bytes.NewReader(data.Bytes()))
	require.NoError(tb, err)
	tb.Cleanup(func() { require.NoError(tb, f.Close()) })
	return f
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
	for _, class := range []elf.Class{elf.ELFCLASS32, elf.ELFCLASS64} {
		for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			t.Run(fmt.Sprintf("%s/%s", class, order), func(t *testing.T) {
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
					f := symbolELFFixture(t, class, order, tables...)
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
			})
		}
	}
}

func TestFindExeSymbolsLongStrings(t *testing.T) {
	const target = "target"
	for _, padding := range []int{(64 << 10) - 4, 64 << 10, (128 << 10) + 3} {
		strtab := "\x00" + strings.Repeat("x", padding) + target + "\x00"
		f := symbolELFFixture(t, elf.ELFCLASS64, binary.LittleEndian, symbolTableFixture{
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
			{"truncated strings", func(f *elf.File) { f.Sections[1].Size++ }},
		} {
			t.Run(fmt.Sprintf("%s/%s", typ, tc.name), func(t *testing.T) {
				f := symbolELFFixture(t, elf.ELFCLASS64, binary.LittleEndian, symbolTableFixture{
					typ: typ, strings: []byte("\x00target\x00"),
					symbols: []elf.Sym64{{}, {Name: 1, Info: byte(elf.STT_FUNC), Value: 42, Size: 8}},
				})
				tc.mutate(f)
				_, err := decodedExeSymbols(f, []string{"target"})
				require.Error(t, err)
				got, err := FindExeSymbols(f, []string{"target"})
				require.Error(t, err)
				assert.Nil(t, got)
			})
		}
	}
}

func largeSymbolELFFixture(tb testing.TB, count int) *elf.File {
	tb.Helper()

	table := symbolTableFixture{typ: elf.SHT_SYMTAB, strings: []byte{0}, symbols: make([]elf.Sym64, count+1)}
	for i := 1; i <= count; i++ {
		table.symbols[i] = elf.Sym64{Name: uint32(len(table.strings)), Info: byte(elf.STT_FUNC), Value: uint64(i), Size: 8}
		table.strings = fmt.Appendf(table.strings, "unrelated_symbol_%08d\x00", i)
	}
	table.symbols[count].Name = uint32(len(table.strings))
	table.strings = append(table.strings, "SSL_read\x00"...)
	return symbolELFFixture(tb, elf.ELFCLASS64, binary.LittleEndian, table)
}

func TestFindExeSymbolsAllocations(t *testing.T) {
	const maxLookupAllocations = 100

	f := largeSymbolELFFixture(t, 10_000)
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
				f := largeSymbolELFFixture(b, count)
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
