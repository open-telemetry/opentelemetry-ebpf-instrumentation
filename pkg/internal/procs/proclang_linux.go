// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"slices"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/internal/fastelf"
)

func FindProcLanguage(pid app.PID) svc.InstrumentableType {
	maps, err := FindLibMaps(pid)
	if err != nil {
		return svc.InstrumentableGeneric
	}

	// We first check for the languages as cheaply as possible when
	// know they link certain libraries that can tell us the language.
	for _, m := range maps {
		t := instrumentableFromModuleMapSharedLib(m.Pathname)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	// We must find the language type from the binary first
	// before resorting to discovery by path or environment variables.
	// For example, a Go application can be called 'node' and we must
	// not identify this application as Node.js.
	filePath, err := resolveProcBinary(pid)
	if err != nil {
		return svc.InstrumentableGeneric
	}

	t := findLanguageFromElf(filePath)

	if t != svc.InstrumentableGeneric {
		return t
	}

	for _, m := range maps {
		t := instrumentableFromModuleMap(m.Pathname)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	t = instrumentableFromPath(filePath)
	if t != svc.InstrumentableGeneric {
		return t
	}

	// Last resort to tell Generic from C++ (and maybe others in the future)
	for _, m := range maps {
		t := instrumentableLastResort(m.Pathname)
		if t != svc.InstrumentableGeneric {
			return t
		}
	}

	return svc.InstrumentableGeneric
}

func resolveProcBinary(pid app.PID) (string, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)

	realPath, err := os.Readlink(exePath)
	if err != nil {
		return "", fmt.Errorf("failed to read process binary: %w", err)
	}

	return fmt.Sprintf("/proc/%d/root%s", pid, realPath), nil
}

func findLanguageFromElf(filePath string) (result svc.InstrumentableType) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("panic while parsing ELF file", "file", filePath, "panic", r)
			result = svc.InstrumentableGeneric
		}
	}()

	ctx, err := fastelf.NewElfContextFromFile(filePath)
	if err != nil {
		return svc.InstrumentableGeneric
	}

	defer ctx.Close()

	if ctx.HasSection(".gopclntab") {
		return svc.InstrumentableGolang
	}

	return matchExeSymbols(ctx)
}

func FindExeSymbols(f *elf.File, symbolNames []string, types ...elf.SymType) (map[string]Sym, error) {
	addresses := map[string]Sym{}
	if len(types) == 0 {
		types = []elf.SymType{elf.STT_FUNC}
	}

	for _, typ := range []elf.SectionType{elf.SHT_SYMTAB, elf.SHT_DYNSYM} {
		if err := collectSymbols(f, typ, symbolNames, addresses, types); err != nil {
			return nil, err
		}
	}

	return addresses, nil
}

const symbolReadBufferSize = 64 << 10

func collectSymbols(f *elf.File, typ elf.SectionType, symbolNames []string, addresses map[string]Sym, types []elf.SymType) error {
	section := f.SectionByType(typ)
	if section == nil || section.Size == 0 {
		return nil
	}

	var symbolSize int
	switch f.Class {
	case elf.ELFCLASS32:
		symbolSize = elf.Sym32Size
	case elf.ELFCLASS64:
		symbolSize = elf.Sym64Size
	default:
		return errors.New("unsupported ELF class")
	}
	if section.Size%uint64(symbolSize) != 0 {
		return errors.New("length of symbol section is not a multiple of symbol size")
	}
	if section.Link == 0 || uint64(section.Link) >= uint64(len(f.Sections)) {
		return errors.New("section has invalid string table link")
	}

	names, validStringSize, err := symbolNameOffsets(f.Sections[section.Link], symbolNames)
	if err != nil {
		return fmt.Errorf("cannot load string table section: %w", err)
	}

	reader := section.Open()
	buffer := make([]byte, symbolReadBufferSize/symbolSize*symbolSize)
	wantEmpty := slices.Contains(symbolNames, "")
	for offset := uint64(0); offset < section.Size; {
		size := int(min(uint64(len(buffer)), section.Size-offset))
		if _, err := io.ReadFull(reader, buffer[:size]); err != nil {
			return fmt.Errorf("cannot load symbol section: %w", err)
		}
		for start := 0; start < size; start += symbolSize {
			// ELF symbol tables begin with a reserved null entry.
			if offset == 0 && start == 0 {
				continue
			}

			data := buffer[start : start+symbolSize]
			nameOffset := f.ByteOrder.Uint32(data[:4])
			name, ok := names[nameOffset]
			if !ok && (!wantEmpty || uint64(nameOffset) < validStringSize) {
				continue
			}

			symbol := elf.Symbol{Name: name}
			if f.Class == elf.ELFCLASS64 {
				symbol.Info = data[4]
				symbol.Value = f.ByteOrder.Uint64(data[8:16])
				symbol.Size = f.ByteOrder.Uint64(data[16:24])
			} else {
				symbol.Info = data[12]
				symbol.Value = uint64(f.ByteOrder.Uint32(data[4:8]))
				symbol.Size = uint64(f.ByteOrder.Uint32(data[8:12]))
			}
			if slices.Contains(types, elf.ST_TYPE(symbol.Info)) {
				addresses[name] = resolveSymbol(f, symbol)
			}
		}
		offset += uint64(size)
	}
	return nil
}

func symbolNameOffsets(section *elf.Section, symbolNames []string) (map[uint32]string, uint64, error) {
	patterns := make(map[string]string, len(symbolNames))
	maxNameLen := 0
	for _, name := range symbolNames {
		if strings.IndexByte(name, 0) >= 0 {
			continue
		}
		patterns[name+"\x00"] = name
		maxNameLen = max(maxNameLen, len(name))
	}

	names := map[uint32]string{}
	buffer := make([]byte, symbolReadBufferSize+maxNameLen)
	reader := section.Open()
	var offset, validStringSize uint64
	tail := 0
	for remaining := section.Size; remaining > 0; {
		size := int(min(uint64(len(buffer)-tail), remaining))
		if _, err := io.ReadFull(reader, buffer[tail:tail+size]); err != nil {
			return nil, 0, err
		}
		remaining -= uint64(size)
		data := buffer[:tail+size]
		if last := bytes.LastIndexByte(data, 0); last >= 0 {
			validStringSize = offset + uint64(last) + 1
		}
		for pattern, name := range patterns {
			for start := 0; start < len(data); {
				index := bytes.Index(data[start:], []byte(pattern))
				if index < 0 {
					break
				}
				start += index
				if nameOffset := offset + uint64(start); nameOffset <= math.MaxUint32 {
					names[uint32(nameOffset)] = name
				}
				start += len(pattern)
			}
		}

		// Keep overlapping bytes for names crossing reads. Matching suffixes also
		// handles ELF string tables that share storage between symbol names.
		tail = min(maxNameLen, len(data))
		offset += uint64(len(data) - tail)
		copy(buffer, data[len(data)-tail:])
	}
	return names, validStringSize, nil
}

func resolveSymbol(f *elf.File, s elf.Symbol) Sym {
	address := s.Value
	var p *elf.Prog

	// Loop over ELF segments.
	for _, prog := range f.Progs {
		// Skip uninteresting segments.
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}

		if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
			address = s.Value - prog.Vaddr + prog.Off
			p = prog
			break
		}
	}

	return Sym{Name: s.Name, Off: address, Value: s.Value, Len: s.Size, Prog: p}
}

func matchExeSymbols(ctx *fastelf.ElfContext) svc.InstrumentableType {
	isRust := false

	for _, sec := range ctx.Sections {
		if sec == nil {
			continue
		}

		if sec.Type != fastelf.SHT_SYMTAB && sec.Type != fastelf.SHT_DYNSYM {
			continue
		}

		if int(sec.Link) >= len(ctx.Sections) {
			continue
		}

		strtab := ctx.Sections[sec.Link]

		strs, ok := ctx.SectionData(strtab)
		if !ok {
			continue
		}

		symOffset, symEntrySize, symCount, ok := ctx.SymbolTableBounds(sec)
		if !ok {
			continue
		}

		for i := range symCount {
			sym := fastelf.ReadStruct[fastelf.Elf64_Sym](ctx.Data, symOffset+i*symEntrySize)

			if sym == nil ||
				fastelf.SymType(sym.Info) != fastelf.STT_FUNC ||
				sym.Size == 0 ||
				sym.Value == 0 {
				continue
			}

			name := fastelf.GetCStringUnsafe(strs, sym.Name)

			t := instrumentableFromSymbolName(name)

			if t != svc.InstrumentableGeneric {
				if t == svc.InstrumentableRust {
					isRust = true
				} else {
					return t
				}
			}
		}
	}

	if isRust {
		return svc.InstrumentableRust
	}

	return svc.InstrumentableGeneric
}
