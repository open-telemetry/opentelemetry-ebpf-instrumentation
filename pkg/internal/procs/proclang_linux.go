// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"debug/elf"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
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

func contains(slice []string, value string) bool {
	return slices.Contains(slice, value)
}

type symbolCollector struct {
	addresses   map[string]Sym
	symbolNames []string
	matches     func(string, []string) (string, bool)
}

func collectSymbols(
	f *elf.File,
	syms []elf.Symbol,
	collectors []symbolCollector,
	coldParts map[string][]Sym,
	types ...elf.SymType,
) {
	if len(types) == 0 {
		types = []elf.SymType{elf.STT_FUNC}
	}
	for _, s := range syms {
		if !slices.Contains(types, elf.ST_TYPE(s.Info)) {
			continue
		}

		if parent, ok := coldPartParent(s); ok && collectorsMatch(collectors, parent) {
			coldParts[parent] = append(coldParts[parent], resolveSymbol(f, s))
		}

		var sym *Sym
		for _, collector := range collectors {
			key, ok := collector.matches(s.Name, collector.symbolNames)
			if !ok {
				continue
			}

			if sym == nil {
				resolvedSym := resolveSymbol(f, s)
				sym = &resolvedSym
			}
			collector.addresses[key] = *sym
		}
	}
}

func collectorsMatch(collectors []symbolCollector, name string) bool {
	return slices.ContainsFunc(collectors, func(collector symbolCollector) bool {
		_, ok := collector.matches(name, collector.symbolNames)
		return ok
	})
}

const coldPartSuffix = ".cold"

// coldPartParent returns the function that a GCC hot/cold split moved this
// part out of, from the <name>.cold or <name>.cold.<N> name GCC gives it.
func coldPartParent(s elf.Symbol) (string, bool) {
	if elf.ST_TYPE(s.Info) != elf.STT_FUNC || elf.ST_BIND(s.Info) != elf.STB_LOCAL {
		return "", false
	}

	index := strings.LastIndex(s.Name, coldPartSuffix)
	if index <= 0 {
		return "", false
	}

	parent, suffix := s.Name[:index], s.Name[index+len(coldPartSuffix):]
	if suffix == "" {
		return parent, true
	}

	number, ok := strings.CutPrefix(suffix, ".")
	if _, err := strconv.ParseUint(number, 10, 64); !ok || err != nil {
		return "", false
	}
	return parent, true
}

func addColdParts(addresses map[string]Sym, coldParts map[string][]Sym) {
	for key, sym := range addresses {
		if parts, ok := coldParts[sym.Name]; ok {
			sym.ColdParts = parts
			addresses[key] = sym
		}
	}
}

func FindExeSymbols(f *elf.File, symbolNames []string, types ...elf.SymType) (map[string]Sym, error) {
	exactSyms, _, err := FindExeSymbolsByNameAndSubstring(f, symbolNames, nil, types...)
	return exactSyms, err
}

func FindExeSymbolsBySubstring(f *elf.File, symbolSubstrings []string, types ...elf.SymType) (map[string]Sym, error) {
	_, substringSyms, err := FindExeSymbolsByNameAndSubstring(f, nil, symbolSubstrings, types...)
	return substringSyms, err
}

func FindExeSymbolsByNameAndSubstring(f *elf.File, symbolNames, symbolSubstrings []string, types ...elf.SymType) (map[string]Sym, map[string]Sym, error) {
	exactAddresses := map[string]Sym{}
	substringAddresses := map[string]Sym{}
	collectors := []symbolCollector{
		{
			addresses:   exactAddresses,
			symbolNames: symbolNames,
			matches:     exactSymbolMatch,
		},
		{
			addresses:   substringAddresses,
			symbolNames: symbolSubstrings,
			matches:     substringSymbolMatch,
		},
	}

	// cold parts are local symbols, so they can precede the global they belong to
	coldParts := map[string][]Sym{}

	syms, err := f.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, nil, err
	}

	collectSymbols(f, syms, collectors, coldParts, types...)

	dynsyms, err := f.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, nil, err
	}

	collectSymbols(f, dynsyms, collectors, coldParts, types...)

	addColdParts(exactAddresses, coldParts)
	addColdParts(substringAddresses, coldParts)

	return exactAddresses, substringAddresses, nil
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

func exactSymbolMatch(symbolName string, names []string) (string, bool) {
	if contains(names, symbolName) {
		return symbolName, true
	}
	return "", false
}

func substringSymbolMatch(symbolName string, substrings []string) (string, bool) {
	for _, substring := range substrings {
		if strings.Contains(symbolName, substring) {
			return substring, true
		}
	}
	return "", false
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
