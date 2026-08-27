// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"strings"
)

const (
	prefixNew = "go:itab."
	prefixOld = "go.itab."
	prefixLen = len(prefixNew)

	go127TypeTFlagOffset = 20
	go127TypeNameOffset  = 40
	go127InterfaceLenOff = 64
	go127ITabTypeOffset  = 8
	go127ITabFunOffset   = 24
	go127ITabBaseSize    = 32
	go127TFlagExtraStar  = 1 << 1
	maxGoTypeNameLen     = 4096
)

func isITabEntry(sym string) bool {
	return strings.Contains(sym, prefixNew) || strings.Contains(sym, prefixOld)
}

func iTabType(sym string) string {
	if len(sym) <= prefixLen {
		return ""
	}
	parts := strings.Split(sym[prefixLen:], ",")
	if len(parts) < 2 {
		return ""
	}

	return parts[0]
}

func findInterfaceImpls(ef *elf.File) (map[string]uint64, error) {
	implementations := map[string]uint64{}
	symbols, err := ef.Symbols()
	if err != nil {
		if !errors.Is(err, elf.ErrNoSymbols) {
			return nil, fmt.Errorf("accessing symbols table: %w", err)
		}
	}
	for _, s := range symbols {
		// Name is in format: go:itab.*net/http.response,net/http.ResponseWriter or go.itab.*net/http.response,net/http.ResponseWriter on old versions
		if !isITabEntry(s.Name) {
			continue
		}
		iType := iTabType(s.Name)
		if iType != "" {
			implementations[iType] = s.Value
		}
	}

	goVersion, _, err := getGoDetails(ef)
	if err != nil || !goVersionAtLeast(goVersion, "1.27.0") {
		return implementations, nil
	}

	moduleImplementations, err := findInterfaceImplsFromModuledata(ef)
	if err != nil {
		return nil, err
	}
	maps.Copy(implementations, moduleImplementations)
	return implementations, nil
}

func findInterfaceImplsFromModuledata(ef *elf.File) (map[string]uint64, error) {
	if ef.Class != elf.ELFCLASS64 {
		return nil, errors.New("go 1.27 itab discovery only supports 64-bit ELF")
	}

	gopclntab := ef.Section(".gopclntab")
	if gopclntab == nil {
		return nil, errors.New("no .gopclntab section")
	}

	mdoffs, err := loadModuledataOffsets(ef)
	if err != nil {
		return nil, err
	}
	relocs := buildRelocationInfo(ef)
	for _, candidate := range moduledataCandidates(ef, gopclntab.Addr, mdoffs, relocs) {
		if !inWritableSection(ef, candidate) {
			continue
		}
		if _, ok := validateModuledata(ef, candidate, gopclntab.Addr, gopclntab.Size, mdoffs, relocs); !ok {
			continue
		}

		return readGo127InterfaceImpls(ef, candidate, mdoffs, relocs)
	}

	return nil, errors.New("runtime.moduledata not found")
}

func readGo127InterfaceImpls(
	ef *elf.File,
	moduledata uint64,
	mdoffs moduledataOffsets,
	relocs relocationInfo,
) (map[string]uint64, error) {
	types := resolveAddr(ef, moduledata+mdoffs.types, relocs)
	typeDescLen := readAddr(ef, moduledata+mdoffs.typedesclen)
	itabOffset := readAddr(ef, moduledata+mdoffs.itaboffset)
	itabSize := readAddr(ef, moduledata+mdoffs.itabsize)
	if types == 0 || typeDescLen == 0 || itabOffset < typeDescLen || itabSize == 0 {
		return nil, errors.New("invalid Go 1.27 type metadata")
	}
	if itabOffset > ^uint64(0)-types || itabSize > ^uint64(0)-(types+itabOffset) {
		return nil, errors.New("go 1.27 itab metadata overflows address space")
	}

	implementations := map[string]uint64{}
	itabAddr := types + itabOffset
	itabEnd := itabAddr + itabSize
	for itabAddr < itabEnd {
		if itabEnd-itabAddr < go127ITabBaseSize {
			return nil, errors.New("truncated Go 1.27 itab metadata")
		}

		interfaceType := resolveAddr(ef, itabAddr, relocs)
		concreteType := resolveAddr(ef, itabAddr+go127ITabTypeOffset, relocs)
		firstMethod := resolveAddr(ef, itabAddr+go127ITabFunOffset, relocs)
		if interfaceType == 0 || concreteType < types || concreteType >= types+itabOffset {
			return nil, errors.New("invalid Go 1.27 itab entry")
		}

		typeName, err := go127TypeName(ef, types, concreteType)
		if err != nil {
			return nil, err
		}
		if typeName != "" {
			implementations[typeName] = itabAddr
		}

		itabEntrySize := uint64(go127ITabBaseSize)
		if firstMethod != 0 {
			methodCount := readAddr(ef, interfaceType+go127InterfaceLenOff)
			if methodCount == 0 || methodCount-1 > (itabEnd-itabAddr-itabEntrySize)/8 {
				return nil, errors.New("invalid Go 1.27 itab method count")
			}
			itabEntrySize += (methodCount - 1) * 8
		}
		itabAddr += itabEntrySize
	}

	return implementations, nil
}

func go127TypeName(ef *elf.File, types, typeAddr uint64) (string, error) {
	typeHeader, err := readVirtualMemory(ef, typeAddr, go127TypeNameOffset+4)
	if err != nil {
		return "", fmt.Errorf("reading Go 1.27 type descriptor: %w", err)
	}

	nameOffset := int32(ef.ByteOrder.Uint32(typeHeader[go127TypeNameOffset:]))
	if nameOffset < 0 || uint64(nameOffset) > ^uint64(0)-types {
		return "", errors.New("invalid Go 1.27 type name offset")
	}
	nameAddr := types + uint64(nameOffset)
	nameHeader, err := readVirtualMemory(ef, nameAddr, 1+binary.MaxVarintLen64)
	if err != nil {
		return "", fmt.Errorf("reading Go 1.27 type name header: %w", err)
	}
	nameLen, varintLen := binary.Uvarint(nameHeader[1:])
	if varintLen <= 0 || nameLen > maxGoTypeNameLen {
		return "", errors.New("invalid Go 1.27 type name length")
	}
	nameBytes, err := readVirtualMemory(ef, nameAddr+1+uint64(varintLen), nameLen)
	if err != nil {
		return "", fmt.Errorf("reading Go 1.27 type name: %w", err)
	}

	name := string(nameBytes)
	if typeHeader[go127TypeTFlagOffset]&go127TFlagExtraStar != 0 {
		name = strings.TrimPrefix(name, "*")
	}
	return name, nil
}

func readVirtualMemory(ef *elf.File, addr, size uint64) ([]byte, error) {
	if size > uint64(^uint(0)>>1) || addr > ^uint64(0)-size {
		return nil, errors.New("invalid virtual memory range")
	}
	for _, prog := range ef.Progs {
		if prog.Type != elf.PT_LOAD || addr < prog.Vaddr || addr+size > prog.Vaddr+prog.Filesz {
			continue
		}
		data := make([]byte, int(size))
		if _, err := prog.ReadAt(data, int64(addr-prog.Vaddr)); err != nil {
			return nil, err
		}
		return data, nil
	}

	return nil, errors.New("virtual memory range is not file-backed")
}
