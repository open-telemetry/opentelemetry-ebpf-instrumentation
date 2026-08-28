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
	go127TypeKindOffset  = 23
	go127TypeNameOffset  = 40
	go127InterfaceLenOff = 64
	go127ITabTypeOffset  = 8
	go127ITabFunOffset   = 24
	go127ITabBaseSize    = 32
	go127TFlagUncommon   = 1 << 0
	go127TFlagExtraStar  = 1 << 1
	go127KindMask        = 1<<5 - 1
	go127KindArray       = 17
	go127KindChan        = 18
	go127KindFunc        = 19
	go127KindInterface   = 20
	go127KindMap         = 21
	go127KindPointer     = 22
	go127KindSlice       = 23
	go127KindStruct      = 25
	go127UncommonArray   = 72
	go127UncommonChan    = 64
	go127UncommonDefault = 48
	go127UncommonMap     = 136
	go127UncommonOneWord = 56
	go127UncommonWithPkg = 80
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
	name, err := go127Name(ef, types, nameOffset)
	if err != nil {
		return "", fmt.Errorf("reading Go 1.27 type name: %w", err)
	}
	if typeHeader[go127TypeTFlagOffset]&go127TFlagExtraStar != 0 {
		name = strings.TrimPrefix(name, "*")
	}

	pkgPath, err := go127TypePackagePath(ef, types, typeAddr, typeHeader)
	if err != nil {
		return "", err
	}
	if pkgPath != "" {
		pointerPrefix := ""
		shortName := name
		if strings.HasPrefix(shortName, "*") {
			pointerPrefix = "*"
			shortName = strings.TrimPrefix(shortName, "*")
		}
		if dot := strings.IndexByte(shortName, '.'); dot >= 0 {
			shortName = shortName[dot+1:]
		}
		name = pointerPrefix + pkgPath + "." + shortName
	}
	return name, nil
}

func go127TypePackagePath(
	ef *elf.File,
	types, typeAddr uint64,
	typeHeader []byte,
) (string, error) {
	if typeHeader[go127TypeTFlagOffset]&go127TFlagUncommon == 0 {
		return "", nil
	}

	uncommonOffset := go127UncommonOffset(typeHeader[go127TypeKindOffset] & go127KindMask)
	pkgPathBytes, err := readVirtualMemory(ef, typeAddr+uncommonOffset, 4)
	if err != nil {
		return "", fmt.Errorf("reading Go 1.27 type package path offset: %w", err)
	}
	pkgPathOffset := int32(ef.ByteOrder.Uint32(pkgPathBytes))
	if pkgPathOffset == 0 {
		return "", nil
	}
	pkgPath, err := go127Name(ef, types, pkgPathOffset)
	if err != nil {
		return "", fmt.Errorf("reading Go 1.27 type package path: %w", err)
	}
	return pkgPath, nil
}

func go127UncommonOffset(kind byte) uint64 {
	switch kind {
	case go127KindArray:
		return go127UncommonArray
	case go127KindChan:
		return go127UncommonChan
	case go127KindFunc, go127KindPointer, go127KindSlice:
		return go127UncommonOneWord
	case go127KindInterface, go127KindStruct:
		return go127UncommonWithPkg
	case go127KindMap:
		return go127UncommonMap
	default:
		return go127UncommonDefault
	}
}

func go127Name(ef *elf.File, types uint64, nameOffset int32) (string, error) {
	if nameOffset < 0 || uint64(nameOffset) > ^uint64(0)-types {
		return "", errors.New("invalid Go 1.27 name offset")
	}
	nameAddr := types + uint64(nameOffset)
	nameHeader, err := readVirtualMemory(ef, nameAddr, 1+binary.MaxVarintLen64)
	if err != nil {
		return "", err
	}
	nameLen, varintLen := binary.Uvarint(nameHeader[1:])
	if varintLen <= 0 || nameLen > maxGoTypeNameLen {
		return "", errors.New("invalid Go 1.27 name length")
	}
	nameBytes, err := readVirtualMemory(ef, nameAddr+1+uint64(varintLen), nameLen)
	if err != nil {
		return "", err
	}
	return string(nameBytes), nil
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
