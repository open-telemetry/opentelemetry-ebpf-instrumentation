// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"strings"

	"go.opentelemetry.io/obi/internal/goabi"
	"go.opentelemetry.io/obi/internal/goversion"
)

const (
	prefixNew        = "go:itab."
	prefixOld        = "go.itab."
	prefixLen        = len(prefixNew)
	maxGoTypeNameLen = 4096
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
		if s.Name == "io.EOF" {
			implementations["io.EOF"] = s.Value
			continue
		}
		// Name is in format: go:itab.*net/http.response,net/http.ResponseWriter or go.itab.*net/http.response,net/http.ResponseWriter on old versions
		if !isITabEntry(s.Name) {
			continue
		}
		iType := iTabType(s.Name)
		if iType != "" {
			implementations[iType] = s.Value
		}
	}

	if _, ok := implementations["io.EOF"]; !ok {
		if eofAddr, err := findIoEOF(ef); err == nil && eofAddr != 0 {
			implementations["io.EOF"] = eofAddr
		}
	}

	versionString, _, err := getGoDetails(ef)
	if err != nil {
		return implementations, nil
	}
	targetVersion, err := goversion.Parse(versionString)
	if err != nil || targetVersion.Compare(minGoRuntimeTypeMetadataVersion) < 0 {
		return implementations, nil
	}

	moduleImplementations, err := findInterfaceImplsFromModuledata(ef, targetVersion)
	if err != nil {
		return nil, err
	}
	maps.Copy(implementations, moduleImplementations)
	return implementations, nil
}

func findIoEOF(ef *elf.File) (uint64, error) {
	if ef.Class != elf.ELFCLASS64 {
		return 0, errors.New("io.EOF discovery only supports 64-bit ELF")
	}

	rodataSec := ef.Section(".rodata")
	dataSec := ef.Section(".data")
	if rodataSec == nil || dataSec == nil {
		return 0, errors.New("missing .rodata or .data section")
	}

	rodata, err := rodataSec.Data()
	if err != nil {
		return 0, fmt.Errorf("reading .rodata section: %w", err)
	}
	data, err := dataSec.Data()
	if err != nil {
		return 0, fmt.Errorf("reading .data section: %w", err)
	}

	relocs := buildRelocationInfo(ef)

	strAddrs := map[uint64]struct{}{}
	pos := 0
	target := []byte("EOF")
	for {
		idx := bytes.Index(rodata[pos:], target)
		if idx == -1 {
			break
		}
		strAddrs[rodataSec.Addr+uint64(pos+idx)] = struct{}{}
		pos += idx + 1
	}

	errStrAddrs := map[uint64]struct{}{}
	for off := 0; off+16 <= len(data); off += 8 {
		strLen := ef.ByteOrder.Uint64(data[off+8 : off+16])
		if strLen != 3 {
			continue
		}
		strPtr := resolveAddr(ef, dataSec.Addr+uint64(off), relocs)
		if _, ok := strAddrs[strPtr]; ok {
			errStrAddrs[dataSec.Addr+uint64(off)] = struct{}{}
		}
	}

	var eofCandidates []uint64
	for off := 0; off+16 <= len(data); off += 8 {
		dataPtr := resolveAddr(ef, dataSec.Addr+uint64(off+8), relocs)
		if _, ok := errStrAddrs[dataPtr]; !ok {
			continue
		}
		itab := resolveAddr(ef, dataSec.Addr+uint64(off), relocs)
		if itab == 0 {
			continue
		}
		eofCandidates = append(eofCandidates, dataSec.Addr+uint64(off))
	}

	if len(eofCandidates) == 1 {
		return eofCandidates[0], nil
	}
	if len(eofCandidates) == 0 {
		return 0, errors.New("io.EOF not found in .data")
	}

	counts := ioEOFReferenceCounts(ef, eofCandidates)
	var selected uint64
	max := 0
	unique := false
	for _, candidate := range eofCandidates {
		count := counts[candidate]
		if count > max {
			selected = candidate
			max = count
			unique = true
		} else if count == max {
			unique = false
		}
	}
	if unique && max > 0 {
		return selected, nil
	}
	return 0, fmt.Errorf("ambiguous io.EOF candidates found: %d", len(eofCandidates))
}

func ioEOFReferenceCounts(ef *elf.File, candidates []uint64) map[uint64]int {
	counts := make(map[uint64]int, len(candidates))
	known := make(map[uint64]struct{}, len(candidates))
	for _, candidate := range candidates {
		known[candidate] = struct{}{}
	}
	for _, value := range buildRelocationInfo(ef).explicit {
		if _, ok := known[value]; ok {
			counts[value]++
		}
	}

	for _, prog := range ef.Progs {
		if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 {
			continue
		}
		text, err := readProgramData(prog)
		if err != nil {
			continue
		}
		for i := 0; i+8 <= len(text); i++ {
			value := ef.ByteOrder.Uint64(text[i : i+8])
			if _, ok := known[value]; ok {
				counts[value]++
			}
		}

		if ef.Machine == elf.EM_X86_64 {
			for i := 0; i+7 <= len(text); i++ {
				if !isRipRelativeMemoryReference(text, i) {
					continue
				}
				disp := int64(int32(ef.ByteOrder.Uint32(text[i+3 : i+7])))
				address := prog.Vaddr + uint64(i) + 7 + uint64(disp)
				if _, ok := known[address]; ok {
					counts[address]++
				}
			}
		} else if ef.Machine == elf.EM_AARCH64 {
			for i := 0; i+8 <= len(text); i += 4 {
				address, ok := arm64PageAddress(text, i, prog.Vaddr)
				if !ok {
					continue
				}
				if _, ok := known[address]; ok {
					counts[address]++
				}
			}
		}
	}
	return counts
}

func readProgramData(prog *elf.Prog) ([]byte, error) {
	if prog.Filesz > uint64(^uint(0)>>1) {
		return nil, errors.New("executable segment is too large")
	}
	data := make([]byte, int(prog.Filesz))
	if _, err := prog.ReadAt(data, 0); err != nil {
		return nil, err
	}
	return data, nil
}

func isRipRelativeMemoryReference(text []byte, i int) bool {
	if text[i]&0xf0 != 0x40 || i+7 > len(text) {
		return false
	}
	opcode := text[i+1]
	if opcode != 0x8b && opcode != 0x8d && opcode != 0x89 && opcode != 0x39 && opcode != 0x3b &&
		opcode != 0x81 && opcode != 0x83 {
		return false
	}
	return text[i+2]&0xc7 == 0x05
}

func arm64PageAddress(text []byte, i int, base uint64) (uint64, bool) {
	adrp := binary.LittleEndian.Uint32(text[i : i+4])
	if adrp&0x9f000000 != 0x90000000 {
		return 0, false
	}

	register := adrp & 0x1f
	immlo := (adrp >> 29) & 0x3
	immhi := (adrp >> 5) & 0x7ffff
	imm := int64((immhi << 2) | immlo)
	if imm&(1<<20) != 0 {
		imm |= ^int64(0) << 21
	}
	page := (base + uint64(i)) &^ 0xfff
	page = uint64(int64(page) + (imm << 12))

	for j := i + 4; j+4 <= len(text) && j <= i+16; j += 4 {
		add := binary.LittleEndian.Uint32(text[j : j+4])
		if add&0x7f000000 != 0x11000000 {
			continue
		}
		if add&0x1f != register || (add>>5)&0x1f != register {
			continue
		}
		return page + uint64((add>>10)&0xfff), true
	}
	return 0, false
}

func findInterfaceImplsFromModuledata(ef *elf.File, targetVersion goversion.Version) (map[string]uint64, error) {
	if ef.Class != elf.ELFCLASS64 {
		return nil, errors.New("go runtime metadata discovery only supports 64-bit ELF")
	}

	gopclntab := ef.Section(".gopclntab")
	if gopclntab == nil {
		return nil, errors.New("no .gopclntab section")
	}

	runtimeABI, err := loadGoRuntimeABI(ef, targetVersion)
	if err != nil {
		return nil, err
	}
	mdoffs := runtimeABI.Moduledata
	metadata := runtimeABI.TypeMetadata
	if metadata == nil {
		return nil, errors.New("go runtime type metadata ABI is unavailable")
	}
	relocs := buildRelocationInfo(ef)
	for _, candidate := range moduledataCandidates(ef, gopclntab.Addr, mdoffs, relocs) {
		if !inWritableSection(ef, candidate) {
			continue
		}
		if _, ok := validateModuledata(ef, candidate, gopclntab.Addr, gopclntab.Size, mdoffs, relocs); !ok {
			continue
		}

		return readGoInterfaceImpls(ef, candidate, mdoffs, metadata, relocs)
	}

	return nil, errors.New("runtime.moduledata not found")
}

func readGoInterfaceImpls(
	ef *elf.File,
	moduledata uint64,
	mdoffs goabi.Moduledata,
	abi *goabi.TypeMetadata,
	relocs relocationInfo,
) (map[string]uint64, error) {
	types := resolveAddr(ef, moduledata+mdoffs.Types, relocs)
	typeDescLen := readAddr(ef, moduledata+mdoffs.TypeDescLen)
	itabOffset := readAddr(ef, moduledata+mdoffs.ITabOffset)
	itabSize := readAddr(ef, moduledata+mdoffs.ITabSize)
	if types == 0 || typeDescLen == 0 || itabOffset < typeDescLen || itabSize == 0 {
		return nil, errors.New("invalid Go runtime type metadata")
	}
	if itabOffset > ^uint64(0)-types || itabSize > ^uint64(0)-(types+itabOffset) {
		return nil, errors.New("go itab metadata overflows address space")
	}

	implementations := map[string]uint64{}
	itabAddr := types + itabOffset
	itabEnd := itabAddr + itabSize
	itabFuncEntrySize := abi.ITabFuncEntrySize()
	for itabAddr < itabEnd {
		if itabEnd-itabAddr < abi.ITabBaseSize {
			return nil, errors.New("truncated Go itab metadata")
		}

		interfaceType := resolveAddr(ef, itabAddr+abi.ITabInterOffset, relocs)
		concreteType := resolveAddr(ef, itabAddr+abi.ITabTypeOffset, relocs)
		firstMethod := resolveAddr(ef, itabAddr+abi.ITabFunOffset, relocs)
		if interfaceType == 0 || concreteType < types || concreteType >= types+itabOffset {
			return nil, errors.New("invalid Go itab entry")
		}

		typeName, err := goTypeName(ef, types, concreteType, abi)
		if err != nil {
			return nil, err
		}
		if typeName != "" {
			implementations[typeName] = itabAddr
		}

		itabEntrySize := abi.ITabBaseSize
		if firstMethod != 0 {
			methodCount := readAddr(ef, interfaceType+abi.InterfaceMethodCountOffset())
			if methodCount == 0 ||
				methodCount-1 > (itabEnd-itabAddr-itabEntrySize)/itabFuncEntrySize {
				return nil, errors.New("invalid Go itab method count")
			}
			itabEntrySize += (methodCount - 1) * itabFuncEntrySize
		}
		itabAddr += itabEntrySize
	}

	return implementations, nil
}

func goTypeName(ef *elf.File, types, typeAddr uint64, abi *goabi.TypeMetadata) (string, error) {
	typeHeader, err := readVirtualMemory(ef, typeAddr, abi.TypeHeaderSize())
	if err != nil {
		return "", fmt.Errorf("reading Go type descriptor: %w", err)
	}

	nameOffset := int32(ef.ByteOrder.Uint32(typeHeader[abi.TypeNameOffset:]))
	if nameOffset < 0 || uint64(nameOffset) > ^uint64(0)-types {
		return "", errors.New("invalid Go type name offset")
	}
	name, err := goTypeMetadataName(ef, types, nameOffset)
	if err != nil {
		return "", fmt.Errorf("reading Go type name: %w", err)
	}
	if typeHeader[abi.TypeTFlagOffset]&byte(abi.TFlagExtraStarMask) != 0 {
		name = strings.TrimPrefix(name, "*")
	}

	pkgPath, err := goTypePackagePath(ef, types, typeAddr, typeHeader, abi)
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

func goTypePackagePath(
	ef *elf.File,
	types, typeAddr uint64,
	typeHeader []byte,
	abi *goabi.TypeMetadata,
) (string, error) {
	if typeHeader[abi.TypeTFlagOffset]&byte(abi.TFlagUncommonMask) == 0 {
		return "", nil
	}

	uncommonOffset := abi.UncommonTypeOffset(typeHeader[abi.TypeKindOffset])
	pkgPathBytes, err := readVirtualMemory(
		ef,
		typeAddr+uncommonOffset+abi.UncommonPkgPathOffset,
		abi.NameOffsetSize,
	)
	if err != nil {
		return "", fmt.Errorf("reading Go type package path offset: %w", err)
	}
	pkgPathOffset := int32(ef.ByteOrder.Uint32(pkgPathBytes))
	if pkgPathOffset == 0 {
		return "", nil
	}
	pkgPath, err := goTypeMetadataName(ef, types, pkgPathOffset)
	if err != nil {
		return "", fmt.Errorf("reading Go type package path: %w", err)
	}
	return pkgPath, nil
}

func goTypeMetadataName(ef *elf.File, types uint64, nameOffset int32) (string, error) {
	if nameOffset < 0 || uint64(nameOffset) > ^uint64(0)-types {
		return "", errors.New("invalid Go name offset")
	}
	nameAddr := types + uint64(nameOffset)
	nameHeader, err := readVirtualMemory(ef, nameAddr, 1+binary.MaxVarintLen64)
	if err != nil {
		return "", err
	}
	nameLen, varintLen := binary.Uvarint(nameHeader[1:])
	if varintLen <= 0 || nameLen > maxGoTypeNameLen {
		return "", errors.New("invalid Go name length")
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
