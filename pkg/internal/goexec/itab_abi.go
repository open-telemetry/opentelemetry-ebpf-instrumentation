// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"

	trackeroffsets "github.com/grafana/go-offsets-tracker/pkg/offsets"
	"golang.org/x/mod/semver"

	"go.opentelemetry.io/obi/internal/goabi"
)

type goTypeMetadataABI struct {
	typeTFlagOffset       uint64
	typeKindOffset        uint64
	typeNameOffset        uint64
	typeSize              uint64
	tflagSize             uint64
	kindSize              uint64
	nameOffsetSize        uint64
	interfaceMethods      uint64
	sliceLenOffset        uint64
	interfaceLenOffset    uint64
	itabInterOffset       uint64
	itabTypeOffset        uint64
	itabFunOffset         uint64
	itabBaseSize          uint64
	itabFuncSize          uint64
	uncommonPkgPathOffset uint64
	tflagUncommon         uint64
	tflagExtraStar        uint64
	kindDirectIface       uint64
	kindArray             uint64
	kindChan              uint64
	kindFunc              uint64
	kindInterface         uint64
	kindMap               uint64
	kindPointer           uint64
	kindSlice             uint64
	kindStruct            uint64
	uncommonArray         uint64
	uncommonChan          uint64
	uncommonFunc          uint64
	uncommonInterface     uint64
	uncommonMap           uint64
	uncommonPointer       uint64
	uncommonSlice         uint64
	uncommonStruct        uint64
}

type goRuntimeABI struct {
	moduledata   moduledataOffsets
	typeMetadata goTypeMetadataABI
}

func loadGoRuntimeABI(ef *elf.File, goVersion string) (goRuntimeABI, error) {
	abi, err := resolveGoRuntimeABI(
		func() (goabi.ABI, error) {
			data, err := ef.DWARF()
			if err != nil {
				return goabi.ABI{}, err
			}
			return goabi.Extract(data, goVersion)
		},
		func() (goabi.ABI, error) {
			return loadGeneratedGoRuntimeABI(goVersion)
		},
	)
	if err != nil {
		return goRuntimeABI{}, err
	}
	return convertGoRuntimeABI(abi), nil
}

func resolveGoRuntimeABI(
	dynamic func() (goabi.ABI, error),
	generated func() (goabi.ABI, error),
) (goabi.ABI, error) {
	abi, dynamicErr := dynamic()
	if dynamicErr == nil {
		return abi, nil
	}
	abi, generatedErr := generated()
	if generatedErr == nil {
		return abi, nil
	}
	return goabi.ABI{}, fmt.Errorf(
		"go runtime ABI unavailable: %w",
		errors.Join(
			fmt.Errorf("DWARF discovery: %w", dynamicErr),
			fmt.Errorf("generated fallback: %w", generatedErr),
		),
	)
}

func loadGeneratedGoRuntimeABI(goVersion string) (goabi.ABI, error) {
	track, err := trackeroffsets.Read(bytes.NewBufferString(prefetchedOffsets))
	if err != nil {
		return goabi.ABI{}, fmt.Errorf("reading generated Go ABI facts: %w", err)
	}
	return goabi.FromLookup(goVersion, func(definition goabi.Definition) (uint64, error) {
		return generatedABIFact(track, definition.OutputType, definition.OutputField, goVersion)
	})
}

func convertGoRuntimeABI(abi goabi.ABI) goRuntimeABI {
	moduledata := abi.Moduledata
	metadata := abi.TypeMetadata
	return goRuntimeABI{
		moduledata: moduledataOffsets{
			pcHeader:    moduledata.PCHeader,
			pclntable:   moduledata.PCLNTable,
			minpc:       moduledata.MinPC,
			maxpc:       moduledata.MaxPC,
			text:        moduledata.Text,
			etext:       moduledata.EText,
			types:       moduledata.Types,
			typedesclen: moduledata.TypeDescLen,
			itaboffset:  moduledata.ITabOffset,
			itabsize:    moduledata.ITabSize,
		},
		typeMetadata: goTypeMetadataABI{
			typeTFlagOffset:       metadata.TypeTFlagOffset,
			typeKindOffset:        metadata.TypeKindOffset,
			typeNameOffset:        metadata.TypeNameOffset,
			typeSize:              metadata.TypeSize,
			tflagSize:             metadata.TFlagSize,
			kindSize:              metadata.KindSize,
			nameOffsetSize:        metadata.NameOffsetSize,
			interfaceMethods:      metadata.InterfaceMethods,
			sliceLenOffset:        metadata.SliceLenOffset,
			interfaceLenOffset:    metadata.InterfaceLenOffset,
			itabInterOffset:       metadata.ITabInterOffset,
			itabTypeOffset:        metadata.ITabTypeOffset,
			itabFunOffset:         metadata.ITabFunOffset,
			itabBaseSize:          metadata.ITabBaseSize,
			itabFuncSize:          metadata.ITabFuncSize,
			uncommonPkgPathOffset: metadata.UncommonPkgPathOffset,
			tflagUncommon:         metadata.TFlagUncommon,
			tflagExtraStar:        metadata.TFlagExtraStar,
			kindDirectIface:       metadata.KindDirectIface,
			kindArray:             metadata.KindArray,
			kindChan:              metadata.KindChan,
			kindFunc:              metadata.KindFunc,
			kindInterface:         metadata.KindInterface,
			kindMap:               metadata.KindMap,
			kindPointer:           metadata.KindPointer,
			kindSlice:             metadata.KindSlice,
			kindStruct:            metadata.KindStruct,
			uncommonArray:         metadata.UncommonArray,
			uncommonChan:          metadata.UncommonChan,
			uncommonFunc:          metadata.UncommonFunc,
			uncommonInterface:     metadata.UncommonInterface,
			uncommonMap:           metadata.UncommonMap,
			uncommonPointer:       metadata.UncommonPointer,
			uncommonSlice:         metadata.UncommonSlice,
			uncommonStruct:        metadata.UncommonStruct,
		},
	}
}

func generatedABIFact(
	track *trackeroffsets.Track,
	typeName string,
	factName string,
	goVersion string,
) (uint64, error) {
	fields, ok := track.Data[typeName]
	if !ok {
		return 0, fmt.Errorf("missing generated Go ABI type %s", typeName)
	}
	fact, ok := fields[factName]
	if !ok {
		return 0, fmt.Errorf("missing generated Go ABI fact %s.%s", typeName, factName)
	}

	target := goVersionPattern.FindString(goVersion)
	oldest := goVersionPattern.FindString(fact.Versions.Oldest)
	newest := goVersionPattern.FindString(fact.Versions.Newest)
	if target == "" || oldest == "" || newest == "" ||
		semver.Compare(semver.MajorMinor("v"+target), semver.MajorMinor("v"+oldest)) < 0 ||
		semver.Compare(semver.MajorMinor("v"+target), semver.MajorMinor("v"+newest)) > 0 {
		return 0, fmt.Errorf("go %s runtime ABI is not generated", goVersion)
	}

	value, ok := track.Find(typeName, factName, target)
	if !ok {
		return 0, fmt.Errorf("missing generated Go ABI fact %s.%s for Go %s", typeName, factName, goVersion)
	}
	return value, nil
}

func (abi goTypeMetadataABI) typeHeaderSize() uint64 {
	size := abi.typeNameOffset + abi.nameOffsetSize
	if end := abi.typeTFlagOffset + abi.tflagSize; end > size {
		size = end
	}
	if end := abi.typeKindOffset + abi.kindSize; end > size {
		size = end
	}
	return size
}

func (abi goTypeMetadataABI) uncommonOffset(kind byte) uint64 {
	kind &= byte(abi.kindDirectIface - 1)
	switch uint64(kind) {
	case abi.kindArray:
		return abi.uncommonArray
	case abi.kindChan:
		return abi.uncommonChan
	case abi.kindFunc:
		return abi.uncommonFunc
	case abi.kindInterface:
		return abi.uncommonInterface
	case abi.kindMap:
		return abi.uncommonMap
	case abi.kindPointer:
		return abi.uncommonPointer
	case abi.kindSlice:
		return abi.uncommonSlice
	case abi.kindStruct:
		return abi.uncommonStruct
	default:
		return abi.typeSize
	}
}
