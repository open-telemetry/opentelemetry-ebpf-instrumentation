// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"strings"

	trackeroffsets "github.com/grafana/go-offsets-tracker/pkg/offsets"

	"go.opentelemetry.io/obi/internal/goabi"
	"go.opentelemetry.io/obi/internal/goversion"
)

type goTypeMetadataABI struct {
	typeTFlagOffset            uint64
	typeKindOffset             uint64
	typeNameOffset             uint64
	interfaceMethodCountOffset uint64
	itabInterOffset            uint64
	itabTypeOffset             uint64
	itabFunOffset              uint64
	uncommonPkgPathOffset      uint64
	arrayUncommonOffset        uint64
	chanUncommonOffset         uint64
	funcUncommonOffset         uint64
	interfaceUncommonOffset    uint64
	mapUncommonOffset          uint64
	pointerUncommonOffset      uint64
	sliceUncommonOffset        uint64
	structUncommonOffset       uint64

	typeSize          uint64
	tflagSize         uint64
	kindSize          uint64
	nameOffsetSize    uint64
	itabBaseSize      uint64
	itabFuncEntrySize uint64

	tflagUncommonMask   uint64
	tflagExtraStarMask  uint64
	kindDirectIfaceFlag uint64
	arrayKind           uint64
	chanKind            uint64
	funcKind            uint64
	interfaceKind       uint64
	mapKind             uint64
	pointerKind         uint64
	sliceKind           uint64
	structKind          uint64
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
	target, err := goversion.Parse(goVersion)
	if err != nil {
		return goabi.ABI{}, err
	}
	track, err := trackeroffsets.Read(bytes.NewBufferString(prefetchedOffsets))
	if err != nil {
		return goabi.ABI{}, fmt.Errorf("reading generated Go ABI facts: %w", err)
	}
	return goabi.FromLookup(target.String(), func(requirement goabi.Requirement) (uint64, error) {
		return generatedABIFact(track, requirement.OutputType, requirement.OutputField, target)
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
			typeTFlagOffset:            metadata.TypeTFlagOffset,
			typeKindOffset:             metadata.TypeKindOffset,
			typeNameOffset:             metadata.TypeNameOffset,
			interfaceMethodCountOffset: metadata.InterfaceMethodCountOffset,
			itabInterOffset:            metadata.ITabInterOffset,
			itabTypeOffset:             metadata.ITabTypeOffset,
			itabFunOffset:              metadata.ITabFunOffset,
			uncommonPkgPathOffset:      metadata.UncommonPkgPathOffset,
			arrayUncommonOffset:        metadata.ArrayUncommonOffset,
			chanUncommonOffset:         metadata.ChanUncommonOffset,
			funcUncommonOffset:         metadata.FuncUncommonOffset,
			interfaceUncommonOffset:    metadata.InterfaceUncommonOffset,
			mapUncommonOffset:          metadata.MapUncommonOffset,
			pointerUncommonOffset:      metadata.PointerUncommonOffset,
			sliceUncommonOffset:        metadata.SliceUncommonOffset,
			structUncommonOffset:       metadata.StructUncommonOffset,

			typeSize:          metadata.TypeSize,
			tflagSize:         metadata.TFlagSize,
			kindSize:          metadata.KindSize,
			nameOffsetSize:    metadata.NameOffsetSize,
			itabBaseSize:      metadata.ITabBaseSize,
			itabFuncEntrySize: metadata.ITabFuncEntrySize,

			tflagUncommonMask:   metadata.TFlagUncommonMask,
			tflagExtraStarMask:  metadata.TFlagExtraStarMask,
			kindDirectIfaceFlag: metadata.KindDirectIfaceFlag,
			arrayKind:           metadata.ArrayKind,
			chanKind:            metadata.ChanKind,
			funcKind:            metadata.FuncKind,
			interfaceKind:       metadata.InterfaceKind,
			mapKind:             metadata.MapKind,
			pointerKind:         metadata.PointerKind,
			sliceKind:           metadata.SliceKind,
			structKind:          metadata.StructKind,
		},
	}
}

func generatedABIFact(
	track *trackeroffsets.Track,
	typeName string,
	factName string,
	target goversion.Version,
) (uint64, error) {
	fields, ok := track.Data[typeName]
	if !ok {
		return 0, fmt.Errorf("missing generated Go ABI type %s", typeName)
	}
	fact, ok := fields[factName]
	if !ok {
		return 0, fmt.Errorf("missing generated Go ABI fact %s.%s", typeName, factName)
	}

	covered, err := generatedVersionCovered(target, fact.Versions.Oldest, fact.Versions.Newest)
	if err != nil {
		return 0, fmt.Errorf("invalid generated Go ABI coverage for %s.%s: %w", typeName, factName, err)
	}
	if !covered {
		return 0, fmt.Errorf("runtime ABI is not generated for %s", target.String())
	}

	release := strings.TrimPrefix(target.String(), "go")
	value, ok := track.Find(typeName, factName, release)
	if !ok {
		return 0, fmt.Errorf("missing generated Go ABI fact %s.%s for %s", typeName, factName, target.String())
	}
	return value, nil
}

func generatedVersionCovered(target goversion.Version, oldestValue, newestValue string) (bool, error) {
	if strings.Contains(target.String(), "-") {
		return false, nil
	}
	oldest, err := goversion.Parse(oldestValue)
	if err != nil {
		return false, err
	}
	newest, err := goversion.Parse(newestValue)
	if err != nil {
		return false, err
	}
	return target.Compare(oldest) >= 0 && target.Compare(newest) <= 0, nil
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
	kind &= byte(abi.kindDirectIfaceFlag - 1)
	switch uint64(kind) {
	case abi.arrayKind:
		return abi.arrayUncommonOffset
	case abi.chanKind:
		return abi.chanUncommonOffset
	case abi.funcKind:
		return abi.funcUncommonOffset
	case abi.interfaceKind:
		return abi.interfaceUncommonOffset
	case abi.mapKind:
		return abi.mapUncommonOffset
	case abi.pointerKind:
		return abi.pointerUncommonOffset
	case abi.sliceKind:
		return abi.sliceUncommonOffset
	case abi.structKind:
		return abi.structUncommonOffset
	default:
		return abi.typeSize
	}
}
