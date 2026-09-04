// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package goabi discovers the private Go runtime ABI used by OBI.
package goabi // import "go.opentelemetry.io/obi/internal/goabi"

import (
	"debug/dwarf"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"golang.org/x/mod/semver"
)

// SizeField is the generated offset field used to store a DWARF type size.
const SizeField = "$size"

// Kind identifies how an ABI fact is represented in DWARF.
type Kind uint8

const (
	// Field is a struct field byte offset.
	Field Kind = iota
	// Size is a type's byte size.
	Size
	// Constant is an integer constant value.
	Constant
)

// Definition describes one versioned ABI fact and its generated output key.
type Definition struct {
	Kind        Kind
	DwarfName   string
	DwarfField  string
	OutputType  string
	OutputField string
	Since       string
}

// Key returns the generated type-and-field key for a definition.
func (d Definition) Key() string {
	return d.OutputType + "." + d.OutputField
}

// Fact is a resolved ABI definition and value.
type Fact struct {
	Definition Definition
	Value      uint64
}

// Moduledata contains the runtime.moduledata field offsets OBI reads.
type Moduledata struct {
	PCHeader    uint64
	PCLNTable   uint64
	MinPC       uint64
	MaxPC       uint64
	Text        uint64
	EText       uint64
	Types       uint64
	TypeDescLen uint64
	ITabOffset  uint64
	ITabSize    uint64
}

// TypeMetadata contains the internal/abi layout used to decode Go type data.
type TypeMetadata struct {
	TypeTFlagOffset       uint64
	TypeKindOffset        uint64
	TypeNameOffset        uint64
	TypeSize              uint64
	TFlagSize             uint64
	KindSize              uint64
	NameOffsetSize        uint64
	InterfaceMethods      uint64
	SliceLenOffset        uint64
	InterfaceLenOffset    uint64
	ITabInterOffset       uint64
	ITabTypeOffset        uint64
	ITabFunOffset         uint64
	ITabBaseSize          uint64
	ITabFuncSize          uint64
	UncommonPkgPathOffset uint64
	TFlagUncommon         uint64
	TFlagExtraStar        uint64
	KindDirectIface       uint64
	KindArray             uint64
	KindChan              uint64
	KindFunc              uint64
	KindInterface         uint64
	KindMap               uint64
	KindPointer           uint64
	KindSlice             uint64
	KindStruct            uint64
	UncommonArray         uint64
	UncommonChan          uint64
	UncommonFunc          uint64
	UncommonInterface     uint64
	UncommonMap           uint64
	UncommonPointer       uint64
	UncommonSlice         uint64
	UncommonStruct        uint64
}

// ABI is one complete, validated set of ABI facts for a Go version.
type ABI struct {
	Moduledata   Moduledata
	TypeMetadata TypeMetadata
	facts        []Fact
}

// Facts returns the resolved facts in stable key order.
func (a ABI) Facts() []Fact {
	return append([]Fact(nil), a.facts...)
}

const (
	go117 = "1.17.0"
	go127 = "1.27.0"
)

var definitions = []Definition{
	{Kind: Field, DwarfName: "runtime.moduledata", DwarfField: "pcHeader", OutputType: "runtime.moduledata", OutputField: "pcHeader", Since: go117},
	{Kind: Field, DwarfName: "runtime.moduledata", DwarfField: "pclntable", OutputType: "runtime.moduledata", OutputField: "pclntable", Since: go117},
	{Kind: Field, DwarfName: "runtime.moduledata", DwarfField: "minpc", OutputType: "runtime.moduledata", OutputField: "minpc", Since: go117},
	{Kind: Field, DwarfName: "runtime.moduledata", DwarfField: "maxpc", OutputType: "runtime.moduledata", OutputField: "maxpc", Since: go117},
	{Kind: Field, DwarfName: "runtime.moduledata", DwarfField: "text", OutputType: "runtime.moduledata", OutputField: "text", Since: go117},
	{Kind: Field, DwarfName: "runtime.moduledata", DwarfField: "etext", OutputType: "runtime.moduledata", OutputField: "etext", Since: go117},
	{Kind: Field, DwarfName: "runtime.moduledata", DwarfField: "types", OutputType: "runtime.moduledata", OutputField: "types", Since: go127},
	{Kind: Field, DwarfName: "runtime.moduledata", DwarfField: "typedesclen", OutputType: "runtime.moduledata", OutputField: "typedesclen", Since: go127},
	{Kind: Field, DwarfName: "runtime.moduledata", DwarfField: "itaboffset", OutputType: "runtime.moduledata", OutputField: "itaboffset", Since: go127},
	{Kind: Field, DwarfName: "runtime.moduledata", DwarfField: "itabsize", OutputType: "runtime.moduledata", OutputField: "itabsize", Since: go127},
	{Kind: Field, DwarfName: "internal/abi.Type", DwarfField: "TFlag", OutputType: "internal/abi.Type", OutputField: "TFlag", Since: go127},
	{Kind: Field, DwarfName: "internal/abi.Type", DwarfField: "Kind_", OutputType: "internal/abi.Type", OutputField: "Kind_", Since: go127},
	{Kind: Field, DwarfName: "internal/abi.Type", DwarfField: "Str", OutputType: "internal/abi.Type", OutputField: "Str", Since: go127},
	{Kind: Field, DwarfName: "internal/abi.InterfaceType", DwarfField: "Methods", OutputType: "internal/abi.InterfaceType", OutputField: "Methods", Since: go127},
	{Kind: Field, DwarfName: "internal/abi.ITab", DwarfField: "Inter", OutputType: "internal/abi.ITab", OutputField: "Inter", Since: go127},
	{Kind: Field, DwarfName: "internal/abi.ITab", DwarfField: "Type", OutputType: "internal/abi.ITab", OutputField: "Type", Since: go127},
	{Kind: Field, DwarfName: "internal/abi.ITab", DwarfField: "Fun", OutputType: "internal/abi.ITab", OutputField: "Fun", Since: go127},
	{Kind: Field, DwarfName: "internal/abi.UncommonType", DwarfField: "PkgPath", OutputType: "internal/abi.UncommonType", OutputField: "PkgPath", Since: go127},
	{Kind: Field, DwarfName: "[]internal/abi.Imethod", DwarfField: "len", OutputType: "[]internal/abi.Imethod", OutputField: "len", Since: go127},
	{Kind: Size, DwarfName: "internal/abi.Type", OutputType: "internal/abi.Type", OutputField: SizeField, Since: go127},
	{Kind: Size, DwarfName: "internal/abi.ArrayType", OutputType: "internal/abi.ArrayType", OutputField: SizeField, Since: go127},
	{Kind: Size, DwarfName: "internal/abi.ChanType", OutputType: "internal/abi.ChanType", OutputField: SizeField, Since: go127},
	{Kind: Size, DwarfName: "internal/abi.FuncType", OutputType: "internal/abi.FuncType", OutputField: SizeField, Since: go127},
	{Kind: Size, DwarfName: "internal/abi.InterfaceType", OutputType: "internal/abi.InterfaceType", OutputField: SizeField, Since: go127},
	{Kind: Size, DwarfName: "internal/abi.MapType", OutputType: "internal/abi.MapType", OutputField: SizeField, Since: go127},
	{Kind: Size, DwarfName: "internal/abi.PtrType", OutputType: "internal/abi.PtrType", OutputField: SizeField, Since: go127},
	{Kind: Size, DwarfName: "internal/abi.SliceType", OutputType: "internal/abi.SliceType", OutputField: SizeField, Since: go127},
	{Kind: Size, DwarfName: "internal/abi.StructType", OutputType: "internal/abi.StructType", OutputField: SizeField, Since: go127},
	{Kind: Size, DwarfName: "internal/abi.ITab", OutputType: "internal/abi.ITab", OutputField: SizeField, Since: go127},
	{Kind: Size, DwarfName: "internal/abi.TFlag", OutputType: "internal/abi.TFlag", OutputField: SizeField, Since: go127},
	{Kind: Size, DwarfName: "internal/abi.Kind", OutputType: "internal/abi.Kind", OutputField: SizeField, Since: go127},
	{Kind: Size, DwarfName: "internal/abi.NameOff", OutputType: "internal/abi.NameOff", OutputField: SizeField, Since: go127},
	{Kind: Constant, DwarfName: "internal/abi.TFlagUncommon", OutputType: "internal/abi", OutputField: "TFlagUncommon", Since: go127},
	{Kind: Constant, DwarfName: "internal/abi.TFlagExtraStar", OutputType: "internal/abi", OutputField: "TFlagExtraStar", Since: go127},
	{Kind: Constant, DwarfName: "internal/abi.KindDirectIface", OutputType: "internal/abi", OutputField: "KindDirectIface", Since: go127},
	{Kind: Constant, DwarfName: "internal/abi.Array", OutputType: "internal/abi", OutputField: "Array", Since: go127},
	{Kind: Constant, DwarfName: "internal/abi.Chan", OutputType: "internal/abi", OutputField: "Chan", Since: go127},
	{Kind: Constant, DwarfName: "internal/abi.Func", OutputType: "internal/abi", OutputField: "Func", Since: go127},
	{Kind: Constant, DwarfName: "internal/abi.Interface", OutputType: "internal/abi", OutputField: "Interface", Since: go127},
	{Kind: Constant, DwarfName: "internal/abi.Map", OutputType: "internal/abi", OutputField: "Map", Since: go127},
	{Kind: Constant, DwarfName: "internal/abi.Pointer", OutputType: "internal/abi", OutputField: "Pointer", Since: go127},
	{Kind: Constant, DwarfName: "internal/abi.Slice", OutputType: "internal/abi", OutputField: "Slice", Since: go127},
	{Kind: Constant, DwarfName: "internal/abi.Struct", OutputType: "internal/abi", OutputField: "Struct", Since: go127},
}

var goVersionPattern = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?`)

// Definitions returns all ABI facts required for goVersion.
func Definitions(goVersion string) ([]Definition, error) {
	version := goVersionPattern.FindString(goVersion)
	if version == "" {
		return nil, fmt.Errorf("invalid Go version %q", goVersion)
	}
	if semver.Compare("v"+version, "v"+go117) < 0 {
		return nil, fmt.Errorf("unsupported Go version %q", goVersion)
	}

	result := make([]Definition, 0, len(definitions))
	for _, definition := range definitions {
		if semver.Compare("v"+version, "v"+definition.Since) >= 0 {
			result = append(result, definition)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Key() < result[j].Key()
	})
	return result, nil
}

// Extract discovers and validates a complete ABI from DWARF.
func Extract(data *dwarf.Data, goVersion string) (ABI, error) {
	if data == nil {
		return ABI{}, errors.New("missing DWARF data")
	}
	requested, err := Definitions(goVersion)
	if err != nil {
		return ABI{}, err
	}
	values, err := readDWARF(data, requested)
	if err != nil {
		return ABI{}, err
	}
	return FromLookup(goVersion, func(definition Definition) (uint64, error) {
		value, ok := values[definition.Key()]
		if !ok {
			return 0, errors.New("not found")
		}
		return value, nil
	})
}

// FromLookup loads and validates a complete ABI using lookup as its source.
func FromLookup(
	goVersion string,
	lookup func(Definition) (uint64, error),
) (ABI, error) {
	requested, err := Definitions(goVersion)
	if err != nil {
		return ABI{}, err
	}

	values := make(map[string]uint64, len(requested))
	facts := make([]Fact, 0, len(requested))
	for _, definition := range requested {
		value, err := lookup(definition)
		if err != nil {
			return ABI{}, fmt.Errorf("loading Go ABI fact %s: %w", definition.Key(), err)
		}
		values[definition.Key()] = value
		facts = append(facts, Fact{Definition: definition, Value: value})
	}

	abi := ABI{
		Moduledata: Moduledata{
			PCHeader:    values["runtime.moduledata.pcHeader"],
			PCLNTable:   values["runtime.moduledata.pclntable"],
			MinPC:       values["runtime.moduledata.minpc"],
			MaxPC:       values["runtime.moduledata.maxpc"],
			Text:        values["runtime.moduledata.text"],
			EText:       values["runtime.moduledata.etext"],
			Types:       values["runtime.moduledata.types"],
			TypeDescLen: values["runtime.moduledata.typedesclen"],
			ITabOffset:  values["runtime.moduledata.itaboffset"],
			ITabSize:    values["runtime.moduledata.itabsize"],
		},
		facts: facts,
	}
	if semver.Compare("v"+goVersionPattern.FindString(goVersion), "v"+go127) < 0 {
		return abi, nil
	}

	abi.TypeMetadata = TypeMetadata{
		TypeTFlagOffset:       values["internal/abi.Type.TFlag"],
		TypeKindOffset:        values["internal/abi.Type.Kind_"],
		TypeNameOffset:        values["internal/abi.Type.Str"],
		TypeSize:              values["internal/abi.Type."+SizeField],
		TFlagSize:             values["internal/abi.TFlag."+SizeField],
		KindSize:              values["internal/abi.Kind."+SizeField],
		NameOffsetSize:        values["internal/abi.NameOff."+SizeField],
		InterfaceMethods:      values["internal/abi.InterfaceType.Methods"],
		SliceLenOffset:        values["[]internal/abi.Imethod.len"],
		ITabInterOffset:       values["internal/abi.ITab.Inter"],
		ITabTypeOffset:        values["internal/abi.ITab.Type"],
		ITabFunOffset:         values["internal/abi.ITab.Fun"],
		ITabBaseSize:          values["internal/abi.ITab."+SizeField],
		UncommonPkgPathOffset: values["internal/abi.UncommonType.PkgPath"],
		TFlagUncommon:         values["internal/abi.TFlagUncommon"],
		TFlagExtraStar:        values["internal/abi.TFlagExtraStar"],
		KindDirectIface:       values["internal/abi.KindDirectIface"],
		KindArray:             values["internal/abi.Array"],
		KindChan:              values["internal/abi.Chan"],
		KindFunc:              values["internal/abi.Func"],
		KindInterface:         values["internal/abi.Interface"],
		KindMap:               values["internal/abi.Map"],
		KindPointer:           values["internal/abi.Pointer"],
		KindSlice:             values["internal/abi.Slice"],
		KindStruct:            values["internal/abi.Struct"],
		UncommonArray:         values["internal/abi.ArrayType."+SizeField],
		UncommonChan:          values["internal/abi.ChanType."+SizeField],
		UncommonFunc:          values["internal/abi.FuncType."+SizeField],
		UncommonInterface:     values["internal/abi.InterfaceType."+SizeField],
		UncommonMap:           values["internal/abi.MapType."+SizeField],
		UncommonPointer:       values["internal/abi.PtrType."+SizeField],
		UncommonSlice:         values["internal/abi.SliceType."+SizeField],
		UncommonStruct:        values["internal/abi.StructType."+SizeField],
	}
	if err := validateTypeMetadata(&abi.TypeMetadata); err != nil {
		return ABI{}, err
	}
	return abi, nil
}

func validateTypeMetadata(metadata *TypeMetadata) error {
	if metadata.TFlagSize != uint64(binary.Size(uint8(0))) ||
		metadata.KindSize != uint64(binary.Size(uint8(0))) ||
		metadata.NameOffsetSize != uint64(binary.Size(int32(0))) {
		return errors.New("unsupported Go runtime ABI scalar sizes")
	}

	pointerSize := uint64(binary.Size(uint64(0)))
	if !fieldFits(metadata.TypeTFlagOffset, metadata.TFlagSize, metadata.TypeSize) ||
		!fieldFits(metadata.TypeKindOffset, metadata.KindSize, metadata.TypeSize) ||
		!fieldFits(metadata.TypeNameOffset, metadata.NameOffsetSize, metadata.TypeSize) ||
		metadata.SliceLenOffset != pointerSize ||
		!fieldFits(metadata.InterfaceMethods, metadata.SliceLenOffset+pointerSize, metadata.UncommonInterface) ||
		!fieldFits(metadata.ITabInterOffset, pointerSize, metadata.ITabBaseSize) ||
		!fieldFits(metadata.ITabTypeOffset, pointerSize, metadata.ITabBaseSize) ||
		metadata.ITabFunOffset > metadata.ITabBaseSize-pointerSize ||
		metadata.ITabFunOffset+pointerSize != metadata.ITabBaseSize ||
		metadata.ITabInterOffset%pointerSize != 0 || metadata.ITabTypeOffset%pointerSize != 0 ||
		metadata.ITabFunOffset%pointerSize != 0 ||
		metadata.ITabInterOffset == metadata.ITabTypeOffset ||
		metadata.ITabInterOffset == metadata.ITabFunOffset ||
		metadata.ITabTypeOffset == metadata.ITabFunOffset ||
		!allAtLeast(metadata.TypeSize,
			metadata.UncommonArray,
			metadata.UncommonChan,
			metadata.UncommonFunc,
			metadata.UncommonInterface,
			metadata.UncommonMap,
			metadata.UncommonPointer,
			metadata.UncommonSlice,
			metadata.UncommonStruct,
		) {
		return errors.New("invalid Go runtime ABI layout")
	}

	maxByte := uint64(^uint8(0))
	if metadata.TFlagUncommon > maxByte || metadata.TFlagExtraStar > maxByte ||
		metadata.KindDirectIface > maxByte || metadata.KindArray > maxByte ||
		metadata.KindChan > maxByte || metadata.KindFunc > maxByte || metadata.KindInterface > maxByte ||
		metadata.KindMap > maxByte || metadata.KindPointer > maxByte || metadata.KindSlice > maxByte ||
		metadata.KindStruct > maxByte {
		return errors.New("invalid Go runtime ABI facts")
	}
	if !powerOfTwo(metadata.TFlagUncommon) || !powerOfTwo(metadata.TFlagExtraStar) ||
		metadata.TFlagUncommon == metadata.TFlagExtraStar || !powerOfTwo(metadata.KindDirectIface) {
		return errors.New("invalid Go runtime ABI constants")
	}
	kindMask := metadata.KindDirectIface - 1
	if !distinctValuesWithin(kindMask,
		metadata.KindArray,
		metadata.KindChan,
		metadata.KindFunc,
		metadata.KindInterface,
		metadata.KindMap,
		metadata.KindPointer,
		metadata.KindSlice,
		metadata.KindStruct,
	) {
		return errors.New("invalid Go runtime ABI kind constants")
	}

	metadata.InterfaceLenOffset = metadata.InterfaceMethods + metadata.SliceLenOffset
	metadata.ITabFuncSize = metadata.ITabBaseSize - metadata.ITabFunOffset
	return nil
}

func fieldFits(offset, size, containerSize uint64) bool {
	return size <= containerSize && offset <= containerSize-size
}

func powerOfTwo(value uint64) bool {
	return value != 0 && value&(value-1) == 0
}

func allAtLeast(minimum uint64, values ...uint64) bool {
	for _, value := range values {
		if value < minimum {
			return false
		}
	}
	return true
}

func distinctValuesWithin(maximum uint64, values ...uint64) bool {
	seen := make(map[uint64]struct{}, len(values))
	for _, value := range values {
		if value == 0 || value > maximum {
			return false
		}
		if _, ok := seen[value]; ok {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func readDWARF(data *dwarf.Data, requested []Definition) (map[string]uint64, error) {
	typeQueries := map[string][]Definition{}
	constantQueries := map[string]Definition{}
	for _, definition := range requested {
		if definition.Kind == Constant {
			constantQueries[definition.DwarfName] = definition
		} else {
			typeQueries[definition.DwarfName] = append(typeQueries[definition.DwarfName], definition)
		}
	}

	values := map[string]uint64{}
	reader := data.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, err
		}
		if entry == nil {
			break
		}
		name, _ := entry.Val(dwarf.AttrName).(string)
		if definition, ok := constantQueries[name]; ok && entry.Tag == dwarf.TagConstant {
			value, err := unsignedValue(entry.Val(dwarf.AttrConstValue))
			if err != nil {
				return nil, fmt.Errorf("reading constant %s: %w", name, err)
			}
			if err := storeValue(values, definition.Key(), value); err != nil {
				return nil, err
			}
		}

		queries := typeQueries[name]
		if len(queries) == 0 {
			continue
		}
		for _, definition := range queries {
			switch definition.Kind {
			case Size:
				value, err := unsignedValue(entry.Val(dwarf.AttrByteSize))
				if err != nil {
					continue
				}
				if err := storeValue(values, definition.Key(), value); err != nil {
					return nil, err
				}
			case Field:
				typeInfo, err := data.Type(entry.Offset)
				if err != nil {
					continue
				}
				structInfo, ok := typeInfo.(*dwarf.StructType)
				if !ok {
					continue
				}
				for _, field := range structInfo.Field {
					if field.Name != definition.DwarfField {
						continue
					}
					if field.ByteOffset < 0 {
						return nil, fmt.Errorf("negative offset for %s.%s", name, definition.DwarfField)
					}
					if err := storeValue(values, definition.Key(), uint64(field.ByteOffset)); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	return values, nil
}

func unsignedValue(value any) (uint64, error) {
	switch value := value.(type) {
	case int64:
		if value < 0 {
			return 0, errors.New("negative value")
		}
		return uint64(value), nil
	case uint64:
		return value, nil
	default:
		return 0, fmt.Errorf("unexpected DWARF value type %T", value)
	}
}

func storeValue(values map[string]uint64, key string, value uint64) error {
	if previous, ok := values[key]; ok && previous != value {
		return fmt.Errorf("conflicting values for %s: %d and %d", key, previous, value)
	}
	values[key] = value
	return nil
}
