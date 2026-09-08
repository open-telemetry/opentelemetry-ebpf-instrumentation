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

// Definition describes one versioned ABI fact and its generated output key.
type Definition struct {
	query       dwarfQuery
	OutputType  string
	OutputField string
	Since       string
}

type dwarfQuery interface {
	name() string
	extract(*dwarf.Data, *dwarf.Entry) (uint64, bool, error)
}

type fieldQuery struct {
	typeName  string
	fieldName string
}

type sizeQuery struct {
	typeName string
}

type constantQuery struct {
	constantName string
}

func fieldDefinition(typeName, fieldName, since string) Definition {
	return Definition{
		query:       fieldQuery{typeName: typeName, fieldName: fieldName},
		OutputType:  typeName,
		OutputField: fieldName,
		Since:       since,
	}
}

func sizeDefinition(typeName string) Definition {
	return Definition{
		query:       sizeQuery{typeName: typeName},
		OutputType:  typeName,
		OutputField: SizeField,
		Since:       go127,
	}
}

func constantDefinition(constantName, outputField string) Definition {
	return Definition{
		query:       constantQuery{constantName: constantName},
		OutputType:  "internal/abi",
		OutputField: outputField,
		Since:       go127,
	}
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
	fieldDefinition("runtime.moduledata", "pcHeader", go117),
	fieldDefinition("runtime.moduledata", "pclntable", go117),
	fieldDefinition("runtime.moduledata", "minpc", go117),
	fieldDefinition("runtime.moduledata", "maxpc", go117),
	fieldDefinition("runtime.moduledata", "text", go117),
	fieldDefinition("runtime.moduledata", "etext", go117),
	fieldDefinition("runtime.moduledata", "types", go127),
	fieldDefinition("runtime.moduledata", "typedesclen", go127),
	fieldDefinition("runtime.moduledata", "itaboffset", go127),
	fieldDefinition("runtime.moduledata", "itabsize", go127),
	fieldDefinition("internal/abi.Type", "TFlag", go127),
	fieldDefinition("internal/abi.Type", "Kind_", go127),
	fieldDefinition("internal/abi.Type", "Str", go127),
	fieldDefinition("internal/abi.InterfaceType", "Methods", go127),
	fieldDefinition("internal/abi.ITab", "Inter", go127),
	fieldDefinition("internal/abi.ITab", "Type", go127),
	fieldDefinition("internal/abi.ITab", "Fun", go127),
	fieldDefinition("internal/abi.UncommonType", "PkgPath", go127),
	fieldDefinition("[]internal/abi.Imethod", "len", go127),
	sizeDefinition("internal/abi.Type"),
	sizeDefinition("internal/abi.ArrayType"),
	sizeDefinition("internal/abi.ChanType"),
	sizeDefinition("internal/abi.FuncType"),
	sizeDefinition("internal/abi.InterfaceType"),
	sizeDefinition("internal/abi.MapType"),
	sizeDefinition("internal/abi.PtrType"),
	sizeDefinition("internal/abi.SliceType"),
	sizeDefinition("internal/abi.StructType"),
	sizeDefinition("internal/abi.ITab"),
	sizeDefinition("internal/abi.TFlag"),
	sizeDefinition("internal/abi.Kind"),
	sizeDefinition("internal/abi.NameOff"),
	constantDefinition("internal/abi.TFlagUncommon", "TFlagUncommon"),
	constantDefinition("internal/abi.TFlagExtraStar", "TFlagExtraStar"),
	constantDefinition("internal/abi.KindDirectIface", "KindDirectIface"),
	constantDefinition("internal/abi.Array", "Array"),
	constantDefinition("internal/abi.Chan", "Chan"),
	constantDefinition("internal/abi.Func", "Func"),
	constantDefinition("internal/abi.Interface", "Interface"),
	constantDefinition("internal/abi.Map", "Map"),
	constantDefinition("internal/abi.Pointer", "Pointer"),
	constantDefinition("internal/abi.Slice", "Slice"),
	constantDefinition("internal/abi.Struct", "Struct"),
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

func (q fieldQuery) name() string {
	return q.typeName
}

func (q fieldQuery) extract(data *dwarf.Data, entry *dwarf.Entry) (uint64, bool, error) {
	typeInfo, err := data.Type(entry.Offset)
	if err != nil {
		return 0, false, nil
	}
	structInfo, ok := typeInfo.(*dwarf.StructType)
	if !ok {
		return 0, false, nil
	}
	for _, field := range structInfo.Field {
		if field.Name != q.fieldName {
			continue
		}
		if field.ByteOffset < 0 {
			return 0, false, fmt.Errorf("negative offset for %s.%s", q.typeName, q.fieldName)
		}
		return uint64(field.ByteOffset), true, nil
	}
	return 0, false, nil
}

func (q sizeQuery) name() string {
	return q.typeName
}

func (q sizeQuery) extract(_ *dwarf.Data, entry *dwarf.Entry) (uint64, bool, error) {
	value, err := unsignedValue(entry.Val(dwarf.AttrByteSize))
	if err != nil {
		return 0, false, nil
	}
	return value, true, nil
}

func (q constantQuery) name() string {
	return q.constantName
}

func (q constantQuery) extract(_ *dwarf.Data, entry *dwarf.Entry) (uint64, bool, error) {
	if entry.Tag != dwarf.TagConstant {
		return 0, false, nil
	}
	value, err := unsignedValue(entry.Val(dwarf.AttrConstValue))
	if err != nil {
		return 0, false, fmt.Errorf("reading constant %s: %w", q.constantName, err)
	}
	return value, true, nil
}

func readDWARF(data *dwarf.Data, requested []Definition) (map[string]uint64, error) {
	queries := map[string][]Definition{}
	for _, definition := range requested {
		name := definition.query.name()
		queries[name] = append(queries[name], definition)
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
		for _, definition := range queries[name] {
			value, found, err := definition.query.extract(data, entry)
			if err != nil {
				return nil, err
			}
			if !found {
				continue
			}
			if err := storeValue(values, definition.Key(), value); err != nil {
				return nil, err
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
