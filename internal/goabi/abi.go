// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package goabi discovers the private Go runtime ABI used by OBI.
package goabi // import "go.opentelemetry.io/obi/internal/goabi"

import (
	"debug/dwarf"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"go.opentelemetry.io/obi/internal/goversion"
)

// SizeField is the generated offset field used to store a DWARF type size.
const SizeField = "$size"

// Requirement describes one versioned ABI fact and its generated output key.
type Requirement struct {
	OutputType  string
	OutputField string
	Since       string
}

// Key returns the generated type-and-field key for a requirement.
func (r Requirement) Key() string {
	return r.OutputType + "." + r.OutputField
}

type definition struct {
	Requirement
	query  dwarfQuery
	assign func(*ABI, uint64)
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

func moduledataField(
	fieldName string,
	since string,
	assign func(*Moduledata, uint64),
) definition {
	return definition{
		Requirement: Requirement{
			OutputType:  "runtime.moduledata",
			OutputField: fieldName,
			Since:       since,
		},
		query: fieldQuery{typeName: "runtime.moduledata", fieldName: fieldName},
		assign: func(abi *ABI, value uint64) {
			assign(&abi.Moduledata, value)
		},
	}
}

func typeMetadataField(
	typeName string,
	fieldName string,
	assign func(*TypeMetadata, uint64),
) definition {
	return definition{
		Requirement: Requirement{
			OutputType:  typeName,
			OutputField: fieldName,
			Since:       go127,
		},
		query: fieldQuery{typeName: typeName, fieldName: fieldName},
		assign: func(abi *ABI, value uint64) {
			assign(abi.typeMetadata(), value)
		},
	}
}

func typeMetadataSize(typeName string, assign func(*TypeMetadata, uint64)) definition {
	return definition{
		Requirement: Requirement{
			OutputType:  typeName,
			OutputField: SizeField,
			Since:       go127,
		},
		query: sizeQuery{typeName: typeName},
		assign: func(abi *ABI, value uint64) {
			assign(abi.typeMetadata(), value)
		},
	}
}

func typeMetadataConstant(
	constantName string,
	outputField string,
	assign func(*TypeMetadata, uint64),
) definition {
	return definition{
		Requirement: Requirement{
			OutputType:  "internal/abi",
			OutputField: outputField,
			Since:       go127,
		},
		query: constantQuery{constantName: constantName},
		assign: func(abi *ABI, value uint64) {
			assign(abi.typeMetadata(), value)
		},
	}
}

// Fact is a resolved ABI requirement and value.
type Fact struct {
	Requirement Requirement
	Value       uint64
}

// Moduledata contains the runtime.moduledata field offsets OBI reads.
type Moduledata struct {
	PCHeader    uint64
	PCLNTable   uint64 // Offset of the pclntable slice header.
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
	TypeTFlagOffset         uint64
	TypeKindOffset          uint64
	TypeNameOffset          uint64
	InterfaceMethodsOffset  uint64
	SliceLenOffset          uint64
	ITabInterOffset         uint64
	ITabTypeOffset          uint64
	ITabFunOffset           uint64
	UncommonPkgPathOffset   uint64
	ArrayUncommonOffset     uint64
	ChanUncommonOffset      uint64
	FuncUncommonOffset      uint64
	InterfaceUncommonOffset uint64
	MapUncommonOffset       uint64
	PointerUncommonOffset   uint64
	SliceUncommonOffset     uint64
	StructUncommonOffset    uint64

	TypeSize       uint64
	TFlagSize      uint64
	KindSize       uint64
	NameOffsetSize uint64
	ITabBaseSize   uint64

	TFlagUncommonMask   uint64
	TFlagExtraStarMask  uint64
	KindDirectIfaceFlag uint64
	ArrayKind           uint64
	ChanKind            uint64
	FuncKind            uint64
	InterfaceKind       uint64
	MapKind             uint64
	PointerKind         uint64
	SliceKind           uint64
	StructKind          uint64
}

// ABI is one complete, validated set of ABI facts for a Go version.
type ABI struct {
	Moduledata Moduledata
	// TypeMetadata is nil when the selected requirements do not include type metadata.
	TypeMetadata *TypeMetadata
	facts        []Fact
}

func (a *ABI) typeMetadata() *TypeMetadata {
	if a.TypeMetadata == nil {
		a.TypeMetadata = &TypeMetadata{}
	}
	return a.TypeMetadata
}

// Facts returns the resolved facts in stable key order.
func (a ABI) Facts() []Fact {
	return append([]Fact(nil), a.facts...)
}

const (
	go117 = "1.17.0"
	go127 = "1.27.0"
)

var definitions = []definition{
	moduledataField("pcHeader", go117, func(m *Moduledata, v uint64) { m.PCHeader = v }),
	moduledataField("pclntable", go117, func(m *Moduledata, v uint64) { m.PCLNTable = v }),
	moduledataField("minpc", go117, func(m *Moduledata, v uint64) { m.MinPC = v }),
	moduledataField("maxpc", go117, func(m *Moduledata, v uint64) { m.MaxPC = v }),
	moduledataField("text", go117, func(m *Moduledata, v uint64) { m.Text = v }),
	moduledataField("etext", go117, func(m *Moduledata, v uint64) { m.EText = v }),
	moduledataField("types", go127, func(m *Moduledata, v uint64) { m.Types = v }),
	moduledataField("typedesclen", go127, func(m *Moduledata, v uint64) { m.TypeDescLen = v }),
	moduledataField("itaboffset", go127, func(m *Moduledata, v uint64) { m.ITabOffset = v }),
	moduledataField("itabsize", go127, func(m *Moduledata, v uint64) { m.ITabSize = v }),

	typeMetadataField("internal/abi.Type", "TFlag", func(m *TypeMetadata, v uint64) { m.TypeTFlagOffset = v }),
	typeMetadataField("internal/abi.Type", "Kind_", func(m *TypeMetadata, v uint64) { m.TypeKindOffset = v }),
	typeMetadataField("internal/abi.Type", "Str", func(m *TypeMetadata, v uint64) { m.TypeNameOffset = v }),
	typeMetadataField("internal/abi.InterfaceType", "Methods", func(m *TypeMetadata, v uint64) { m.InterfaceMethodsOffset = v }),
	typeMetadataField("internal/abi.ITab", "Inter", func(m *TypeMetadata, v uint64) { m.ITabInterOffset = v }),
	typeMetadataField("internal/abi.ITab", "Type", func(m *TypeMetadata, v uint64) { m.ITabTypeOffset = v }),
	typeMetadataField("internal/abi.ITab", "Fun", func(m *TypeMetadata, v uint64) { m.ITabFunOffset = v }),
	typeMetadataField("internal/abi.UncommonType", "PkgPath", func(m *TypeMetadata, v uint64) { m.UncommonPkgPathOffset = v }),
	typeMetadataField("[]internal/abi.Imethod", "len", func(m *TypeMetadata, v uint64) { m.SliceLenOffset = v }),

	typeMetadataSize("internal/abi.Type", func(m *TypeMetadata, v uint64) { m.TypeSize = v }),
	typeMetadataSize("internal/abi.ArrayType", func(m *TypeMetadata, v uint64) { m.ArrayUncommonOffset = v }),
	typeMetadataSize("internal/abi.ChanType", func(m *TypeMetadata, v uint64) { m.ChanUncommonOffset = v }),
	typeMetadataSize("internal/abi.FuncType", func(m *TypeMetadata, v uint64) { m.FuncUncommonOffset = v }),
	typeMetadataSize("internal/abi.InterfaceType", func(m *TypeMetadata, v uint64) { m.InterfaceUncommonOffset = v }),
	typeMetadataSize("internal/abi.MapType", func(m *TypeMetadata, v uint64) { m.MapUncommonOffset = v }),
	typeMetadataSize("internal/abi.PtrType", func(m *TypeMetadata, v uint64) { m.PointerUncommonOffset = v }),
	typeMetadataSize("internal/abi.SliceType", func(m *TypeMetadata, v uint64) { m.SliceUncommonOffset = v }),
	typeMetadataSize("internal/abi.StructType", func(m *TypeMetadata, v uint64) { m.StructUncommonOffset = v }),
	typeMetadataSize("internal/abi.ITab", func(m *TypeMetadata, v uint64) { m.ITabBaseSize = v }),
	typeMetadataSize("internal/abi.TFlag", func(m *TypeMetadata, v uint64) { m.TFlagSize = v }),
	typeMetadataSize("internal/abi.Kind", func(m *TypeMetadata, v uint64) { m.KindSize = v }),
	typeMetadataSize("internal/abi.NameOff", func(m *TypeMetadata, v uint64) { m.NameOffsetSize = v }),

	typeMetadataConstant("internal/abi.TFlagUncommon", "TFlagUncommon", func(m *TypeMetadata, v uint64) { m.TFlagUncommonMask = v }),
	typeMetadataConstant("internal/abi.TFlagExtraStar", "TFlagExtraStar", func(m *TypeMetadata, v uint64) { m.TFlagExtraStarMask = v }),
	typeMetadataConstant("internal/abi.KindDirectIface", "KindDirectIface", func(m *TypeMetadata, v uint64) { m.KindDirectIfaceFlag = v }),
	typeMetadataConstant("internal/abi.Array", "Array", func(m *TypeMetadata, v uint64) { m.ArrayKind = v }),
	typeMetadataConstant("internal/abi.Chan", "Chan", func(m *TypeMetadata, v uint64) { m.ChanKind = v }),
	typeMetadataConstant("internal/abi.Func", "Func", func(m *TypeMetadata, v uint64) { m.FuncKind = v }),
	typeMetadataConstant("internal/abi.Interface", "Interface", func(m *TypeMetadata, v uint64) { m.InterfaceKind = v }),
	typeMetadataConstant("internal/abi.Map", "Map", func(m *TypeMetadata, v uint64) { m.MapKind = v }),
	typeMetadataConstant("internal/abi.Pointer", "Pointer", func(m *TypeMetadata, v uint64) { m.PointerKind = v }),
	typeMetadataConstant("internal/abi.Slice", "Slice", func(m *TypeMetadata, v uint64) { m.SliceKind = v }),
	typeMetadataConstant("internal/abi.Struct", "Struct", func(m *TypeMetadata, v uint64) { m.StructKind = v }),
}

// Requirements returns the ABI facts known to be required for goVersion.
// The version selects facts; it does not establish ABI compatibility.
func Requirements(goVersion string) ([]Requirement, error) {
	definitions, err := requiredDefinitions(goVersion)
	if err != nil {
		return nil, err
	}

	result := make([]Requirement, 0, len(definitions))
	for _, definition := range definitions {
		result = append(result, definition.Requirement)
	}
	return result, nil
}

func requiredDefinitions(goVersion string) ([]definition, error) {
	version, err := goversion.Parse(goVersion)
	if err != nil {
		return nil, err
	}
	minimum, err := goversion.Parse(go117)
	if err != nil {
		return nil, err
	}
	if version.Compare(minimum) < 0 {
		return nil, fmt.Errorf("unsupported Go version %q", goVersion)
	}

	result := make([]definition, 0, len(definitions))
	for _, definition := range definitions {
		since, err := goversion.Parse(definition.Since)
		if err != nil {
			return nil, err
		}
		if version.Compare(since) >= 0 {
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
	requested, err := requiredDefinitions(goVersion)
	if err != nil {
		return ABI{}, err
	}
	values, err := readDWARF(data, requested)
	if err != nil {
		return ABI{}, err
	}
	return loadAndValidate(requested, func(requirement Requirement) (uint64, error) {
		value, ok := values[requirement.Key()]
		if !ok {
			return 0, errors.New("not found")
		}
		return value, nil
	})
}

// FromLookup loads and validates a complete ABI using lookup as its source.
func FromLookup(
	goVersion string,
	lookup func(Requirement) (uint64, error),
) (ABI, error) {
	requested, err := requiredDefinitions(goVersion)
	if err != nil {
		return ABI{}, err
	}
	return loadAndValidate(requested, lookup)
}

func loadAndValidate(
	requested []definition,
	lookup func(Requirement) (uint64, error),
) (ABI, error) {
	abi := ABI{facts: make([]Fact, 0, len(requested))}
	for _, definition := range requested {
		requirement := definition.Requirement
		value, err := lookup(requirement)
		if err != nil {
			return ABI{}, fmt.Errorf("loading Go ABI fact %s: %w", requirement.Key(), err)
		}
		definition.assign(&abi, value)
		abi.facts = append(abi.facts, Fact{Requirement: requirement, Value: value})
	}

	if abi.TypeMetadata == nil {
		return abi, nil
	}
	if err := validateTypeMetadata(abi.TypeMetadata); err != nil {
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
		!fieldFits(metadata.InterfaceMethodsOffset, metadata.SliceLenOffset+pointerSize, metadata.InterfaceUncommonOffset) ||
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
			metadata.ArrayUncommonOffset,
			metadata.ChanUncommonOffset,
			metadata.FuncUncommonOffset,
			metadata.InterfaceUncommonOffset,
			metadata.MapUncommonOffset,
			metadata.PointerUncommonOffset,
			metadata.SliceUncommonOffset,
			metadata.StructUncommonOffset,
		) {
		return errors.New("invalid Go runtime ABI layout")
	}

	maxByte := uint64(^uint8(0))
	if metadata.TFlagUncommonMask > maxByte || metadata.TFlagExtraStarMask > maxByte ||
		metadata.KindDirectIfaceFlag > maxByte || metadata.ArrayKind > maxByte ||
		metadata.ChanKind > maxByte || metadata.FuncKind > maxByte || metadata.InterfaceKind > maxByte ||
		metadata.MapKind > maxByte || metadata.PointerKind > maxByte || metadata.SliceKind > maxByte ||
		metadata.StructKind > maxByte {
		return errors.New("invalid Go runtime ABI facts")
	}
	if !powerOfTwo(metadata.TFlagUncommonMask) || !powerOfTwo(metadata.TFlagExtraStarMask) ||
		metadata.TFlagUncommonMask == metadata.TFlagExtraStarMask || !powerOfTwo(metadata.KindDirectIfaceFlag) {
		return errors.New("invalid Go runtime ABI constants")
	}
	kindMask := metadata.KindDirectIfaceFlag - 1
	if !distinctValuesWithin(kindMask,
		metadata.ArrayKind,
		metadata.ChanKind,
		metadata.FuncKind,
		metadata.InterfaceKind,
		metadata.MapKind,
		metadata.PointerKind,
		metadata.SliceKind,
		metadata.StructKind,
	) {
		return errors.New("invalid Go runtime ABI kind constants")
	}

	return nil
}

// TypeHeaderSize returns the number of bytes needed to decode a Go type header.
func (metadata *TypeMetadata) TypeHeaderSize() uint64 {
	size := metadata.TypeNameOffset + metadata.NameOffsetSize
	if end := metadata.TypeTFlagOffset + metadata.TFlagSize; end > size {
		size = end
	}
	if end := metadata.TypeKindOffset + metadata.KindSize; end > size {
		size = end
	}
	return size
}

// InterfaceMethodCountOffset returns the offset of the method slice's length.
func (metadata *TypeMetadata) InterfaceMethodCountOffset() uint64 {
	return metadata.InterfaceMethodsOffset + metadata.SliceLenOffset
}

// ITabFuncEntrySize returns the size of one function-table entry in an itab.
func (metadata *TypeMetadata) ITabFuncEntrySize() uint64 {
	return metadata.ITabBaseSize - metadata.ITabFunOffset
}

// UncommonTypeOffset returns the offset of uncommon type data for kind.
func (metadata *TypeMetadata) UncommonTypeOffset(kind byte) uint64 {
	kind &= byte(metadata.KindDirectIfaceFlag - 1)
	switch uint64(kind) {
	case metadata.ArrayKind:
		return metadata.ArrayUncommonOffset
	case metadata.ChanKind:
		return metadata.ChanUncommonOffset
	case metadata.FuncKind:
		return metadata.FuncUncommonOffset
	case metadata.InterfaceKind:
		return metadata.InterfaceUncommonOffset
	case metadata.MapKind:
		return metadata.MapUncommonOffset
	case metadata.PointerKind:
		return metadata.PointerUncommonOffset
	case metadata.SliceKind:
		return metadata.SliceUncommonOffset
	case metadata.StructKind:
		return metadata.StructUncommonOffset
	default:
		return metadata.TypeSize
	}
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

func readDWARF(data *dwarf.Data, requested []definition) (map[string]uint64, error) {
	queries := map[string][]definition{}
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
