// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	goRuntimeTypeSize       = uint64(48)
	goRuntimeTypeTFlagPos   = uint64(20)
	goRuntimeTypeKindPos    = uint64(23)
	goRuntimeTypeNamePos    = uint64(40)
	goRuntimePointerElemPos = goRuntimeTypeSize

	goRuntimeKindInt     = uint8(2)
	goRuntimeKindPointer = uint8(22)
	goRuntimeKindSlice   = uint8(23)
	goRuntimeKindStruct  = uint8(25)
	goRuntimeKindMask    = uint8(0x1f)

	goRuntimeTFlagUncommon  = uint8(1 << 0)
	goRuntimeTFlagExtraStar = uint8(1 << 1)

	goRuntimeStructPkgPathPos = goRuntimeTypeSize
	goRuntimeStructFieldsPos  = goRuntimeTypeSize + 8
	goRuntimeStructFieldSize  = uint64(24)

	goRuntimeUncommonPkgPathPos       = goRuntimeTypeSize
	goRuntimeSliceUncommonPkgPathPos  = goRuntimeTypeSize + 8
	goRuntimeStructUncommonPkgPathPos = goRuntimeStructFieldsPos + 24
	goRuntimeMaxNameLen               = uint64(1024)
	goRuntimeMaxStructFields          = uint64(256)
	goRuntimeMaxTypeLinks             = uint64(1 << 20)

	otelTracePackagePath    = "go.opentelemetry.io/otel/trace"
	otelSDKTracePackagePath = "go.opentelemetry.io/otel/sdk/trace"
)

// GoAutoSDKTypeInfo identifies the concrete runtime types and fields needed to
// read an OpenTelemetry SpanContext from context.valueCtx in a target process.
// Type addresses are link-time virtual addresses and need the process load bias
// added before they are used by eBPF.
type GoAutoSDKTypeInfo struct {
	TraceContextKeyType        uint64
	NonRecordingSpanType       uint64
	RecordingSpanType          uint64
	AttributeOptionType        uint64
	TimestampOptionType        uint64
	NonRecordingSpanContextPos uint64
	RecordingSpanContextPos    uint64
	SpanContextTraceIDPos      uint64
	SpanContextSpanIDPos       uint64
	SpanContextTraceFlagsPos   uint64
	SpanContextRemotePos       uint64
	Resolved                   bool
}

// Valid reports whether type discovery completed. Field offsets may validly be
// zero, so discovery carries an explicit completion marker.
func (i GoAutoSDKTypeInfo) Valid() bool {
	return i.Resolved && i.TraceContextKeyType != 0
}

type goRuntimeTypeReader struct {
	elf                      *elf.File
	typesBase                uint64
	typesEnd                 uint64
	typelinks                []byte
	relocs                   relocationInfo
	legacyStructFieldOffsets bool
}

func findGoAutoSDKTypeInfo(elfFile *elf.File) (GoAutoSDKTypeInfo, error) {
	if elfFile == nil || elfFile.Class != elf.ELFCLASS64 {
		return GoAutoSDKTypeInfo{}, nil
	}

	goVersion, _, err := getGoDetails(elfFile)
	if err != nil {
		return GoAutoSDKTypeInfo{}, fmt.Errorf("getting Go version: %w", err)
	}
	view, err := findRuntimeModuledata(elfFile, elfFile.Section(".gopclntab"))
	if err != nil {
		return GoAutoSDKTypeInfo{}, fmt.Errorf("finding Go runtime module data: %w", err)
	}

	reader := goRuntimeTypeReader{
		elf:                      elfFile,
		relocs:                   view.relocs,
		legacyStructFieldOffsets: !goVersionAtLeast(goVersion, "1.19"),
	}
	reader.typesBase = resolveAddr(
		elfFile, view.address+view.offsets.types, view.relocs)
	reader.typesEnd = resolveAddr(
		elfFile, view.address+view.offsets.etypes, view.relocs)
	if reader.typesBase == 0 || reader.typesEnd <= reader.typesBase ||
		reader.typesEnd-reader.typesBase > uint64(^uint32(0)) {
		return GoAutoSDKTypeInfo{}, errors.New("invalid Go runtime type range")
	}

	typelinksAddress := resolveAddr(
		elfFile, view.address+view.offsets.typelinks, view.relocs)
	typelinksLen, err := reader.readUint64(view.address + view.offsets.typelinks + 8)
	if err != nil {
		return GoAutoSDKTypeInfo{}, fmt.Errorf("reading Go typelinks length: %w", err)
	}
	typelinksCap, err := reader.readUint64(view.address + view.offsets.typelinks + 16)
	if err != nil {
		return GoAutoSDKTypeInfo{}, fmt.Errorf("reading Go typelinks capacity: %w", err)
	}
	if typelinksLen == 0 || typelinksLen > typelinksCap ||
		typelinksLen > goRuntimeMaxTypeLinks || typelinksAddress == 0 {
		return GoAutoSDKTypeInfo{}, errors.New("invalid Go typelinks slice")
	}
	reader.typelinks, err = reader.read(typelinksAddress, typelinksLen*4)
	if err != nil {
		return GoAutoSDKTypeInfo{}, fmt.Errorf("reading Go typelinks: %w", err)
	}

	keyType := reader.findPointerElement("*trace.traceContextKeyType", goRuntimeKindInt)
	nonRecordingSpan := reader.findPointerElement("*trace.nonRecordingSpan", goRuntimeKindStruct)
	recordingSpanType, recordingSpan := reader.findPointerTypeAndElement(
		"*trace.recordingSpan", goRuntimeKindStruct, otelSDKTracePackagePath)
	spanContext := reader.findPointerElement("*trace.SpanContext", goRuntimeKindStruct)
	attributeOption := reader.findPointerElement("*trace.attributeOption", goRuntimeKindSlice)
	timestampOption := reader.findPointerElement("*trace.timestampOption", goRuntimeKindStruct)
	if keyType == 0 || spanContext == 0 {
		return GoAutoSDKTypeInfo{}, nil
	}

	var nonRecordingSpanContextPos uint64
	if nonRecordingSpan != 0 {
		var ok bool
		nonRecordingSpanContextPos, ok = reader.structFieldOffset(
			nonRecordingSpan, "sc", spanContext)
		if !ok {
			return GoAutoSDKTypeInfo{}, errors.New("go trace.nonRecordingSpan.sc field not found")
		}
	}
	var recordingSpanContextPos uint64
	if recordingSpan != 0 {
		var ok bool
		recordingSpanContextPos, ok = reader.structFieldOffset(
			recordingSpan, "spanContext", spanContext)
		if !ok {
			return GoAutoSDKTypeInfo{}, errors.New("go sdk trace.recordingSpan.spanContext field not found")
		}
	}
	traceIDPos, ok := reader.structFieldOffset(spanContext, "traceID", 0)
	if !ok {
		return GoAutoSDKTypeInfo{}, errors.New("go trace.SpanContext.traceID field not found")
	}
	spanIDPos, ok := reader.structFieldOffset(spanContext, "spanID", 0)
	if !ok {
		return GoAutoSDKTypeInfo{}, errors.New("go trace.SpanContext.spanID field not found")
	}
	traceFlagsPos, ok := reader.structFieldOffset(spanContext, "traceFlags", 0)
	if !ok {
		return GoAutoSDKTypeInfo{}, errors.New("go trace.SpanContext.traceFlags field not found")
	}
	remotePos, ok := reader.structFieldOffset(spanContext, "remote", 0)
	if !ok {
		return GoAutoSDKTypeInfo{}, errors.New("go trace.SpanContext.remote field not found")
	}

	return GoAutoSDKTypeInfo{
		TraceContextKeyType:        keyType,
		NonRecordingSpanType:       nonRecordingSpan,
		RecordingSpanType:          recordingSpanType,
		AttributeOptionType:        attributeOption,
		TimestampOptionType:        timestampOption,
		NonRecordingSpanContextPos: nonRecordingSpanContextPos,
		RecordingSpanContextPos:    recordingSpanContextPos,
		SpanContextTraceIDPos:      traceIDPos,
		SpanContextSpanIDPos:       spanIDPos,
		SpanContextTraceFlagsPos:   traceFlagsPos,
		SpanContextRemotePos:       remotePos,
		Resolved:                   true,
	}, nil
}

func (r *goRuntimeTypeReader) findPointerElement(name string, elemKind uint8) uint64 {
	_, elem := r.findPointerTypeAndElement(name, elemKind, otelTracePackagePath)
	return elem
}

func (r *goRuntimeTypeReader) findPointerTypeAndElement(
	name string,
	elemKind uint8,
	packagePath string,
) (uint64, uint64) {
	for offset := 0; offset+4 <= len(r.typelinks); offset += 4 {
		typeOffset := int64(int32(r.elf.ByteOrder.Uint32(r.typelinks[offset:])))
		if typeOffset < 0 || uint64(typeOffset) > r.typesEnd-r.typesBase {
			continue
		}
		typeAddress := r.typesBase + uint64(typeOffset)
		if !r.typeRange(typeAddress, goRuntimePointerElemPos+8) {
			continue
		}
		kind, err := r.readByte(typeAddress + goRuntimeTypeKindPos)
		if err != nil || kind&goRuntimeKindMask != goRuntimeKindPointer {
			continue
		}
		typeName, err := r.typeName(typeAddress)
		if err != nil || typeName != name {
			continue
		}

		elem := resolveAddr(r.elf, typeAddress+goRuntimePointerElemPos, r.relocs)
		if !r.typeRange(elem, goRuntimeTypeSize) {
			continue
		}
		kind, err = r.readByte(elem + goRuntimeTypeKindPos)
		if err != nil || kind&goRuntimeKindMask != elemKind {
			continue
		}
		pkgPath, err := r.typePackagePath(elem, elemKind)
		if err != nil || pkgPath != packagePath {
			continue
		}
		return typeAddress, elem
	}
	return 0, 0
}

func (r *goRuntimeTypeReader) typeName(typeAddress uint64) (string, error) {
	if !r.typeRange(typeAddress, goRuntimeTypeSize) {
		return "", errors.New("invalid Go runtime type address")
	}
	nameOffset, err := r.readInt32(typeAddress + goRuntimeTypeNamePos)
	if err != nil || nameOffset <= 0 ||
		uint64(nameOffset) >= r.typesEnd-r.typesBase {
		return "", errors.New("invalid Go runtime type name offset")
	}
	name, err := r.nameAt(r.typesBase + uint64(nameOffset))
	if err != nil {
		return "", err
	}
	tflag, err := r.readByte(typeAddress + goRuntimeTypeTFlagPos)
	if err != nil {
		return "", err
	}
	if tflag&goRuntimeTFlagExtraStar != 0 && strings.HasPrefix(name, "*") {
		name = name[1:]
	}
	return name, nil
}

func (r *goRuntimeTypeReader) typePackagePath(typeAddress uint64, kind uint8) (string, error) {
	if kind == goRuntimeKindStruct {
		if !r.typeRange(typeAddress, goRuntimeStructFieldsPos+24) {
			return "", errors.New("invalid Go runtime struct type")
		}
		if pkgPath, ok := r.uncommonPackagePath(
			typeAddress, goRuntimeStructUncommonPkgPathPos); ok {
			return pkgPath, nil
		}
		nameAddress := resolveAddr(r.elf, typeAddress+goRuntimeStructPkgPathPos, r.relocs)
		if nameAddress == 0 {
			return "", nil
		}
		return r.nameAt(nameAddress)
	}

	uncommonPkgPathPos := goRuntimeUncommonPkgPathPos
	if kind == goRuntimeKindSlice {
		uncommonPkgPathPos = goRuntimeSliceUncommonPkgPathPos
	}
	pkgPath, ok := r.uncommonPackagePath(typeAddress, uncommonPkgPathPos)
	if !ok {
		return "", nil
	}
	return pkgPath, nil
}

func (r *goRuntimeTypeReader) uncommonPackagePath(
	typeAddress, uncommonPkgPathPos uint64,
) (string, bool) {
	if !r.typeRange(typeAddress, uncommonPkgPathPos+4) {
		return "", false
	}
	tflag, err := r.readByte(typeAddress + goRuntimeTypeTFlagPos)
	if err != nil || tflag&goRuntimeTFlagUncommon == 0 {
		return "", false
	}
	nameOffset, err := r.readInt32(typeAddress + uncommonPkgPathPos)
	if err != nil || nameOffset <= 0 ||
		uint64(nameOffset) >= r.typesEnd-r.typesBase {
		return "", false
	}
	pkgPath, err := r.nameAt(r.typesBase + uint64(nameOffset))
	return pkgPath, err == nil
}

func (r *goRuntimeTypeReader) structFieldOffset(
	typeAddress uint64,
	fieldName string,
	expectedType uint64,
) (uint64, bool) {
	if !r.typeRange(typeAddress, goRuntimeStructFieldsPos+24) {
		return 0, false
	}
	fields := resolveAddr(r.elf, typeAddress+goRuntimeStructFieldsPos, r.relocs)
	fieldCount, err := r.readUint64(typeAddress + goRuntimeStructFieldsPos + 8)
	if err != nil {
		return 0, false
	}
	fieldCap, err := r.readUint64(typeAddress + goRuntimeStructFieldsPos + 16)
	if err != nil || fieldCount > fieldCap || fieldCount > goRuntimeMaxStructFields {
		return 0, false
	}
	if fields == 0 || !r.typeRange(fields, fieldCount*goRuntimeStructFieldSize) {
		return 0, false
	}

	structSize, err := r.readUint64(typeAddress)
	if err != nil {
		return 0, false
	}
	for i := uint64(0); i < fieldCount; i++ {
		fieldAddress := fields + i*goRuntimeStructFieldSize
		nameAddress := resolveAddr(r.elf, fieldAddress, r.relocs)
		name, err := r.nameAt(nameAddress)
		if err != nil || name != fieldName {
			continue
		}
		fieldType := resolveAddr(r.elf, fieldAddress+8, r.relocs)
		if !r.typeRange(fieldType, goRuntimeTypeSize) ||
			expectedType != 0 && fieldType != expectedType {
			return 0, false
		}
		rawOffset, err := r.readUint64(fieldAddress + 16)
		if err != nil {
			return 0, false
		}
		fieldOffset := decodeGoRuntimeStructFieldOffset(
			rawOffset, r.legacyStructFieldOffsets)
		fieldSize, err := r.readUint64(fieldType)
		if err != nil || fieldOffset > structSize ||
			fieldSize > structSize-fieldOffset {
			return 0, false
		}
		return fieldOffset, true
	}
	return 0, false
}

func decodeGoRuntimeStructFieldOffset(raw uint64, legacy bool) uint64 {
	if legacy {
		return raw >> 1
	}
	return raw
}

func (r *goRuntimeTypeReader) nameAt(address uint64) (string, error) {
	if !r.typeRange(address, 2) {
		return "", errors.New("invalid Go runtime name address")
	}
	remaining := r.typesEnd - address
	headerSize := min(remaining, uint64(12))
	header, err := r.read(address, headerSize)
	if err != nil {
		return "", err
	}
	nameLen, consumed := binary.Uvarint(header[1:])
	if consumed <= 0 || nameLen > goRuntimeMaxNameLen ||
		nameLen > remaining-1-uint64(consumed) {
		return "", errors.New("invalid Go runtime name")
	}
	name, err := r.read(address+1+uint64(consumed), nameLen)
	if err != nil {
		return "", err
	}
	return string(name), nil
}

func (r *goRuntimeTypeReader) readByte(address uint64) (uint8, error) {
	data, err := r.read(address, 1)
	if err != nil {
		return 0, err
	}
	return data[0], nil
}

func (r *goRuntimeTypeReader) readInt32(address uint64) (int32, error) {
	data, err := r.read(address, 4)
	if err != nil {
		return 0, err
	}
	return int32(r.elf.ByteOrder.Uint32(data)), nil
}

func (r *goRuntimeTypeReader) readUint64(address uint64) (uint64, error) {
	data, err := r.read(address, 8)
	if err != nil {
		return 0, err
	}
	return r.elf.ByteOrder.Uint64(data), nil
}

func (r *goRuntimeTypeReader) typeRange(address, size uint64) bool {
	if address < r.typesBase || address > r.typesEnd || size > r.typesEnd-r.typesBase {
		return false
	}
	return address-r.typesBase <= r.typesEnd-r.typesBase-size
}

func (r *goRuntimeTypeReader) read(address, size uint64) ([]byte, error) {
	if size == 0 || size > uint64(^uint(0)>>1) {
		return nil, errors.New("invalid Go runtime metadata read size")
	}
	for _, program := range r.elf.Progs {
		if program.Type != elf.PT_LOAD ||
			address < program.Vaddr ||
			size > program.Filesz ||
			address-program.Vaddr > program.Filesz-size {
			continue
		}
		data := make([]byte, int(size))
		if _, err := program.ReadAt(data, int64(address-program.Vaddr)); err != nil {
			return nil, err
		}
		return data, nil
	}
	return nil, fmt.Errorf("go runtime metadata address %#x is not file-backed", address)
}
