// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package classfile // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/classfile"

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	classFileMagic     = 0xCAFEBABE
	maxAnnotationDepth = 32
)

// JVM constant pool tags, as defined by the Java Virtual Machine
// Specification 4.4 (The Constant Pool).
const (
	cpTagUtf8               uint8 = 1
	cpTagInteger            uint8 = 3
	cpTagFloat              uint8 = 4
	cpTagLong               uint8 = 5
	cpTagDouble             uint8 = 6
	cpTagClass              uint8 = 7
	cpTagString             uint8 = 8
	cpTagFieldref           uint8 = 9
	cpTagMethodref          uint8 = 10
	cpTagInterfaceMethodref uint8 = 11
	cpTagNameAndType        uint8 = 12
	cpTagMethodHandle       uint8 = 15
	cpTagMethodType         uint8 = 16
	cpTagDynamic            uint8 = 17
	cpTagInvokeDynamic      uint8 = 18
	cpTagModule             uint8 = 19
	cpTagPackage            uint8 = 20
)

type Class struct {
	ClassAnnotations  []Annotation
	MethodAnnotations [][]Annotation
}

type Annotation struct {
	Descriptor string
	Elements   map[string][]string
	Nested     []Annotation
}

type constantPoolEntry struct {
	tag   uint8
	utf8  string
	index uint16
}

type constantPool []constantPoolEntry

type classReader struct {
	data  []byte
	off   int
	depth int
}

type elementValue struct {
	strings     []string
	annotations []Annotation
}

func Parse(data []byte) (*Class, error) {
	reader := classReader{data: data}

	magic, err := reader.u4()
	if err != nil {
		return nil, err
	}
	if magic != classFileMagic {
		return nil, fmt.Errorf("invalid class file magic: 0x%x", magic)
	}

	if err := reader.skip(4); err != nil {
		return nil, err
	}

	cp, err := parseConstantPool(&reader)
	if err != nil {
		return nil, err
	}

	if err := reader.skip(6); err != nil {
		return nil, err
	}

	interfacesCount, err := reader.u2()
	if err != nil {
		return nil, err
	}
	if err := reader.skip(int(interfacesCount) * 2); err != nil {
		return nil, err
	}

	fieldsCount, err := reader.u2()
	if err != nil {
		return nil, err
	}
	for range int(fieldsCount) {
		if err := skipMember(&reader); err != nil {
			return nil, err
		}
	}

	methodsCount, err := reader.u2()
	if err != nil {
		return nil, err
	}
	class := &Class{}
	for range int(methodsCount) {
		annotations, err := parseMemberAnnotations(&reader, cp)
		if err != nil {
			return nil, err
		}
		if len(annotations) > 0 {
			class.MethodAnnotations = append(class.MethodAnnotations, annotations)
		}
	}

	ClassAnnotations, err := parseAttributesAnnotations(&reader, cp)
	if err != nil {
		return nil, err
	}
	class.ClassAnnotations = ClassAnnotations

	return class, nil
}

func parseConstantPool(reader *classReader) (constantPool, error) {
	count, err := reader.u2()
	if err != nil {
		return nil, err
	}

	cp := make(constantPool, count)
	if count == 0 {
		return nil, errors.New("empty constant pool")
	}
	for i := uint16(1); i < count; i++ {
		tag, err := reader.u1()
		if err != nil {
			return nil, err
		}
		cp[i].tag = tag

		switch tag {
		case cpTagUtf8:
			length, err := reader.u2()
			if err != nil {
				return nil, err
			}
			b, err := reader.bytes(int(length))
			if err != nil {
				return nil, err
			}
			cp[i].utf8 = string(b)
		case cpTagInteger, cpTagFloat:
			if err := reader.skip(4); err != nil {
				return nil, err
			}
		case cpTagLong, cpTagDouble:
			if i+1 >= count {
				return nil, errors.New("missing second constant pool slot")
			}
			if err := reader.skip(8); err != nil {
				return nil, err
			}
			// Long and Double constants occupy two entries in the
			// constant pool table; skip the unusable next index.
			i++
		case cpTagClass, cpTagString, cpTagMethodType, cpTagModule, cpTagPackage:
			index, err := reader.u2()
			if err != nil {
				return nil, err
			}
			cp[i].index = index
		case cpTagFieldref, cpTagMethodref, cpTagInterfaceMethodref, cpTagNameAndType, cpTagDynamic, cpTagInvokeDynamic:
			if err := reader.skip(4); err != nil {
				return nil, err
			}
		case cpTagMethodHandle:
			if err := reader.skip(3); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported constant pool tag %d", tag)
		}
	}

	return cp, nil
}

func skipMember(reader *classReader) error {
	if err := reader.skip(6); err != nil {
		return err
	}
	return skipAttributes(reader)
}

func parseMemberAnnotations(reader *classReader, cp constantPool) ([]Annotation, error) {
	if err := reader.skip(6); err != nil {
		return nil, err
	}
	return parseAttributesAnnotations(reader, cp)
}

func skipAttributes(reader *classReader) error {
	count, err := reader.u2()
	if err != nil {
		return err
	}
	for range int(count) {
		if err := reader.skip(2); err != nil {
			return err
		}
		length, err := reader.u4()
		if err != nil {
			return err
		}
		if err := reader.skip(int(length)); err != nil {
			return err
		}
	}
	return nil
}

func parseAttributesAnnotations(reader *classReader, cp constantPool) ([]Annotation, error) {
	count, err := reader.u2()
	if err != nil {
		return nil, err
	}

	var annotations []Annotation
	for range int(count) {
		nameIndex, err := reader.u2()
		if err != nil {
			return nil, err
		}
		length, err := reader.u4()
		if err != nil {
			return nil, err
		}
		data, err := reader.bytes(int(length))
		if err != nil {
			return nil, err
		}

		name, ok := cp.utf8(nameIndex)
		if !ok || !isAnnotationsAttribute(name) {
			continue
		}

		attrAnnotations, err := parseAnnotationsAttribute(data, cp)
		if err != nil {
			return nil, err
		}
		annotations = append(annotations, attrAnnotations...)
	}

	return annotations, nil
}

func isAnnotationsAttribute(name string) bool {
	return name == "RuntimeVisibleAnnotations" || name == "RuntimeInvisibleAnnotations"
}

func parseAnnotationsAttribute(data []byte, cp constantPool) ([]Annotation, error) {
	reader := classReader{data: data}
	count, err := reader.u2()
	if err != nil {
		return nil, err
	}

	annotations := make([]Annotation, 0, count)
	for range int(count) {
		ann, err := parseAnnotation(&reader, cp)
		if err != nil {
			return nil, err
		}
		annotations = append(annotations, ann)
	}
	if reader.off != len(data) {
		return nil, errors.New("trailing annotation data")
	}
	return annotations, nil
}

func parseAnnotation(reader *classReader, cp constantPool) (Annotation, error) {
	if reader.depth >= maxAnnotationDepth {
		return Annotation{}, errors.New("annotation nesting limit exceeded")
	}
	reader.depth++
	defer func() { reader.depth-- }()
	typeIndex, err := reader.u2()
	if err != nil {
		return Annotation{}, err
	}
	descriptor, ok := cp.utf8(typeIndex)
	if !ok {
		return Annotation{}, fmt.Errorf("invalid annotation type index %d", typeIndex)
	}

	pairCount, err := reader.u2()
	if err != nil {
		return Annotation{}, err
	}

	ann := Annotation{
		Descriptor: descriptor,
		Elements:   map[string][]string{},
	}
	for range int(pairCount) {
		nameIndex, err := reader.u2()
		if err != nil {
			return Annotation{}, err
		}
		name, ok := cp.utf8(nameIndex)
		if !ok {
			return Annotation{}, fmt.Errorf("invalid annotation element name index %d", nameIndex)
		}

		values, err := parseElementValue(reader, cp)
		if err != nil {
			return Annotation{}, err
		}
		if len(values.strings) > 0 {
			ann.Elements[name] = append(ann.Elements[name], values.strings...)
		}
		if len(values.annotations) > 0 {
			ann.Nested = append(ann.Nested, values.annotations...)
		}
	}

	return ann, nil
}

func parseElementValue(reader *classReader, cp constantPool) (elementValue, error) {
	if reader.depth >= maxAnnotationDepth {
		return elementValue{}, errors.New("annotation nesting limit exceeded")
	}
	reader.depth++
	defer func() { reader.depth-- }()
	tag, err := reader.u1()
	if err != nil {
		return elementValue{}, err
	}

	switch tag {
	case 's':
		index, err := reader.u2()
		if err != nil {
			return elementValue{}, err
		}
		value, ok := cp.stringValue(index)
		if !ok {
			return elementValue{}, fmt.Errorf("invalid string annotation value index %d", index)
		}
		return elementValue{strings: []string{value}}, nil
	case '[':
		count, err := reader.u2()
		if err != nil {
			return elementValue{}, err
		}
		var values elementValue
		for range int(count) {
			nested, err := parseElementValue(reader, cp)
			if err != nil {
				return elementValue{}, err
			}
			values.strings = append(values.strings, nested.strings...)
			values.annotations = append(values.annotations, nested.annotations...)
		}
		return values, nil
	case 'e':
		if err := readAnnotationConstant(reader, cp, cpTagUtf8); err != nil {
			return elementValue{}, err
		}
		return elementValue{}, readAnnotationConstant(reader, cp, cpTagUtf8)
	case 'c':
		return elementValue{}, readAnnotationConstant(reader, cp, cpTagUtf8)
	case '@':
		ann, err := parseAnnotation(reader, cp)
		if err != nil {
			return elementValue{}, err
		}
		return elementValue{annotations: []Annotation{ann}}, nil
	case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z':
		constantTag := cpTagInteger
		switch tag {
		case 'D':
			constantTag = cpTagDouble
		case 'F':
			constantTag = cpTagFloat
		case 'J':
			constantTag = cpTagLong
		}
		return elementValue{}, readAnnotationConstant(reader, cp, constantTag)
	default:
		return elementValue{}, fmt.Errorf("unsupported annotation value tag %q", tag)
	}
}

func readAnnotationConstant(reader *classReader, cp constantPool, tag uint8) error {
	index, err := reader.u2()
	if err != nil {
		return err
	}
	if int(index) >= len(cp) || cp[index].tag != tag {
		return errors.New("invalid annotation constant reference")
	}
	return nil
}

func (cp constantPool) utf8(index uint16) (string, bool) {
	if int(index) >= len(cp) || cp[index].tag != 1 {
		return "", false
	}
	return cp[index].utf8, true
}

func (cp constantPool) stringValue(index uint16) (string, bool) {
	if value, ok := cp.utf8(index); ok {
		return value, true
	}
	if int(index) >= len(cp) || cp[index].tag != 8 {
		return "", false
	}
	return cp.utf8(cp[index].index)
}

func (r *classReader) u1() (uint8, error) {
	if r.off+1 > len(r.data) {
		return 0, errors.New("unexpected end of class file")
	}
	value := r.data[r.off]
	r.off++
	return value, nil
}

func (r *classReader) u2() (uint16, error) {
	if r.off+2 > len(r.data) {
		return 0, errors.New("unexpected end of class file")
	}
	value := binary.BigEndian.Uint16(r.data[r.off:])
	r.off += 2
	return value, nil
}

func (r *classReader) u4() (uint32, error) {
	if r.off+4 > len(r.data) {
		return 0, errors.New("unexpected end of class file")
	}
	value := binary.BigEndian.Uint32(r.data[r.off:])
	r.off += 4
	return value, nil
}

func (r *classReader) bytes(n int) ([]byte, error) {
	if n < 0 || n > len(r.data)-r.off {
		return nil, errors.New("unexpected end of class file")
	}
	value := r.data[r.off : r.off+n]
	r.off += n
	return value, nil
}

func (r *classReader) skip(n int) error {
	_, err := r.bytes(n)
	return err
}
