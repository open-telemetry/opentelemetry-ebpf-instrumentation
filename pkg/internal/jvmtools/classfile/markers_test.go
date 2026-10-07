// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package classfile

import (
	"encoding/binary"
	"testing"
)

type testAttribute struct {
	name uint16
	data []byte
}

func markerFixture(attributes ...testAttribute) []byte {
	b := binary.BigEndian.AppendUint32(nil, classFileMagic)
	for _, n := range []uint16{0, 52, 11} {
		b = binary.BigEndian.AppendUint16(b, n)
	}
	for _, entry := range []struct {
		text  string
		class uint16
	}{
		{text: "Example"},
		{class: 1},
		{text: "java/lang/Object"},
		{class: 3},
		{text: "RuntimeVisibleAnnotations"},
		{text: "Lkotlin/Metadata;"},
		{text: "Lscala/reflect/ScalaSignature;"},
		{text: "TASTY"},
		{text: "Lscala/reflect/ScalaLongSignature;"},
		{text: "Lexample/Unrelated;"},
	} {
		if entry.class != 0 {
			b = append(b, cpTagClass)
			b = binary.BigEndian.AppendUint16(b, entry.class)
		} else {
			b = append(b, cpTagUtf8)
			b = binary.BigEndian.AppendUint16(b, uint16(len(entry.text)))
			b = append(b, entry.text...)
		}
	}
	for _, n := range []uint16{1, 2, 4, 0, 0, 0, uint16(len(attributes))} {
		b = binary.BigEndian.AppendUint16(b, n)
	}
	for _, a := range attributes {
		b = binary.BigEndian.AppendUint16(b, a.name)
		b = binary.BigEndian.AppendUint32(b, uint32(len(a.data)))
		b = append(b, a.data...)
	}
	return b
}

func annotations(indices ...uint16) testAttribute {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(indices)))
	for _, index := range indices {
		b = binary.BigEndian.AppendUint16(b, index)
		b = binary.BigEndian.AppendUint16(b, 0)
	}
	return testAttribute{5, b}
}

func TestInspectLanguage(t *testing.T) {
	for _, tt := range []struct {
		name, language string
		attrs          []testAttribute
		invalid        bool
	}{
		{name: "decoy pool strings"},
		{name: "kotlin", language: "kotlin", attrs: []testAttribute{annotations(6)}},
		{name: "scala signature", language: "scala", attrs: []testAttribute{annotations(7)}},
		{name: "scala long signature", language: "scala", attrs: []testAttribute{annotations(9)}},
		{name: "scala tasty", language: "scala", attrs: []testAttribute{{8, make([]byte, 16)}}},
		{name: "conflict", attrs: []testAttribute{annotations(6, 7)}, invalid: true},
		{name: "bad tasty", attrs: []testAttribute{{8, []byte{1}}}, invalid: true},
		{name: "bad annotation reference", attrs: []testAttribute{annotations(50)}, invalid: true},
		{name: "bad attribute reference", attrs: []testAttribute{{50, nil}}, invalid: true},
		{name: "trailing annotation bytes", attrs: []testAttribute{{5, []byte{0, 0, 1}}}, invalid: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := InspectLanguage(markerFixture(tt.attrs...))
			if tt.invalid {
				if err == nil {
					t.Fatal("expected malformed/conflicting input to fail")
				}
				return
			}
			if err != nil || got.Language != tt.language {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
	valid := markerFixture(annotations(6))
	for n := range len(valid) {
		if _, err := InspectLanguage(valid[:n]); err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
}

func TestAnnotationNestingLimit(t *testing.T) {
	cp := constantPool{{}, {tag: cpTagUtf8, utf8: "Lexample/A;"}, {tag: cpTagUtf8, utf8: "value"}}
	data := []byte{0, 1, 0, 1, 0, 1, 0, 2}
	for range maxAnnotationDepth + 1 {
		data = append(data, '[', 0, 1)
	}
	data = append(data, 's', 0, 2)
	if _, err := parseAnnotationsAttribute(data, cp); err == nil {
		t.Fatal("accepted excessive nesting")
	}
}

func FuzzInspectLanguage(f *testing.F) {
	f.Add(markerFixture())
	f.Add(markerFixture(annotations(6)))
	f.Add(markerFixture(testAttribute{8, make([]byte, 16)}))
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = InspectLanguage(data) })
}
