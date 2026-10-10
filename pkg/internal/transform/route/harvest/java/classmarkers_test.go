// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package java

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestInspectLanguageIgnoresMemberAnnotations(t *testing.T) {
	data := markerFixture(annotations(6))
	r := classReader{data: data}
	_, err := r.u4()
	require.NoError(t, err)
	require.NoError(t, r.skip(4))
	cp, err := parseConstantPool(&r)
	require.NoError(t, err)
	_, err = readClassIdentity(&r, cp)
	require.NoError(t, err)

	classData := append([]byte(nil), data[:r.off]...)
	memberAnnotation := annotations(7)
	for range 2 {
		// One member with a Scala annotation in each field/method table.
		for _, value := range []uint16{1, 0, 1, 3, 1, memberAnnotation.name} {
			classData = binary.BigEndian.AppendUint16(classData, value)
		}
		classData = binary.BigEndian.AppendUint32(classData, uint32(len(memberAnnotation.data)))
		classData = append(classData, memberAnnotation.data...)
	}
	classData = append(classData, data[r.off+2*2:]...)

	got, err := InspectLanguage(classData)
	require.NoError(t, err)
	assert.Equal(t, "kotlin", got.Language)
	assert.Equal(t, []string{"Lkotlin/Metadata;"}, got.Markers)
}

func TestParseAnnotations(t *testing.T) {
	for _, tt := range []struct {
		name    string
		attr    testAttribute
		invalid bool
	}{
		{name: "unrelated annotation", attr: annotations(10)},
		{name: "compiler annotation", attr: annotations(6)},
		{name: "invalid reference", attr: annotations(50), invalid: true},
		{name: "trailing data", attr: testAttribute{5, []byte{0, 0, 1}}, invalid: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			class, err := parseClassFile(markerFixture(tt.attr))
			if tt.invalid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, class.classAnnotations, 1)
			assert.Empty(t, class.methodAnnotations)
		})
	}
}

func TestAnnotationConstantReferences(t *testing.T) {
	for _, tt := range []struct {
		name string
		tag  byte
		pool uint8
	}{
		{"integer", 'I', cpTagInteger},
		{"boolean", 'Z', cpTagInteger},
		{"double", 'D', cpTagDouble},
		{"float", 'F', cpTagFloat},
		{"long", 'J', cpTagLong},
		{"class", 'c', cpTagUtf8},
		{"enum", 'e', cpTagUtf8},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cp := constantPool{{}, {tag: tt.pool, utf8: "value"}}
			data := []byte{tt.tag, 0, 1}
			if tt.tag == 'e' {
				data = append(data, 0, 1)
			}
			_, err := parseElementValue(&classReader{data: data}, cp)
			require.NoError(t, err)

			cp[1].tag = cpTagClass
			_, err = parseElementValue(&classReader{data: data}, cp)
			require.ErrorContains(t, err, "invalid annotation constant reference")
			data[len(data)-1] = 2
			_, err = parseElementValue(&classReader{data: data}, cp[:1])
			require.Error(t, err)
		})
	}
}

func TestConstantPoolSlotValidation(t *testing.T) {
	for _, data := range [][]byte{
		{0, 0},
		{0, 2, cpTagLong, 0, 0, 0, 0, 0, 0, 0, 0},
		{0, 2, cpTagDouble, 0, 0, 0, 0, 0, 0, 0, 0},
	} {
		_, err := parseConstantPool(&classReader{data: data})
		require.Error(t, err)
	}
	_, err := parseConstantPool(&classReader{data: []byte{0, 3, cpTagLong, 0, 0, 0, 0, 0, 0, 0, 0}})
	require.NoError(t, err)
}

func FuzzInspectLanguage(f *testing.F) {
	f.Add(markerFixture())
	f.Add(markerFixture(annotations(6)))
	f.Add(markerFixture(testAttribute{8, make([]byte, 16)}))
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = InspectLanguage(data) })
}
