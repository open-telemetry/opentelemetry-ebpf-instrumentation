// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rustabi

import (
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRustFieldOffsetLimit(t *testing.T) {
	word := &dwarf.UintType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{ByteSize: 8}}}
	field := &dwarf.StructField{Name: "value", Type: word, ByteOffset: maxRustFieldOffset}
	s := &dwarf.StructType{CommonType: dwarf.CommonType{ByteSize: maxRustFieldOffset + 16}, Field: []*dwarf.StructField{field}}
	offset, _, err := rustDwarfField(s, "value")
	require.NoError(t, err)
	require.EqualValues(t, maxRustFieldOffset, offset)
	field.ByteOffset++
	_, _, err = rustDwarfField(s, "value")
	require.Error(t, err)
}

func TestRustDiscriminantScope(t *testing.T) {
	// These abbreviations describe a DWARF 4 unit with one-byte attributes and references.
	const (
		end = iota
		unit
		word
		structure
		leaf
		variantPart
		tagMember
	)
	const (
		data1 = 0x0b // DW_FORM_data1
		ref1  = 0x11 // DW_FORM_ref1
	)
	abbrev := []byte{
		unit, byte(dwarf.TagCompileUnit), 1, 0, 0,
		word, byte(dwarf.TagBaseType), 0, byte(dwarf.AttrEncoding), data1, byte(dwarf.AttrByteSize), data1, 0, 0,
		structure, byte(dwarf.TagStructType), 1, 0, 0,
		leaf, byte(dwarf.TagStructType), 0, 0, 0,
		variantPart, byte(dwarf.TagVariantPart), 1, byte(dwarf.AttrDiscr), ref1, 0, 0,
		tagMember, byte(dwarf.TagMember), 0, byte(dwarf.AttrType), ref1, byte(dwarf.AttrDataMemberLoc), data1, 0, 0,
		end,
	}
	for _, tc := range []struct {
		name    string
		entries []byte
		hasTag  bool
	}{
		{"childless sender before enum", []byte{leaf, structure, variantPart, end}, false},
		{"sender with children before enum", []byte{structure, leaf, end, structure, variantPart, end}, false},
		{"nested enum", []byte{structure, structure, variantPart, end, end}, false},
		{"late direct variant part", []byte{structure, leaf, leaf, leaf, leaf, leaf, leaf, leaf, leaf, variantPart, end}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := []byte{0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8, unit}
			wordOffset := byte(len(info))
			info = append(info, word, 0x07, 8) // DW_ATE_unsigned, eight bytes
			root := dwarf.Offset(len(info))
			const tagOffset = 16
			for _, entry := range tc.entries {
				info = append(info, entry)
				if entry == variantPart {
					// DW_AT_discr points to the member immediately after the reference.
					info = append(info, byte(len(info)+1), tagMember, wordOffset, tagOffset, end)
				}
			}
			info = append(info, end)
			binary.LittleEndian.PutUint32(info, uint32(len(info)-4))

			data, err := dwarf.New(abbrev, nil, nil, info, nil, nil, nil, nil)
			require.NoError(t, err)
			sender, err := data.Type(root)
			require.NoError(t, err)
			types := rustDwarfTypes{data: data, names: map[string][]dwarf.Offset{"": {root}}}
			offset, err := types.discriminant(sender)
			if tc.hasTag {
				require.NoError(t, err)
				require.EqualValues(t, tagOffset, offset)
			} else {
				require.Error(t, err)
			}
		})
	}
}

// Enum payload fields require an explicit variant in the path.
func TestRustVariantScope(t *testing.T) {
	f, err := elf.Open("testdata/http1/http1.elf")
	require.NoError(t, err)
	defer f.Close()
	reader, err := newLayoutReader(f)
	require.NoError(t, err)

	const body = "hyper::body::incoming::Incoming"
	const envelope = "hyper::client::dispatch::Envelope<http::request::Request<" + body + ">, http::response::Response<" + body + ">>"
	require.NotEmpty(t, reader.typeEntryOffsets[envelope])
	message, err := reader.data.Type(reader.typeEntryOffsets[envelope][0])
	require.NoError(t, err)
	_, callback, err := reader.path(message, "__0", "Some", "__0", "__1")
	require.NoError(t, err)

	offset, _, err := reader.path(callback, "__0")
	require.ErrorContains(t, err, "rust variant __0 is missing", "Callback.__0 returned offset %d", offset)
	for _, variant := range []string{"Retry", "NoRetry"} {
		offset, _, err := reader.path(callback, variant, "__0")
		require.NoError(t, err)
		require.EqualValues(t, 8, offset)
	}
}
