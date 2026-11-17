// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// dwarf_test.go checks nested DWARF field lookup through typedefs and rejects
// missing fields, invalid paths, and fields extending beyond their containing type.

package rustexec

import (
	"debug/dwarf"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDwarfFieldBounds(t *testing.T) {
	word := &dwarf.UintType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{ByteSize: 8}}}
	inner := &dwarf.StructType{CommonType: dwarf.CommonType{ByteSize: 16}, Field: []*dwarf.StructField{
		{Name: "value", ByteOffset: 8, Type: word},
	}}
	outer := &dwarf.StructType{CommonType: dwarf.CommonType{ByteSize: 24}, Field: []*dwarf.StructField{
		{Name: "inner", ByteOffset: 8, Type: &dwarf.TypedefType{Type: inner}},
	}}
	offset, leaf, err := rustDwarfField(outer, "inner", "value")
	require.NoError(t, err)
	assert.EqualValues(t, 16, offset)
	assert.Equal(t, word, leaf)
	_, _, err = rustDwarfField(outer, "missing")
	require.Error(t, err)
	_, _, err = rustDwarfField(outer, "inner", "value", "invalid")
	require.Error(t, err)
	inner.Field[0].ByteOffset = 12
	_, _, err = rustDwarfField(inner, "value")
	require.Error(t, err)
}
