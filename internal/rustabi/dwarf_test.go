// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rustabi

import (
	"debug/dwarf"
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
