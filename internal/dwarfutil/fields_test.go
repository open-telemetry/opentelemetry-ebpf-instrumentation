// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dwarfutil

import (
	"debug/dwarf"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFieldPath(t *testing.T) {
	word := &dwarf.UintType{BasicType: dwarf.BasicType{CommonType: dwarf.CommonType{ByteSize: 8}}}
	inner := &dwarf.StructType{CommonType: dwarf.CommonType{ByteSize: 16}, Field: []*dwarf.StructField{
		{Name: "value", ByteOffset: 8, Type: word},
	}}
	outer := &dwarf.StructType{CommonType: dwarf.CommonType{ByteSize: 24}, Field: []*dwarf.StructField{
		{Name: "inner", ByteOffset: 8, Type: &dwarf.TypedefType{Type: inner}},
	}}
	offset, leaf, err := FieldPath(outer, "inner", "value")
	require.NoError(t, err)
	assert.EqualValues(t, 16, offset)
	assert.Equal(t, word, leaf)
	_, _, err = FieldPath(outer, "missing")
	require.ErrorIs(t, err, ErrFieldNotFound)
	_, _, err = FieldPath(outer, "inner", "value", "invalid")
	require.Error(t, err)
	for _, invalidOffset := range []int64{-1, 12, math.MaxInt64} {
		inner.Field[0].ByteOffset = invalidOffset
		_, _, err = FieldPath(inner, "value")
		require.Error(t, err)
	}
	inner.Field[0].Type = nil
	_, _, err = FieldPath(inner, "value")
	require.ErrorContains(t, err, "has no type")
	require.NotErrorIs(t, err, ErrFieldNotFound)
}
