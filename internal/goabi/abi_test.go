// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goabi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTypeMetadataDerivedOffsets(t *testing.T) {
	metadata := TypeMetadata{
		TypeTFlagOffset:         20,
		TypeKindOffset:          23,
		TypeNameOffset:          40,
		InterfaceMethodsOffset:  56,
		SliceLenOffset:          8,
		ITabFunOffset:           16,
		ArrayUncommonOffset:     48,
		ChanUncommonOffset:      56,
		FuncUncommonOffset:      64,
		InterfaceUncommonOffset: 80,
		MapUncommonOffset:       88,
		PointerUncommonOffset:   96,
		SliceUncommonOffset:     104,
		StructUncommonOffset:    112,
		TypeSize:                48,
		TFlagSize:               1,
		KindSize:                1,
		NameOffsetSize:          4,
		ITabBaseSize:            24,
		KindDirectIfaceFlag:     32,
		ArrayKind:               17,
		ChanKind:                18,
		FuncKind:                19,
		InterfaceKind:           20,
		MapKind:                 21,
		PointerKind:             22,
		SliceKind:               23,
		StructKind:              25,
	}

	assert.Equal(t, uint64(44), metadata.TypeHeaderSize())
	assert.Equal(t, uint64(64), metadata.InterfaceMethodCountOffset())
	assert.Equal(t, uint64(8), metadata.ITabFuncEntrySize())

	tests := []struct {
		kind   uint64
		offset uint64
	}{
		{kind: metadata.ArrayKind, offset: metadata.ArrayUncommonOffset},
		{kind: metadata.ChanKind, offset: metadata.ChanUncommonOffset},
		{kind: metadata.FuncKind, offset: metadata.FuncUncommonOffset},
		{kind: metadata.InterfaceKind, offset: metadata.InterfaceUncommonOffset},
		{kind: metadata.MapKind, offset: metadata.MapUncommonOffset},
		{kind: metadata.PointerKind, offset: metadata.PointerUncommonOffset},
		{kind: metadata.SliceKind, offset: metadata.SliceUncommonOffset},
		{kind: metadata.StructKind, offset: metadata.StructUncommonOffset},
	}
	for _, test := range tests {
		assert.Equal(t, test.offset, metadata.UncommonTypeOffset(byte(test.kind)))
		assert.Equal(
			t,
			test.offset,
			metadata.UncommonTypeOffset(byte(test.kind|metadata.KindDirectIfaceFlag)),
		)
	}
	assert.Equal(t, metadata.TypeSize, metadata.UncommonTypeOffset(1))
}
