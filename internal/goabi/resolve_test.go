// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goabi

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFromLookupRequiresCompleteABI(t *testing.T) {
	values := validValues(t)
	delete(values, "runtime.moduledata.itabsize")

	_, err := FromLookup("go1.27.0", mapLookup(values))
	require.ErrorContains(t, err, "runtime.moduledata.itabsize")
}

func TestFromLookupLeavesUnrequiredTypeMetadataAbsent(t *testing.T) {
	requirements, err := Requirements("go1.26.9")
	require.NoError(t, err)
	values := make(map[string]uint64, len(requirements))
	for _, requirement := range requirements {
		values[requirement.Key()] = 1
	}

	abi, err := FromLookup("go1.26.9", mapLookup(values))
	require.NoError(t, err)
	assert.Nil(t, abi.TypeMetadata)
}

func TestFromLookupBuildsABI(t *testing.T) {
	values := validValues(t)
	abi, err := FromLookup("go1.27.0", mapLookup(values))
	require.NoError(t, err)

	assert.Equal(t, Moduledata{
		PCHeader:    0,
		PCLNTable:   104,
		MinPC:       160,
		MaxPC:       168,
		Text:        176,
		EText:       184,
		Types:       296,
		TypeDescLen: 304,
		ITabOffset:  320,
		ITabSize:    328,
	}, abi.Moduledata)
	require.NotNil(t, abi.TypeMetadata)
	assert.Equal(t, validTypeMetadata(), *abi.TypeMetadata)
	assert.Len(t, abi.Facts(), len(values))
}

func validValues(t *testing.T) map[string]uint64 {
	t.Helper()
	requirements, err := Requirements("go1.27.0")
	require.NoError(t, err)
	values := make(map[string]uint64, len(requirements))
	for _, requirement := range requirements {
		values[requirement.Key()] = 1
	}
	values["runtime.moduledata.pcHeader"] = 0
	values["runtime.moduledata.pclntable"] = 104
	values["runtime.moduledata.minpc"] = 160
	values["runtime.moduledata.maxpc"] = 168
	values["runtime.moduledata.text"] = 176
	values["runtime.moduledata.etext"] = 184
	values["runtime.moduledata.types"] = 296
	values["runtime.moduledata.typedesclen"] = 304
	values["runtime.moduledata.itaboffset"] = 320
	values["runtime.moduledata.itabsize"] = 328
	values["internal/abi.Type.TFlag"] = 20
	values["internal/abi.Type.Kind_"] = 23
	values["internal/abi.Type.Str"] = 40
	values["internal/abi.Type."+sizeField] = 48
	values["internal/abi.TFlag."+sizeField] = 1
	values["internal/abi.Kind."+sizeField] = 1
	values["internal/abi.NameOff."+sizeField] = 4
	values["internal/abi.InterfaceType.Methods"] = 56
	values["internal/abi.InterfaceType."+sizeField] = 80
	values["[]internal/abi.Imethod.len"] = 8
	values["internal/abi.ITab.Inter"] = 0
	values["internal/abi.ITab.Type"] = 8
	values["internal/abi.ITab.Fun"] = 16
	values["internal/abi.ITab."+sizeField] = 24
	values["internal/abi.UncommonType.PkgPath"] = 4
	values["internal/abi.ArrayType."+sizeField] = 48
	values["internal/abi.ChanType."+sizeField] = 56
	values["internal/abi.FuncType."+sizeField] = 64
	values["internal/abi.MapType."+sizeField] = 88
	values["internal/abi.PtrType."+sizeField] = 96
	values["internal/abi.SliceType."+sizeField] = 104
	values["internal/abi.StructType."+sizeField] = 112
	values["internal/abi.TFlagUncommon"] = 1
	values["internal/abi.TFlagExtraStar"] = 2
	values["internal/abi.KindDirectIface"] = 32
	values["internal/abi.Array"] = 17
	values["internal/abi.Chan"] = 18
	values["internal/abi.Func"] = 19
	values["internal/abi.Interface"] = 20
	values["internal/abi.Map"] = 21
	values["internal/abi.Pointer"] = 22
	values["internal/abi.Slice"] = 23
	values["internal/abi.Struct"] = 25
	return values
}

func validTypeMetadata() TypeMetadata {
	return TypeMetadata{
		TypeTFlagOffset:         20,
		TypeKindOffset:          23,
		TypeNameOffset:          40,
		InterfaceMethodsOffset:  56,
		SliceLenOffset:          8,
		ITabInterOffset:         0,
		ITabTypeOffset:          8,
		ITabFunOffset:           16,
		UncommonPkgPathOffset:   4,
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
		TFlagUncommonMask:       1,
		TFlagExtraStarMask:      2,
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
}

func mapLookup(values map[string]uint64) func(Requirement) (uint64, error) {
	return func(requirement Requirement) (uint64, error) {
		value, ok := values[requirement.Key()]
		if !ok {
			return 0, errors.New("not found")
		}
		return value, nil
	}
}
