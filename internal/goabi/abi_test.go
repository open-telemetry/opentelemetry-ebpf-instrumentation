// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goabi

import (
	"debug/elf"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequirementsByGoVersion(t *testing.T) {
	legacy, err := Requirements("go1.26.9")
	require.NoError(t, err)
	require.Len(t, legacy, 6)
	for _, definition := range legacy {
		assert.Equal(t, "runtime.moduledata", definition.OutputType)
	}
	rc, err := Requirements("go1.27rc1")
	require.NoError(t, err)
	assert.Equal(t, legacy, rc)

	current, err := Requirements("1.27.0")
	require.NoError(t, err)
	assert.Greater(t, len(current), len(legacy))
	prefixed, err := Requirements("go1.27.0")
	require.NoError(t, err)
	assert.Equal(t, current, prefixed)
	patch, err := Requirements("go1.27.1")
	require.NoError(t, err)
	assert.Equal(t, current, patch)

	keys := map[string]struct{}{}
	for _, definition := range current {
		_, duplicate := keys[definition.Key()]
		assert.False(t, duplicate, definition.Key())
		keys[definition.Key()] = struct{}{}
	}
	assert.Contains(t, keys, "internal/abi.ITab.Inter")
}

func TestDefinitionsCanAssignResolvedFacts(t *testing.T) {
	for _, definition := range definitions {
		assert.NotNil(t, definition.query, definition.Key())
		assert.NotNil(t, definition.assign, definition.Key())
	}
}

func TestRequirementsRejectsInvalidGoVersions(t *testing.T) {
	for _, goVersion := range []string{
		"release go1.27.0",
		"go1.27.0 release",
		"devel go1.29-abcdef",
	} {
		t.Run(goVersion, func(t *testing.T) {
			_, err := Requirements(goVersion)
			require.ErrorContains(t, err, "invalid Go version")
		})
	}
}

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

func TestFromLookupValidatesABI(t *testing.T) {
	values := validValues(t)
	values["internal/abi.TFlag."+SizeField] = 8

	_, err := FromLookup("go1.27.0", mapLookup(values))
	require.ErrorContains(t, err, "unsupported Go runtime ABI scalar sizes")
}

func TestFromLookupRejectsInvalidITabLayout(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value uint64
	}{
		{name: "function array is not trailing", key: "internal/abi.ITab." + SizeField, value: 40},
		{name: "type field is out of bounds", key: "internal/abi.Type.TFlag", value: 48},
		{name: "interface slice is out of bounds", key: "internal/abi.InterfaceType.Methods", value: 72},
		{name: "interface pointer is unaligned", key: "internal/abi.ITab.Inter", value: 1},
		{name: "type-specific data is inside type header", key: "internal/abi.ArrayType." + SizeField, value: 40},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := validValues(t)
			values[test.key] = test.value

			_, err := FromLookup("go1.27.0", mapLookup(values))
			require.ErrorContains(t, err, "invalid Go runtime ABI layout")
		})
	}
}

func TestFromLookupRejectsInvalidConstants(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		value   uint64
		message string
	}{
		{name: "non-power-of-two kind mask", key: "internal/abi.KindDirectIface", value: 33, message: "invalid Go runtime ABI constants"},
		{name: "zero kind", key: "internal/abi.Array", value: 0, message: "invalid Go runtime ABI kind constants"},
		{name: "kind above mask", key: "internal/abi.Array", value: 64, message: "invalid Go runtime ABI kind constants"},
		{name: "duplicate kind", key: "internal/abi.Array", value: 18, message: "invalid Go runtime ABI kind constants"},
		{name: "non-power-of-two flag", key: "internal/abi.TFlagUncommon", value: 3, message: "invalid Go runtime ABI constants"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := validValues(t)
			values[test.key] = test.value

			_, err := FromLookup("go1.27.0", mapLookup(values))
			require.ErrorContains(t, err, test.message)
		})
	}
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
	assert.Equal(t, TypeMetadata{
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
	}, *abi.TypeMetadata)
	assert.Equal(t, uint64(44), abi.TypeMetadata.TypeHeaderSize())
	assert.Equal(t, uint64(64), abi.TypeMetadata.InterfaceMethodCountOffset())
	assert.Equal(t, uint64(8), abi.TypeMetadata.ITabFuncEntrySize())
	assert.Equal(t, uint64(48), abi.TypeMetadata.UncommonTypeOffset(byte(abi.TypeMetadata.ArrayKind)))
	assert.Equal(
		t,
		uint64(48),
		abi.TypeMetadata.UncommonTypeOffset(byte(abi.TypeMetadata.ArrayKind|abi.TypeMetadata.KindDirectIfaceFlag)),
	)
	assert.Equal(t, abi.TypeMetadata.TypeSize, abi.TypeMetadata.UncommonTypeOffset(1))
	assert.Len(t, abi.Facts(), len(values))
}

func TestExtractCompleteRuntimeABI(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "inspect")
	source := filepath.Join("..", "..", "configs", "offsets", "std_inspect.go")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", executable, source)
	cmd.Env = append(os.Environ(), "GOOS=linux")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))

	file, err := elf.Open(executable)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })
	data, err := file.DWARF()
	require.NoError(t, err)

	abi, err := Extract(data, "go1.27.0")
	require.NoError(t, err)
	requirements, err := Requirements("go1.27.0")
	require.NoError(t, err)
	assert.Len(t, abi.Facts(), len(requirements))
	require.NotNil(t, abi.TypeMetadata)
	assert.Equal(t, uint64(0), abi.TypeMetadata.ITabInterOffset)

	legacyABI, err := Extract(data, "go1.26.9")
	require.NoError(t, err)
	assert.Nil(t, legacyABI.TypeMetadata)
	assert.Len(t, legacyABI.Facts(), 6)
}

func TestStoreValueRejectsConflicts(t *testing.T) {
	values := map[string]uint64{"fact": 1}
	require.NoError(t, storeValue(values, "fact", 1))
	require.ErrorContains(t, storeValue(values, "fact", 2), "conflicting values")
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
	values["internal/abi.Type."+SizeField] = 48
	values["internal/abi.TFlag."+SizeField] = 1
	values["internal/abi.Kind."+SizeField] = 1
	values["internal/abi.NameOff."+SizeField] = 4
	values["internal/abi.InterfaceType.Methods"] = 56
	values["internal/abi.InterfaceType."+SizeField] = 80
	values["[]internal/abi.Imethod.len"] = 8
	values["internal/abi.ITab.Inter"] = 0
	values["internal/abi.ITab.Type"] = 8
	values["internal/abi.ITab.Fun"] = 16
	values["internal/abi.ITab."+SizeField] = 24
	values["internal/abi.UncommonType.PkgPath"] = 4
	values["internal/abi.ArrayType."+SizeField] = 48
	values["internal/abi.ChanType."+SizeField] = 56
	values["internal/abi.FuncType."+SizeField] = 64
	values["internal/abi.MapType."+SizeField] = 88
	values["internal/abi.PtrType."+SizeField] = 96
	values["internal/abi.SliceType."+SizeField] = 104
	values["internal/abi.StructType."+SizeField] = 112
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

func mapLookup(values map[string]uint64) func(Requirement) (uint64, error) {
	return func(requirement Requirement) (uint64, error) {
		value, ok := values[requirement.Key()]
		if !ok {
			return 0, errors.New("not found")
		}
		return value, nil
	}
}
