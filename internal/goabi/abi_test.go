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

func TestDefinitionsByGoVersion(t *testing.T) {
	legacy, err := Definitions("go1.26.9")
	require.NoError(t, err)
	require.Len(t, legacy, 6)
	for _, definition := range legacy {
		assert.Equal(t, "runtime.moduledata", definition.OutputType)
	}

	current, err := Definitions("go1.27.0")
	require.NoError(t, err)
	assert.Greater(t, len(current), len(legacy))

	keys := map[string]struct{}{}
	for _, definition := range current {
		_, duplicate := keys[definition.Key()]
		assert.False(t, duplicate, definition.Key())
		keys[definition.Key()] = struct{}{}
	}
	assert.Contains(t, keys, "internal/abi.ITab.Inter")
}

func TestFromLookupRequiresCompleteABI(t *testing.T) {
	values := validValues(t)
	delete(values, "runtime.moduledata.itabsize")

	_, err := FromLookup("go1.27.0", mapLookup(values))
	require.ErrorContains(t, err, "runtime.moduledata.itabsize")
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

func TestFromLookupBuildsDerivedFacts(t *testing.T) {
	values := validValues(t)
	abi, err := FromLookup("go1.27.0", mapLookup(values))
	require.NoError(t, err)

	assert.Equal(t, abi.TypeMetadata.InterfaceMethods+abi.TypeMetadata.SliceLenOffset, abi.TypeMetadata.InterfaceLenOffset)
	assert.Equal(t, abi.TypeMetadata.ITabBaseSize-abi.TypeMetadata.ITabFunOffset, abi.TypeMetadata.ITabFuncSize)
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
	definitions, err := Definitions("go1.27.0")
	require.NoError(t, err)
	assert.Len(t, abi.Facts(), len(definitions))
	assert.Equal(t, uint64(0), abi.TypeMetadata.ITabInterOffset)
}

func TestStoreValueRejectsConflicts(t *testing.T) {
	values := map[string]uint64{"fact": 1}
	require.NoError(t, storeValue(values, "fact", 1))
	require.ErrorContains(t, storeValue(values, "fact", 2), "conflicting values")
}

func validValues(t *testing.T) map[string]uint64 {
	t.Helper()
	definitions, err := Definitions("go1.27.0")
	require.NoError(t, err)
	values := make(map[string]uint64, len(definitions))
	for _, definition := range definitions {
		values[definition.Key()] = 1
	}
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
	for _, typeName := range []string{
		"internal/abi.ArrayType",
		"internal/abi.ChanType",
		"internal/abi.FuncType",
		"internal/abi.MapType",
		"internal/abi.PtrType",
		"internal/abi.SliceType",
		"internal/abi.StructType",
	} {
		values[typeName+"."+SizeField] = 48
	}
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

func mapLookup(values map[string]uint64) func(Definition) (uint64, error) {
	return func(definition Definition) (uint64, error) {
		value, ok := values[definition.Key()]
		if !ok {
			return 0, errors.New("not found")
		}
		return value, nil
	}
}
