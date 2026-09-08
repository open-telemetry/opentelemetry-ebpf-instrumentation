// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goabi

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/goversion"
)

func TestFromLookupValidatesABI(t *testing.T) {
	values := validValues(t)
	values["internal/abi.TFlag."+sizeField] = 8

	_, err := FromLookup(goversion.MustParse("go1.27.0"), mapLookup(values))
	require.ErrorContains(t, err, "unsupported Go runtime ABI scalar sizes")
}

func TestFromLookupRejectsInvalidITabLayout(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value uint64
	}{
		{name: "function array is not trailing", key: "internal/abi.ITab." + sizeField, value: 40},
		{name: "type field is out of bounds", key: "internal/abi.Type.TFlag", value: 48},
		{name: "interface slice is out of bounds", key: "internal/abi.InterfaceType.Methods", value: 72},
		{name: "interface pointer is unaligned", key: "internal/abi.ITab.Inter", value: 1},
		{name: "type-specific data is inside type header", key: "internal/abi.ArrayType." + sizeField, value: 40},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := validValues(t)
			values[test.key] = test.value

			_, err := FromLookup(goversion.MustParse("go1.27.0"), mapLookup(values))
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

			_, err := FromLookup(goversion.MustParse("go1.27.0"), mapLookup(values))
			require.ErrorContains(t, err, test.message)
		})
	}
}
