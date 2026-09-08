// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package runtime

import (
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectPrivateCollectorSymbol(t *testing.T) {
	function := func(name string, value uint64) elf.Symbol {
		return elf.Symbol{Name: name, Info: byte(elf.STT_FUNC), Section: 1, Value: value}
	}

	t.Run("exact", func(t *testing.T) {
		address, err := selectPrivateCollectorSymbol([]elf.Symbol{function("gc_collect_main", 0x2000)})
		require.NoError(t, err)
		assert.Equal(t, uint64(0x2000), address)
	})

	t.Run("supported variants", func(t *testing.T) {
		address, err := selectPrivateCollectorSymbol([]elf.Symbol{
			function("gc_collect_main.lto_priv.0", 0x3000),
			function("gc_collect_main.lto_priv.0.cold", 0x1000),
		})
		require.NoError(t, err)
		assert.Equal(t, uint64(0x3000), address)
	})

	t.Run("duplicate tables", func(t *testing.T) {
		symbol := function("collect_with_callback", 0x4000)
		address, err := selectPrivateCollectorSymbol([]elf.Symbol{symbol}, []elf.Symbol{symbol})
		require.NoError(t, err)
		assert.Equal(t, uint64(0x4000), address)
	})

	t.Run("missing", func(t *testing.T) {
		_, err := selectPrivateCollectorSymbol([]elf.Symbol{function("unrelated", 0x5000)})
		require.ErrorIs(t, err, errUnsupportedLayout)
	})

	t.Run("ambiguous", func(t *testing.T) {
		_, err := selectPrivateCollectorSymbol([]elf.Symbol{
			function("gc_collect_main", 0x6000),
			function("gc_collect_internal", 0x7000),
		})
		require.ErrorIs(t, err, errUnsupportedLayout)
	})
}
