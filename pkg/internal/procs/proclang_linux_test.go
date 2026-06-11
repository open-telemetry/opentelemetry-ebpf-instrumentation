//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/internal/fastelf"
)

func TestMatchExeSymbols_InvalidStringOffset(t *testing.T) {
	const symSize = 24

	data := make([]byte, symSize+4)
	binary.LittleEndian.PutUint32(data[0:4], 128)
	data[4] = 0x02
	binary.LittleEndian.PutUint64(data[8:16], 1)
	binary.LittleEndian.PutUint64(data[16:24], 1)
	copy(data[symSize:], []byte("x\x00"))

	ctx := &fastelf.ElfContext{
		Data: data,
		Sections: []*fastelf.Elf64_Shdr{
			{
				Type:    fastelf.SHT_SYMTAB,
				Link:    1,
				Offset:  0,
				Size:    symSize,
				Entsize: symSize,
			},
			{
				Offset: symSize,
			},
		},
	}

	assert.Equal(t, svc.InstrumentableGeneric, matchExeSymbols(ctx))
}

func TestFindExeSymbolsExactLookup(t *testing.T) {
	f := openCurrentTestELF(t)
	defer f.Close()

	syms, err := FindExeSymbols(f, []string{"go.opentelemetry.io/obi/pkg/internal/procs.TestFindExeSymbolsExactLookup"})
	require.NoError(t, err)

	sym, ok := syms["go.opentelemetry.io/obi/pkg/internal/procs.TestFindExeSymbolsExactLookup"]
	require.True(t, ok)
	assert.NotZero(t, sym.Off)
	assert.NotZero(t, sym.Len)
	assert.NotNil(t, sym.Prog)
}

func TestFindExeSymbolsSubstringLookup(t *testing.T) {
	f := openCurrentTestELF(t)
	defer f.Close()

	syms, err := FindExeSymbolsBySubstring(f, []string{"FindExeSymbolsSubstring"})
	require.NoError(t, err)

	sym, ok := syms["FindExeSymbolsSubstring"]
	require.True(t, ok)
	assert.NotZero(t, sym.Off)
	assert.NotZero(t, sym.Len)
	assert.NotNil(t, sym.Prog)
}

func openCurrentTestELF(t *testing.T) *elf.File {
	t.Helper()

	exe, err := os.Executable()
	require.NoError(t, err)

	f, err := elf.Open(exe)
	require.NoError(t, err)

	return f
}
