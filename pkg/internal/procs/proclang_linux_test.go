//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
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

func TestMatchExeSymbols_InvalidStringTableOffset(t *testing.T) {
	const symSize = 24

	ctx := &fastelf.ElfContext{
		Data: make([]byte, symSize),
		Sections: []*fastelf.Elf64_Shdr{
			{
				Type:    fastelf.SHT_SYMTAB,
				Link:    1,
				Size:    symSize,
				Entsize: symSize,
			},
			{
				Offset: ^uint64(0),
				Size:   1,
			},
		},
	}

	assert.Equal(t, svc.InstrumentableGeneric, matchExeSymbols(ctx))
}

func TestFindExeSymbolsExactLookup(t *testing.T) {
	const symbolName = "main.exactLookupTarget"

	f := openSymbolFixtureELF(t)
	defer f.Close()

	syms, err := FindExeSymbols(f, []string{symbolName})
	require.NoError(t, err)

	sym, ok := syms[symbolName]
	require.True(t, ok)
	assert.Equal(t, symbolName, sym.Name)
	assert.NotZero(t, sym.Off)
	assert.NotZero(t, sym.Len)
	assert.NotNil(t, sym.Prog)
}

func TestFindExeSymbolsSubstringLookup(t *testing.T) {
	const (
		symbolName = "main.substringLookupTarget"
		substring  = "substringLookup"
	)

	f := openSymbolFixtureELF(t)
	defer f.Close()

	syms, err := FindExeSymbolsBySubstring(f, []string{substring})
	require.NoError(t, err)

	sym, ok := syms[substring]
	require.True(t, ok)
	assert.Equal(t, symbolName, sym.Name)
	assert.NotZero(t, sym.Off)
	assert.NotZero(t, sym.Len)
	assert.NotNil(t, sym.Prog)
}

func TestFindExeSymbolsByNameAndSubstring(t *testing.T) {
	const (
		exactSymbolName    = "main.exactLookupTarget"
		substringSymbol    = "main.substringLookupTarget"
		symbolNameFragment = "substringLookup"
	)

	f := openSymbolFixtureELF(t)
	defer f.Close()

	exactSyms, substringSyms, err := FindExeSymbolsByNameAndSubstring(
		f,
		[]string{exactSymbolName},
		[]string{symbolNameFragment},
	)
	require.NoError(t, err)

	exactSym, ok := exactSyms[exactSymbolName]
	require.True(t, ok)
	assert.Equal(t, exactSymbolName, exactSym.Name)
	assert.NotZero(t, exactSym.Off)
	assert.NotZero(t, exactSym.Len)
	assert.NotNil(t, exactSym.Prog)

	substringSym, ok := substringSyms[symbolNameFragment]
	require.True(t, ok)
	assert.Equal(t, substringSymbol, substringSym.Name)
	assert.NotZero(t, substringSym.Off)
	assert.NotZero(t, substringSym.Len)
	assert.NotNil(t, substringSym.Prog)
}

func openSymbolFixtureELF(t *testing.T) *elf.File {
	t.Helper()

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "main.go")
	exePath := filepath.Join(dir, "symbol-fixture")

	require.NoError(t, os.WriteFile(sourcePath, []byte(`package main

//go:noinline
func exactLookupTarget() {}

//go:noinline
func substringLookupTarget() {}

func main() {
	exactLookupTarget()
	substringLookupTarget()
}
`), 0o600))

	cmd := exec.Command("go", "build", "-gcflags=all=-l", "-o", exePath, sourcePath)
	cmd.Env = append(os.Environ(), "GO111MODULE=off")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	require.NoError(t, cmd.Run(), out.String())

	f, err := elf.Open(exePath)
	require.NoError(t, err)

	return f
}
