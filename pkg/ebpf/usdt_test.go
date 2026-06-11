// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseUSDTNote64(t *testing.T) {
	desc := makeUSDTDesc64(
		t,
		0x401020,
		0x400000,
		0x600008,
		"hotspot",
		"mem__pool__gc__begin",
		"8@%rdi 4@%esi 8@%rdx",
	)

	note, err := parseUSDTNote(elf.ELFCLASS64, binary.LittleEndian, desc)
	require.NoError(t, err)

	assert.Equal(t, uint64(0x401020), note.Location)
	assert.Equal(t, uint64(0x400000), note.Base)
	assert.Equal(t, uint64(0x600008), note.Semaphore)
	assert.Equal(t, "hotspot", note.Provider)
	assert.Equal(t, "mem__pool__gc__begin", note.Name)
	assert.Equal(t, "8@%rdi 4@%esi 8@%rdx", note.Args)
}

func TestParseUSDTArgSpecX8664(t *testing.T) {
	spec, err := parseUSDTArgSpec(elf.EM_X86_64, "-8@%rdi 4@%esi 8@-0x10(%rsp) 8@$0x7")
	require.NoError(t, err)

	require.Equal(t, uint16(4), spec.ArgCount)

	assert.Equal(t, obiUSDTArgReg, spec.Args[0].ArgType)
	assert.Equal(t, int16(112), spec.Args[0].RegOff)
	assert.Equal(t, uint8(1), spec.Args[0].ArgSigned)
	assert.Equal(t, uint8(0), spec.Args[0].ArgBitshift)

	assert.Equal(t, obiUSDTArgReg, spec.Args[1].ArgType)
	assert.Equal(t, int16(104), spec.Args[1].RegOff)
	assert.Equal(t, uint8(0), spec.Args[1].ArgSigned)
	assert.Equal(t, uint8(32), spec.Args[1].ArgBitshift)

	assert.Equal(t, obiUSDTArgRegDeref, spec.Args[2].ArgType)
	assert.Equal(t, int16(152), spec.Args[2].RegOff)
	assert.Equal(t, uint64(^uint64(15)), spec.Args[2].ValOff)

	assert.Equal(t, obiUSDTArgConst, spec.Args[3].ArgType)
	assert.Equal(t, uint64(7), spec.Args[3].ValOff)
}

func TestParseUSDTArgSpecArm64(t *testing.T) {
	spec, err := parseUSDTArgSpec(elf.EM_AARCH64, "8@x0 4@w1 8@[sp, 0x10] 8@0x7")
	require.NoError(t, err)

	require.Equal(t, uint16(4), spec.ArgCount)

	assert.Equal(t, obiUSDTArgReg, spec.Args[0].ArgType)
	assert.Equal(t, int16(0), spec.Args[0].RegOff)

	assert.Equal(t, obiUSDTArgReg, spec.Args[1].ArgType)
	assert.Equal(t, int16(8), spec.Args[1].RegOff)
	assert.Equal(t, uint8(32), spec.Args[1].ArgBitshift)

	assert.Equal(t, obiUSDTArgRegDeref, spec.Args[2].ArgType)
	assert.Equal(t, int16(248), spec.Args[2].RegOff)
	assert.Equal(t, uint64(16), spec.Args[2].ValOff)

	assert.Equal(t, obiUSDTArgConst, spec.Args[3].ArgType)
	assert.Equal(t, uint64(7), spec.Args[3].ValOff)
}

func makeUSDTDesc64(t *testing.T, location, base, semaphore uint64, provider, name, args string) []byte {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, location))
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, base))
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, semaphore))
	buf.WriteString(provider)
	buf.WriteByte(0)
	buf.WriteString(name)
	buf.WriteByte(0)
	buf.WriteString(args)
	buf.WriteByte(0)
	return buf.Bytes()
}
