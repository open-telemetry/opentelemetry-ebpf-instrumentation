// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"
	"unsafe"

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

func TestParseUSDTNote32BigEndian(t *testing.T) {
	desc := makeUSDTDesc32(
		t,
		binary.BigEndian,
		0x1020,
		0x1000,
		0x2008,
		"hotspot",
		"gc__heap__summary",
		"4@%edi 8@%rsi",
	)

	note, err := parseUSDTNote(elf.ELFCLASS32, binary.BigEndian, desc)
	require.NoError(t, err)

	assert.Equal(t, uint64(0x1020), note.Location)
	assert.Equal(t, uint64(0x1000), note.Base)
	assert.Equal(t, uint64(0x2008), note.Semaphore)
	assert.Equal(t, "hotspot", note.Provider)
	assert.Equal(t, "gc__heap__summary", note.Name)
	assert.Equal(t, "4@%edi 8@%rsi", note.Args)
}

func TestReadSDTHeaderUsesELFByteOrder(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint32(8)))
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint32(16)))
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint32(obiUSDTNoteType)))

	header, err := readSDTHeader(binary.BigEndian, buf.Bytes())
	require.NoError(t, err)

	assert.Equal(t, uint32(8), header.NameSize)
	assert.Equal(t, uint32(16), header.DescSize)
	assert.Equal(t, uint32(obiUSDTNoteType), header.Type)
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
	assert.Equal(t, ^uint64(15), spec.Args[2].ValOff)

	assert.Equal(t, obiUSDTArgConst, spec.Args[3].ArgType)
	assert.Equal(t, uint64(7), spec.Args[3].ValOff)
}

func TestOBIUSDTSpecLayoutMatchesBPFABI(t *testing.T) {
	assert.Equal(t, 16, binary.Size(obiUSDTArgSpec{}))
	assert.Equal(t, uintptr(0), unsafe.Offsetof(obiUSDTArgSpec{}.ValOff))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(obiUSDTArgSpec{}.RegOff))
	assert.Equal(t, uintptr(10), unsafe.Offsetof(obiUSDTArgSpec{}.ArgType))
	assert.Equal(t, uintptr(11), unsafe.Offsetof(obiUSDTArgSpec{}.ArgSigned))
	assert.Equal(t, uintptr(12), unsafe.Offsetof(obiUSDTArgSpec{}.ArgBitshift))
	assert.Equal(t, 208, binary.Size(obiUSDTSpec{}))
	assert.Equal(t, 16, binary.Size(obiUSDTIPKey{}))
	assert.Equal(t, uintptr(0), unsafe.Offsetof(obiUSDTIPKey{}.PID))
	assert.Equal(t, uintptr(4), unsafe.Offsetof(obiUSDTIPKey{}.Namespace))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(obiUSDTIPKey{}.IP))
}

func TestParseUSDTArgSpecX8664RejectsSIBAddressing(t *testing.T) {
	_, err := parseUSDTArgSpec(elf.EM_X86_64, "8@0x10(%rax,%rbx,2)")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unrecognized x86_64 USDT argument")
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

func TestParseUSDTArgSpecHotSpotArm64MemoryPoolGC(t *testing.T) {
	spec, err := parseUSDTArgSpec(elf.EM_AARCH64, "8@x22 8@x20 8@x23 8@x0 8@x26 8@x27 8@[sp, 112] 8@[sp, 120]")
	require.NoError(t, err)

	require.Equal(t, uint16(8), spec.ArgCount)
	for i := 0; i < 6; i++ {
		assert.Equal(t, obiUSDTArgReg, spec.Args[i].ArgType)
	}
	assert.Equal(t, int16(22*8), spec.Args[0].RegOff)
	assert.Equal(t, int16(20*8), spec.Args[1].RegOff)
	assert.Equal(t, int16(23*8), spec.Args[2].RegOff)
	assert.Equal(t, int16(0), spec.Args[3].RegOff)
	assert.Equal(t, int16(26*8), spec.Args[4].RegOff)
	assert.Equal(t, int16(27*8), spec.Args[5].RegOff)

	assert.Equal(t, obiUSDTArgRegDeref, spec.Args[6].ArgType)
	assert.Equal(t, int16(248), spec.Args[6].RegOff)
	assert.Equal(t, uint64(112), spec.Args[6].ValOff)
	assert.Equal(t, obiUSDTArgRegDeref, spec.Args[7].ArgType)
	assert.Equal(t, int16(248), spec.Args[7].RegOff)
	assert.Equal(t, uint64(120), spec.Args[7].ValOff)
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

func makeUSDTDesc32(t *testing.T, order binary.ByteOrder, location, base, semaphore uint32, provider, name, args string) []byte {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, order, location))
	require.NoError(t, binary.Write(&buf, order, base))
	require.NoError(t, binary.Write(&buf, order, semaphore))
	buf.WriteString(provider)
	buf.WriteByte(0)
	buf.WriteString(name)
	buf.WriteByte(0)
	buf.WriteString(args)
	buf.WriteByte(0)
	return buf.Bytes()
}
