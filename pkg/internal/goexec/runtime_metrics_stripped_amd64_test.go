// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"debug/elf"
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/arch/x86/x86asm"
)

func TestResolveGOMAXPROCSFromCode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address uint64
		size    uint64
		flags   elf.ProgFlag
		want    uint64
	}{
		{"valid", 0x2000, 4, elf.PF_R | elf.PF_W, 0x2000},
		{"misaligned", 0x2001, 8, elf.PF_R | elf.PF_W, 0},
		{"crosses segment end", 0x2000, 3, elf.PF_R | elf.PF_W, 0},
		{"read-only memory", 0x2000, 4, elf.PF_R, 0},
		{"outside segment", 0x2004, 4, elf.PF_R | elf.PF_W, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const functionAddress = 0x1000
			code := []byte{0x8b, 0x05, 0, 0, 0, 0, 0x85, 0xc0, 0x7c, 1}
			// MOV ends at functionAddress+6; its displacement points to the candidate.
			binary.LittleEndian.PutUint32(code[2:6], uint32(tc.address-(functionAddress+6)))
			f := &elf.File{Progs: []*elf.Prog{{ProgHeader: elf.ProgHeader{
				Type: elf.PT_LOAD, Flags: tc.flags, Vaddr: 0x2000, Memsz: tc.size,
			}}}}
			address, err := resolveGOMAXPROCSFromCode(f, functionAddress, code)
			if tc.want == 0 {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.want, address)
		})
	}
}

func TestDecodeRuntimeMetricX86Instructions(t *testing.T) {
	code := []byte{
		0xf3, 0x0f, 0x1e, 0xfa, // ENDBR64
		0x8b, 0x05, 0x10, 0x00, 0x00, 0x00, // MOV EAX, [RIP+0x10]
		0x85, 0xc0, // TEST EAX, EAX
		0x7c, 0x01, // JL +1
		0xc3, // RET
	}
	instructions, err := decodeRuntimeMetricX86Instructions(code)
	require.NoError(t, err)
	require.Len(t, instructions, 4)
	for i, offset := range []int{4, 10, 12, 14} {
		require.Equal(t, offset, instructions[i].offsetInFunction)
	}
	require.Equal(t, x86asm.MOV, instructions[0].inst.Op)
	require.Equal(t, x86asm.Mem{Base: x86asm.RIP, Disp: 0x10}, instructions[0].inst.Args[1])
	require.Equal(t, x86asm.TEST, instructions[1].inst.Op)
	require.Equal(t, x86asm.JL, instructions[2].inst.Op)
}

func TestDecodeRuntimeMetricX86InstructionsTruncated(t *testing.T) {
	// The final MOV opcode is missing its operands, after a valid candidate.
	code := []byte{0x8b, 0x05, 0x10, 0, 0, 0, 0x85, 0xc0, 0x7c, 1, 0x8b}
	instructions, err := decodeRuntimeMetricX86Instructions(code)
	require.Error(t, err)
	require.Nil(t, instructions)
}

func TestIsGOMAXPROCSLoadSequence(t *testing.T) {
	for _, tc := range []struct {
		name string
		code []byte
		want bool
	}{
		{"valid", []byte{0x8b, 0x05, 0x10, 0, 0, 0, 0x85, 0xc0, 0x7c, 1}, true},
		{"different destination register", []byte{0x8b, 0x0d, 0x10, 0, 0, 0, 0x85, 0xc9, 0x7c, 1}, true},
		{"64-bit load", []byte{0x48, 0x8b, 0x05, 0x10, 0, 0, 0, 0x48, 0x85, 0xc0, 0x7c, 1}, false},
		{"non-RIP load", []byte{0x8b, 0x03, 0x85, 0xc0, 0x7c, 1}, false},
		{"test different register", []byte{0x8b, 0x05, 0x10, 0, 0, 0, 0x85, 0xc9, 0x7c, 1}, false},
		{"test two registers", []byte{0x8b, 0x05, 0x10, 0, 0, 0, 0x85, 0xc8, 0x7c, 1}, false},
		{"different branch", []byte{0x8b, 0x05, 0x10, 0, 0, 0, 0x85, 0xc0, 0x74, 1}, false},
		{"missing branch", []byte{0x8b, 0x05, 0x10, 0, 0, 0, 0x85, 0xc0}, false},
		{"empty", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			instructions, err := decodeRuntimeMetricX86Instructions(tc.code)
			require.NoError(t, err)
			require.Equal(t, tc.want, isGOMAXPROCSLoadSequence(instructions, 0))
			require.False(t, isGOMAXPROCSLoadSequence(instructions, -1))
			require.False(t, isGOMAXPROCSLoadSequence(instructions, len(instructions)))
		})
	}
}

func TestRuntimeMetricRIPTarget(t *testing.T) {
	for _, tc := range []struct {
		name         string
		base         uint64
		offset       int
		length       int
		displacement int64
		want         uint64
		ok           bool
	}{
		{"forward", 0x1000, 4, 6, 0x10, 0x101a, true},
		{"backward", 0x1000, 4, 6, -0x10, 0xffa, true},
		{"offset overflow", math.MaxUint64, 1, 6, 0, 0, false},
		{"length overflow", math.MaxUint64 - 5, 0, 6, 0, 0, false},
		{"displacement overflow", math.MaxUint64 - 6, 0, 6, 1, 0, false},
		{"displacement underflow", 0, 0, 6, -7, 0, false},
		{"negative offset", 0x1000, -1, 6, 0, 0, false},
		{"zero length", 0x1000, 0, 0, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			instruction := runtimeMetricX86Instruction{
				offsetInFunction: tc.offset,
				inst: x86asm.Inst{
					Len: tc.length,
					Args: x86asm.Args{x86asm.EAX, x86asm.Mem{
						Base: x86asm.RIP, Disp: tc.displacement,
					}},
				},
			}
			address, ok := runtimeMetricRIPTarget(tc.base, instruction)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.want, address)
		})
	}
}
