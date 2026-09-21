// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/arch/x86/x86asm"
)

func TestIsRuntimeMetricSizeClassTableLoad(t *testing.T) {
	// LEA RCX,[RIP+0x10c82f]; MOVZX EAX,WORD PTR [RCX+RAX*2].
	address := []byte{0x48, 0x8d, 0x0d, 0x2f, 0xc8, 0x10, 0x00}
	for _, tc := range []struct {
		name    string
		address []byte
		lookup  []byte
		want    bool
	}{
		{"observed lookup", address, []byte{0x0f, 0xb7, 0x04, 0x41}, true},
		{"different registers", []byte{0x48, 0x8d, 0x15, 0, 0, 0, 0}, []byte{0x0f, 0xb7, 0x0c, 0x5a}, true},
		{"wrong base", address, []byte{0x0f, 0xb7, 0x04, 0x42}, false},
		{"byte entry", address, []byte{0x0f, 0xb6, 0x04, 0x41}, false},
		{"signed entry", address, []byte{0x0f, 0xbf, 0x04, 0x41}, false},
		{"scale one", address, []byte{0x0f, 0xb7, 0x04, 0x01}, false},
		{"scale four", address, []byte{0x0f, 0xb7, 0x04, 0x81}, false},
		{"missing index", address, []byte{0x0f, 0xb7, 0x01}, false},
		{"nonzero displacement", address, []byte{0x0f, 0xb7, 0x44, 0x41, 0x02}, false},
		{"intervening instruction", address, []byte{0x90, 0x0f, 0xb7, 0x04, 0x41}, false},
		{"missing lookup", address, nil, false},
		{"32-bit address", []byte{0x8d, 0x0d, 0, 0, 0, 0}, []byte{0x0f, 0xb7, 0x04, 0x41}, false},
		{"indirect address", []byte{0x48, 0x8d, 0x0b}, []byte{0x0f, 0xb7, 0x04, 0x41}, false},
		{"load instead of address", []byte{0x48, 0x8b, 0x0d, 0, 0, 0, 0}, []byte{0x0f, 0xb7, 0x04, 0x41}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := append(append([]byte(nil), tc.address...), tc.lookup...)
			instructions, err := decodeRuntimeMetricX86Instructions(code)
			require.NoError(t, err)
			require.Equal(t, tc.want, isRuntimeMetricSizeClassTableLoad(instructions, 0))
			require.False(t, isRuntimeMetricSizeClassTableLoad(instructions, -1))
			require.False(t, isRuntimeMetricSizeClassTableLoad(instructions, len(instructions)))
		})
	}
	require.False(t, isRuntimeMetricSizeClassTableLoad(nil, 0))
}

func TestRuntimeMetricSizeClassTableCandidates(t *testing.T) {
	for _, tc := range []struct {
		name         string
		functionAddr uint64
		displacement int32
		references   int
		want         []uint64
	}{
		{"observed address", 0x417faa, 0x10c82f, 1, []uint64{0x5247e0}},
		{"backward reference", 0x1000, -0x807, 1, []uint64{0x800}},
		{"repeated reference", 0x1000, 0x1ff9, 2, []uint64{0x3000, 0x3000}},
		{"zero address", 0x1000, -0x1007, 1, nil},
		{"negative address", 0x1000, -0x1008, 1, nil},
		{"instruction overflow", math.MaxUint64 - 3, 0, 1, nil},
		{"target overflow", math.MaxUint64 - 8, 2, 1, nil},
		{"no instructions", 0x1000, 0, 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var code []byte
			for range tc.references {
				start := len(code)
				code = append(code, 0x48, 0x8d, 0x0d, 0, 0, 0, 0, 0x0f, 0xb7, 0x04, 0x41)
				// Adjust each displacement so repeated references reach the same address.
				binary.LittleEndian.PutUint32(code[start+3:start+7], uint32(tc.displacement-int32(start)))
			}
			got, err := runtimeMetricSizeClassTableCandidates(tc.functionAddr, code)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	_, err := runtimeMetricSizeClassTableCandidates(0x1000, []byte{0x48, 0x8d})
	require.Error(t, err)
}

func TestResolveRuntimeMetricSizeClassTableFromCode(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses [][]uint64
		want      uint64
		wantError string
	}{
		{"mallocgc only", [][]uint64{{0x3000}}, 0x3000, ""},
		{"lockVerifyMSize only", [][]uint64{nil, {0x3000}}, 0x3000, ""},
		{"anchors agree", [][]uint64{{0x3000}, {0x3000}}, 0x3000, ""},
		{"anchors conflict", [][]uint64{{0x3000}, {0x3100}}, 0, "ambiguous runtime global address"},
		{"repeated references", [][]uint64{{0x3000, 0x3000}}, 0x3000, ""},
		{"conflicting references", [][]uint64{{0x3000, 0x3100}}, 0, "ambiguous runtime global address"},
		{"invalid table decoy", [][]uint64{{0x3002, 0x3000}}, 0x3000, ""},
		{"no valid table", [][]uint64{{0x3002}}, 0, "runtime global address not found"},
		{"missing anchors", nil, 0, "runtime global address not found"},
		{"zero bounds", [][]uint64{{0x3000}}, 0, "invalid runtime.mallocgc function bounds"},
		{"oversized function", [][]uint64{{0x3000}}, 0, "invalid runtime.mallocgc function bounds"},
		{"nonexecutable code", [][]uint64{{0x3000}}, 0, "virtual memory range is not file-backed"},
		{"truncated code", [][]uint64{{0x3000}}, 0, "virtual memory range is not file-backed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Two distinct tables with valid shapes let us exercise ambiguity.
			data := make([]byte, 0x200)
			for _, start := range []int{0, 0x100} {
				for index := range 68 {
					size := uint16(index * 8)
					if index == 67 {
						size = 32768
					}
					binary.LittleEndian.PutUint16(data[start+index*2:], size)
				}
			}
			f := &elf.File{
				FileHeader: elf.FileHeader{ByteOrder: binary.LittleEndian},
				Progs: []*elf.Prog{{
					ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R, Vaddr: 0x3000, Filesz: uint64(len(data))},
					ReaderAt:   bytes.NewReader(data),
				}},
			}
			table := &gosym.Table{}
			for anchor, addresses := range tc.addresses {
				if addresses == nil {
					continue
				}
				entry := uint64(0x1000 + anchor*0x100)
				var code []byte
				for _, address := range addresses {
					start := len(code)
					code = append(code, 0x48, 0x8d, 0x0d, 0, 0, 0, 0, 0x0f, 0xb7, 0x04, 0x41)
					binary.LittleEndian.PutUint32(code[start+3:start+7], uint32(address-entry-uint64(start+7)))
				}
				name := []string{"runtime.mallocgc", "runtime.lockVerifyMSize"}[anchor]
				function := gosym.Func{Entry: entry, End: entry + uint64(len(code)), Sym: &gosym.Sym{Name: name}}
				segment := &elf.Prog{
					ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X, Vaddr: entry, Filesz: uint64(len(code))},
					ReaderAt:   bytes.NewReader(code),
				}
				switch tc.name {
				case "zero bounds":
					function.End = entry
				case "oversized function":
					function.End = entry + maximumRuntimeFunctionSize + 1
				case "nonexecutable code":
					segment.Flags = elf.PF_R
				case "truncated code":
					segment.Filesz--
				}
				table.Funcs = append(table.Funcs, function)
				f.Progs = append(f.Progs, segment)
			}
			got, err := resolveRuntimeMetricSizeClassTableFromCode(f, table)
			if tc.wantError == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, tc.wantError)
			}
			require.Equal(t, tc.want, got)
		})
	}
}

func TestResolveRuntimeMetricReceiverFromCode(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []uint64
		want      uint64
		wantError string
	}{
		{"single", []uint64{0x3000}, 0x3000, ""},
		{"backward receiver", []uint64{0x800}, 0x800, ""},
		{"repeated", []uint64{0x3000, 0x3000}, 0x3000, ""},
		{"conflicting", []uint64{0x3000, 0x4000}, 0, "ambiguous runtime global address"},
		{"zero address", []uint64{0}, 0, "runtime global address not found"},
		{"missing", nil, 0, "runtime global address not found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const functionAddress = uint64(0x1000)
			var code []byte
			for _, address := range tc.addresses {
				// LEA RAX,[RIP+disp]; CALL the method at 0x2000.
				start := len(code)
				code = append(code, 0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0)
				binary.LittleEndian.PutUint32(code[start+3:start+7], uint32(int64(address)-int64(functionAddress)-int64(start+7)))
				binary.LittleEndian.PutUint32(code[start+8:start+12], uint32(0x2000-functionAddress-uint64(start+12)))
			}
			got, err := resolveRuntimeMetricReceiverFromCode(functionAddress, code, 0x2000)
			if tc.wantError != "" {
				require.EqualError(t, err, tc.wantError)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.want, got)
		})
	}
}

func TestResolveRuntimeMetricReceiverFromMultipleMethods(t *testing.T) {
	for _, tc := range []struct {
		name      string
		receivers []uint64
		methods   []uint64
		wantError string
	}{
		{"first method", []uint64{0x3000}, []uint64{0x2000, 0x2100}, ""},
		{"second method", []uint64{0x3000}, []uint64{0x2100, 0x2000}, ""},
		{"both agree", []uint64{0x3000, 0x3000}, []uint64{0x2000, 0x2100}, ""},
		{"both disagree", []uint64{0x3000, 0x4000}, []uint64{0x2000, 0x2100}, "ambiguous runtime global address"},
		{"no methods", []uint64{0x3000}, nil, "runtime global address not found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const functionAddress = uint64(0x1000)
			var code []byte
			for i, receiver := range tc.receivers {
				// Each LEA/CALL pair targets a different method with its own receiver.
				start := len(code)
				code = append(code, 0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xe8, 0, 0, 0, 0)
				binary.LittleEndian.PutUint32(code[start+3:start+7], uint32(receiver-functionAddress-uint64(start+7)))
				method := uint64(0x2000 + i*0x100)
				binary.LittleEndian.PutUint32(code[start+8:start+12], uint32(method-functionAddress-uint64(start+12)))
			}
			got, err := resolveRuntimeMetricReceiverFromCode(functionAddress, code, tc.methods...)
			if tc.wantError != "" {
				require.EqualError(t, err, tc.wantError)
				require.Zero(t, got)
			} else {
				require.NoError(t, err)
				require.Equal(t, uint64(0x3000), got)
			}
		})
	}
}

func TestRuntimeMetricCallTarget(t *testing.T) {
	for _, tc := range []struct {
		name         string
		base         uint64
		displacement x86asm.Rel
		want         uint64
		ok           bool
	}{
		{"backward call", 0x1000, -0x105, 0xf00, true},
		{"displacement underflow", 0, -6, 0, false},
		{"instruction end overflow", math.MaxUint64 - 3, 0, 0, false},
		{"displacement overflow", math.MaxUint64 - 5, 1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			instruction := runtimeMetricX86Instruction{inst: x86asm.Inst{Op: x86asm.CALL, Len: 5, Args: x86asm.Args{tc.displacement}}}
			got, ok := runtimeMetricCallTarget(tc.base, instruction)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestRuntimeMetricReceiverCall(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  []byte
		target uint64
		want   bool
	}{
		{"receiver in RAX", []byte{0x48, 0x8d, 0x05, 0, 0, 0, 0}, 0x2000, true},
		{"NOP padding", []byte{0x48, 0x8d, 0x05, 0, 0, 0, 0, 0x90}, 0x2000, true},
		{"wrong method", []byte{0x48, 0x8d, 0x05, 0, 0, 0, 0}, 0x3000, false},
		{"receiver in RCX", []byte{0x48, 0x8d, 0x0d, 0, 0, 0, 0}, 0x2000, false},
		{"receiver overwritten", []byte{0x48, 0x8d, 0x05, 0, 0, 0, 0, 0x31, 0xc0}, 0x2000, false},
		{"MOV reads contents instead of address", []byte{0x48, 0x8b, 0x05, 0, 0, 0, 0}, 0x2000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const functionAddress = 0x1000
			code := append(append([]byte(nil), tc.setup...), 0xe8, 0, 0, 0, 0)
			// CALL stores the distance from its end to the called method.
			binary.LittleEndian.PutUint32(code[len(code)-4:], uint32(tc.target-(functionAddress+uint64(len(code)))))
			instructions, err := decodeRuntimeMetricX86Instructions(code)
			require.NoError(t, err)
			require.Equal(t, tc.want, isRuntimeMetricReceiverCall(instructions, 0, functionAddress, 0x2000))
		})
	}
}

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
