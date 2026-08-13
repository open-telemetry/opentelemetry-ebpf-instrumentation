// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"encoding/binary"

	"golang.org/x/arch/arm64/arm64asm"
)

const (
	armInstructionSize = 4
)

func FindReturnOffsets(baseOffset uint64, data []byte) ([]uint64, error) {
	var returnOffsets []uint64
	index := 0
	for index < len(data) {
		instruction, err := arm64asm.Decode(data[index:])
		if err == nil && instruction.Op == arm64asm.RET {
			returnOffsets = append(returnOffsets, baseOffset+uint64(index))
		}

		// arm64 instructions are fixed 4 bytes; advance unconditionally even on
		// decode errors so that truncated or unrecognized words are skipped cleanly.
		index += armInstructionSize
	}

	return returnOffsets, nil
}

func FindWriteStartOffset(
	baseOffset uint64,
	entryPC uint64,
	data []byte,
	lineAt func(uint64) int,
) (uint64, error) {
	type decoded struct {
		index  int
		line   int
		call   bool
		target int
	}
	instructions := make([]decoded, 0, len(data)/armInstructionSize)
	for index := 0; index+armInstructionSize <= len(data); index += armInstructionSize {
		instruction, err := arm64asm.Decode(data[index:])
		target := -1
		if err == nil && instruction.Op != arm64asm.BL {
			for _, arg := range instruction.Args {
				if relative, ok := arg.(arm64asm.PCRel); ok {
					target = index + int(relative)
					break
				}
			}
		}
		instructions = append(instructions, decoded{
			index:  index,
			line:   lineAt(entryPC + uint64(index)),
			call:   err == nil && instruction.Op == arm64asm.BLR,
			target: target,
		})
	}
	for call := len(instructions) - 1; call >= 0; call-- {
		if !instructions[call].call || instructions[call].line == 0 {
			continue
		}
		start := call
		for start > 0 && instructions[start-1].line == instructions[call].line {
			start--
		}
		for _, instruction := range instructions[:call] {
			if instruction.target >= instructions[start].index &&
				instruction.target <= instructions[call].index {
				for start < call && instructions[start].index < instruction.target {
					start++
				}
			}
		}
		return baseOffset + uint64(instructions[start].index), nil
	}
	return 0, nil
}

func FindPadStartOffset(baseOffset uint64, data []byte) (uint64, uint64, error) {
	const (
		loadByteImmediateMask = 0xffc00000
		loadByteImmediate     = 0x39400000
		stackPointerRegister  = 31
	)
	for index := 0; index+3*armInstructionSize <= len(data); index += armInstructionSize {
		word := binary.LittleEndian.Uint32(data[index:])
		if word&loadByteImmediateMask != loadByteImmediate || (word>>5)&0x1f != stackPointerRegister {
			continue
		}
		offset := uint64((word >> 10) & 0xfff)
		if offset == 0 || offset >= 512 {
			continue
		}
		loadRegister := word & 0x1f
		move, moveErr := arm64asm.Decode(data[index+armInstructionSize:])
		branch, branchErr := arm64asm.Decode(data[index+2*armInstructionSize:])
		if moveErr != nil || branchErr != nil || move.Op != arm64asm.MOV || branch.Op != arm64asm.CBZ {
			continue
		}
		moveDestination, dstOK := move.Args[0].(arm64asm.Reg)
		moveSource, srcOK := move.Args[1].(arm64asm.Reg)
		branchRegister, branchOK := branch.Args[0].(arm64asm.Reg)
		destinationNumber := srcOKReg(moveDestination)
		if dstOK && srcOK && branchOK && uint32(srcOKReg(moveSource)) == loadRegister &&
			destinationNumber != 0xff && destinationNumber == srcOKReg(branchRegister) {
			return baseOffset + uint64(index), offset, nil
		}
	}
	return 0, 0, nil
}

func srcOKReg(register arm64asm.Reg) uint8 {
	if register >= arm64asm.W0 && register <= arm64asm.W30 {
		return uint8(register - arm64asm.W0)
	}
	if register >= arm64asm.X0 && register <= arm64asm.X30 {
		return uint8(register - arm64asm.X0)
	}
	return 0xff
}
