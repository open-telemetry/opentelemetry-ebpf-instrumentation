// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"fmt"

	"golang.org/x/arch/x86/x86asm"
)

const endbrSize = 4

func isENDBRXX(data []uint8) bool {
	if len(data) < endbrSize {
		return false
	}

	return data[0] == 0xF3 &&
		data[1] == 0x0F &&
		data[2] == 0x1E &&
		(data[3] == 0xFA || data[3] == 0xFB)
}

func FindReturnOffsets(baseOffset uint64, data []byte) ([]uint64, error) {
	var returnOffsets []uint64
	index := 0
	for index < len(data) {
		// FIXME remove this once x86asm is able to recognize and decode
		// ENDBR64
		if isENDBRXX(data[index:]) {
			index += endbrSize
			continue
		}

		instruction, err := x86asm.Decode(data[index:], 64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode x64 instruction at offset %d: %w", index, err)
		}

		if instruction.Op == x86asm.RET {
			returnOffsets = append(returnOffsets, baseOffset+uint64(index))
		}

		index += instruction.Len
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
	instructions := make([]decoded, 0, len(data)/4)
	for index := 0; index < len(data); {
		if isENDBRXX(data[index:]) {
			index += endbrSize
			continue
		}
		instruction, err := x86asm.Decode(data[index:], 64)
		if err != nil {
			return 0, fmt.Errorf("failed to decode x64 instruction at offset %d: %w", index, err)
		}
		indirectCall := false
		if instruction.Op == x86asm.CALL {
			_, direct := instruction.Args[0].(x86asm.Rel)
			indirectCall = !direct
		}
		target := -1
		if relative, ok := instruction.Args[0].(x86asm.Rel); ok && instruction.Op != x86asm.CALL {
			target = index + instruction.Len + int(relative)
		}
		instructions = append(instructions, decoded{
			index:  index,
			line:   lineAt(entryPC + uint64(index)),
			call:   indirectCall,
			target: target,
		})
		index += instruction.Len
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
	type decoded struct {
		index int
		inst  x86asm.Inst
	}
	instructions := make([]decoded, 0, len(data)/4)
	for index := 0; index < len(data); {
		if isENDBRXX(data[index:]) {
			index += endbrSize
			continue
		}
		instruction, err := x86asm.Decode(data[index:], 64)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to decode x64 instruction at offset %d: %w", index, err)
		}
		instructions = append(instructions, decoded{index: index, inst: instruction})
		index += instruction.Len
	}
	for index := 0; index+2 < len(instructions); index++ {
		load := instructions[index].inst
		if load.Op != x86asm.MOVZX || load.MemBytes != 1 {
			continue
		}
		destination, dstOK := load.Args[0].(x86asm.Reg)
		memory, memOK := load.Args[1].(x86asm.Mem)
		if !dstOK || !memOK || memory.Base != x86asm.RSP || memory.Disp <= 0 || memory.Disp >= 512 {
			continue
		}
		next := index + 1
		for next < len(instructions) && instructions[next].inst.Op == x86asm.NOP {
			next++
		}
		if next+1 >= len(instructions) || instructions[next].inst.Op != x86asm.TEST {
			continue
		}
		testA, aOK := instructions[next].inst.Args[0].(x86asm.Reg)
		testB, bOK := instructions[next].inst.Args[1].(x86asm.Reg)
		branch := instructions[next+1].inst.Op
		if aOK && bOK && testA == testB && sameX86Register(testA, destination) &&
			branch == x86asm.JE {
			return baseOffset + uint64(instructions[index].index), uint64(memory.Disp), nil
		}
	}
	return 0, 0, nil
}

func sameX86Register(left, right x86asm.Reg) bool {
	leftNumber, leftOK := x86RegisterNumber(left)
	rightNumber, rightOK := x86RegisterNumber(right)
	return leftOK && rightOK && leftNumber == rightNumber
}

func x86RegisterNumber(register x86asm.Reg) (int, bool) {
	switch {
	case register >= x86asm.AL && register <= x86asm.BL:
		return int(register - x86asm.AL), true
	case register >= x86asm.SPB && register <= x86asm.R15B:
		return int(register-x86asm.SPB) + 4, true
	case register >= x86asm.AX && register <= x86asm.R15W:
		return int(register - x86asm.AX), true
	case register >= x86asm.EAX && register <= x86asm.R15L:
		return int(register - x86asm.EAX), true
	case register >= x86asm.RAX && register <= x86asm.R15:
		return int(register - x86asm.RAX), true
	default:
		return 0, false
	}
}
