// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"fmt"

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

// FindGoAutoSDKFlagLoadOffset locates the byte load through Go parameter 4
// (X3), which is the process-global Auto SDK enable flag pointer.
func FindGoAutoSDKFlagLoadOffset(
	baseOffset uint64,
	data []byte,
) (uint64, error) {
	match := uint64(0)
	matches := 0
	for index := 0; index+armInstructionSize <= len(data); index += armInstructionSize {
		instruction, err := arm64asm.Decode(data[index:])
		if err != nil {
			continue
		}
		if instruction.Op != arm64asm.LDRB {
			continue
		}
		memory, ok := instruction.Args[1].(arm64asm.MemImmediate)
		if !ok || arm64asm.Reg(memory.Base) != arm64asm.X3 ||
			memory.String() != "[X3]" {
			continue
		}
		nextIndex := index + armInstructionSize
		if nextIndex+armInstructionSize > len(data) {
			continue
		}
		branch, err := arm64asm.Decode(data[nextIndex:])
		if err != nil ||
			!goAutoSDKARM64FlagBranch(
				branch,
				instruction.Args[0],
			) {
			continue
		}
		match = baseOffset + uint64(index)
		matches++
	}
	if matches != 1 {
		return 0, fmt.Errorf(
			"expected exactly one flag load/branch through Go parameter 4 (X3), found %d",
			matches,
		)
	}
	return match, nil
}

func goAutoSDKARM64FlagBranch(
	branch arm64asm.Inst,
	flagRegister arm64asm.Arg,
) bool {
	if branch.Args[0] != flagRegister {
		return false
	}
	if branch.Op == arm64asm.CBZ ||
		branch.Op == arm64asm.CBNZ {
		return true
	}
	if branch.Op != arm64asm.TBZ &&
		branch.Op != arm64asm.TBNZ {
		return false
	}
	bit := branch.Args[1]
	return bit != nil &&
		(bit.String() == "#0" || bit.String() == "#0x0")
}
