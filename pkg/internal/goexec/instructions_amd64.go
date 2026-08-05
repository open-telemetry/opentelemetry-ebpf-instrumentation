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

// FindGoAutoSDKFlagLoadOffset locates the instruction that reads the
// process-global Auto SDK enable flag. Attaching at this interior instruction
// makes dynamic attachment exact: an invocation already past it necessarily
// read the old false value, while any invocation that can read a future true
// value must cross the admission probe.
func FindGoAutoSDKFlagLoadOffset(
	baseOffset uint64,
	data []byte,
) (uint64, error) {
	match := uint64(0)
	matches := 0
	for index := 0; index < len(data); {
		if isENDBRXX(data[index:]) {
			index += endbrSize
			continue
		}
		instruction, err := x86asm.Decode(data[index:], 64)
		if err != nil {
			return 0, fmt.Errorf(
				"decoding x64 Auto SDK newSpan at offset %d: %w",
				index,
				err,
			)
		}
		if instruction.Op == x86asm.CMP &&
			instruction.MemBytes == 1 &&
			goAutoSDKAMD64FlagMemoryArgument(instruction.Args) &&
			goAutoSDKAMD64ZeroImmediate(instruction.Args) &&
			goAutoSDKAMD64ConditionalBranch(
				data[index+instruction.Len:],
			) {
			match = baseOffset + uint64(index)
			matches++
		}
		index += instruction.Len
	}
	if matches != 1 {
		return 0, fmt.Errorf(
			"expected exactly one flag compare/branch through Go parameter 4 (RDI), found %d",
			matches,
		)
	}
	return match, nil
}

func goAutoSDKAMD64FlagMemoryArgument(args x86asm.Args) bool {
	for _, argument := range args {
		memory, ok := argument.(x86asm.Mem)
		if !ok {
			continue
		}
		return memory.Base == x86asm.RDI &&
			memory.Index == 0 &&
			memory.Disp == 0
	}
	return false
}

func goAutoSDKAMD64ZeroImmediate(args x86asm.Args) bool {
	for _, argument := range args {
		if immediate, ok := argument.(x86asm.Imm); ok {
			return immediate == 0
		}
	}
	return false
}

func goAutoSDKAMD64ConditionalBranch(data []byte) bool {
	skipped := 0
	for len(data) != 0 && skipped <= 16 {
		instruction, err := x86asm.Decode(data, 64)
		if err != nil {
			return false
		}
		if instruction.Op == x86asm.JE ||
			instruction.Op == x86asm.JNE {
			return true
		}
		if instruction.Op != x86asm.NOP {
			return false
		}
		data = data[instruction.Len:]
		skipped += instruction.Len
	}
	return false
}
