// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/elf"
	"encoding/binary"
	"strings"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

func embeddedSDKActivationAlias(name string) string {
	const pkg = "go.opentelemetry.io/otel/trace."
	for _, receiver := range []string{"noopSpan", "nonRecordingSpan", "(*noopSpan)", "(*nonRecordingSpan)"} {
		suffix := pkg + receiver + ".TracerProvider"
		if prefix, ok := strings.CutSuffix(name, suffix); ok {
			return prefix + pkg + "noopSpan.tracerProvider"
		}
	}
	return ""
}

// OTel 1.35 inlines the private hook. Stop immediately before reading the flag,
// after its pointer has been loaded into the third Go argument register.
func embeddedSDKFlagReadOffset(machine elf.Machine, data []byte) uint64 {
	if machine == elf.EM_X86_64 {
		for index := 0; index < len(data); {
			load, err := x86asm.Decode(data[index:], 64)
			if err != nil {
				return 0
			}
			readAt := index + load.Len
			check, checkErr := x86asm.Decode(data[readAt:], 64)
			branch, branchErr := x86asm.Decode(data[min(readAt+check.Len, len(data)):], 64)
			memory, ok := load.Args[1].(x86asm.Mem)
			if load.Op == x86asm.MOV && load.Args[0] == x86asm.RCX && ok &&
				memory.Base == x86asm.RIP && memory.Index == 0 && memory.Segment == 0 &&
				checkErr == nil && check.Op == x86asm.CMP && check.MemBytes == 1 &&
				check.Args[0] == (x86asm.Mem{Base: x86asm.RCX}) && check.Args[1] == x86asm.Imm(0) &&
				branchErr == nil && branch.Op == x86asm.JE {
				return uint64(readAt)
			}
			index = readAt
		}
	}
	if machine == elf.EM_AARCH64 {
		const instructionSize = 4
		const flagRead = 0x39400042 // LDRB W2, [X2], without pointer adjustment.
		for index := 0; index+4*instructionSize <= len(data); index += instructionSize {
			page, pageErr := arm64asm.Decode(data[index:])
			load, loadErr := arm64asm.Decode(data[index+instructionSize:])
			branch, branchErr := arm64asm.Decode(data[index+3*instructionSize:])
			memory, ok := load.Args[1].(arm64asm.MemImmediate)
			bit, bitOK := branch.Args[1].(arm64asm.Imm)
			pageRegister, pageOK := page.Args[0].(arm64asm.Reg)
			if pageErr == nil && page.Op == arm64asm.ADRP && pageOK && loadErr == nil &&
				load.Op == arm64asm.LDR && load.Args[0] == arm64asm.X2 && ok &&
				memory.Mode == arm64asm.AddrOffset && memory.Base == arm64asm.RegSP(pageRegister) &&
				binary.LittleEndian.Uint32(data[index+2*instructionSize:]) == flagRead &&
				branchErr == nil && branch.Op == arm64asm.TBZ && branch.Args[0] == arm64asm.W2 && bitOK && bit.Imm == 0 {
				return uint64(index + 2*instructionSize)
			}
		}
	}
	return 0
}
