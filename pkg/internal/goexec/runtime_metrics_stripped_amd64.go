// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"debug/elf"
	"fmt"

	"golang.org/x/arch/x86/x86asm"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type runtimeMetricX86Instruction struct {
	offsetInFunction int
	inst             x86asm.Inst
}

// resolveGOMAXPROCSFromCode follows procresize's processor-count validation from
// machine code to the global's ELF address. Each matching RIP-relative load must
// point to aligned, writable int32 storage, and all matches must agree.
func resolveGOMAXPROCSFromCode(f *elf.File, functionELFAddress uint64, code []byte) (uint64, error) {
	instructions, err := decodeRuntimeMetricX86Instructions(code)
	if err != nil {
		return 0, err
	}

	// Find the load used by procresize's check of the previous processor count.
	const gomaxprocsSize = 4 // The runtime declares gomaxprocs as int32.
	var candidates []uint64
	for index, instruction := range instructions {
		if !isGOMAXPROCSLoadSequence(instructions, index) {
			continue
		}
		globalELFAddress, ok := runtimeMetricRIPTarget(functionELFAddress, instruction)
		if !ok || globalELFAddress == 0 || globalELFAddress%gomaxprocsSize != 0 {
			continue
		}
		// A plausible instruction match must also point to four bytes of writable
		// global storage. This checks the address, not the variable's current value.
		if !runtimeMetricWritableRange(f, globalELFAddress, gomaxprocsSize) {
			continue
		}
		candidates = append(candidates, globalELFAddress)
	}
	return uniqueRuntimeMetricAddress(candidates)
}

// resolveRuntimeMetricReceiverFromCode finds the address passed to a method.
// For memstats.heapStats.acquire(), the LEA supplies &memstats.heapStats;
// subtracting the field offset to recover memstats is the caller's responsibility.
func resolveRuntimeMetricReceiverFromCode(functionELFAddress uint64, code []byte, methodELFAddresses ...uint64) (uint64, error) {
	instructions, err := decodeRuntimeMetricX86Instructions(code)
	if err != nil {
		return 0, err
	}
	var candidates []uint64
	for index, instruction := range instructions {
		for _, methodELFAddress := range methodELFAddresses {
			if !isRuntimeMetricReceiverCall(instructions, index, functionELFAddress, methodELFAddress) {
				continue
			}
			address, ok := runtimeMetricRIPTarget(functionELFAddress, instruction)
			if !ok || address == 0 {
				continue
			}
			candidates = append(candidates, address)
			break
		}
	}
	return uniqueRuntimeMetricAddress(candidates)
}

// decodeRuntimeMetricX86Instructions turns file bytes into instructions.
func decodeRuntimeMetricX86Instructions(code []byte) ([]runtimeMetricX86Instruction, error) {
	var instructions []runtimeMetricX86Instruction
	err := walkX86Instructions(code, func(offset int, inst x86asm.Inst) {
		instructions = append(instructions, runtimeMetricX86Instruction{offsetInFunction: offset, inst: inst})
	})
	if err != nil {
		return nil, err
	}
	for _, instruction := range instructions {
		// x86asm can report an incomplete instruction as Op == 0 without an error.
		if instruction.inst.Op == 0 {
			return nil, fmt.Errorf("invalid runtime instruction at offset %d", instruction.offsetInFunction)
		}
	}
	return instructions, nil
}

// isGOMAXPROCSLoadSequence recognizes procresize's check of the previous processor
// count. Before resizing the Go scheduler, procresize reads old := gomaxprocs and
// rejects old < 0. On amd64, that check has this shape:
// Source: https://go.dev/src/runtime/proc.go (runtime.procresize).
//
//	MOV  EDX, [RIP+displacement]  // read the int32 gomaxprocs global
//	TEST EDX, EDX                // set condition flags from the old count
//	JL   invalidArg              // branch if the old count is negative
func isGOMAXPROCSLoadSequence(instructions []runtimeMetricX86Instruction, index int) bool {
	if index < 0 || index > len(instructions)-3 {
		return false
	}

	// Require a 32-bit read from a global addressed relative to this instruction.
	load := instructions[index].inst
	register, registerOK := load.Args[0].(x86asm.Reg)
	memory, memoryOK := load.Args[1].(x86asm.Mem)
	if load.Op != x86asm.MOV || load.MemBytes != 4 || !registerOK || !memoryOK || memory.Base != x86asm.RIP {
		return false
	}

	test := instructions[index+1].inst
	branch := instructions[index+2].inst
	return test.Op == x86asm.TEST &&
		test.Args[0] == register && test.Args[1] == register &&
		branch.Op == x86asm.JL
}

// isRuntimeMetricReceiverCall recognizes method calls such as this in mcache.refill:
//
//	stats := memstats.heapStats.acquire()
//
//	LEA  RAX, [RIP + displacement] // Pass &memstats.heapStats as the receiver.
//	CALL acquire                  // Invoke consistentHeapStats.acquire.
//
// Go's amd64 register ABI passes the receiver in RAX.
func isRuntimeMetricReceiverCall(instructions []runtimeMetricX86Instruction, index int, functionELFAddress, methodELFAddress uint64) bool {
	if index < 0 || index >= len(instructions) {
		return false
	}
	load := instructions[index].inst
	memory, ok := load.Args[1].(x86asm.Mem)
	if load.Op != x86asm.LEA || load.Args[0] != x86asm.RAX || !ok || memory.Base != x86asm.RIP || memory.Index != 0 {
		return false
	}

	// Only padding may separate the receiver setup from the call.
	index++
	for index < len(instructions) && instructions[index].inst.Op == x86asm.NOP {
		index++
	}
	if index == len(instructions) {
		return false
	}
	target, ok := runtimeMetricCallTarget(functionELFAddress, instructions[index])
	return ok && target == methodELFAddress
}

// runtimeMetricCallTarget decodes the CALL part of a method call such as
// memstats.heapStats.acquire() in mcache.refill:
//
//	0x420486: e8 95 eb 01 00  CALL 0x43f020
//	          next instruction + stored displacement = destination
//	          0x42048b         + 0x1eb95             = 0x43f020
//
// Comparing the destination with acquire.Entry identifies the call to acquire.
func runtimeMetricCallTarget(functionELFAddress uint64, instruction runtimeMetricX86Instruction) (uint64, bool) {
	relative, ok := instruction.inst.Args[0].(x86asm.Rel)
	if instruction.inst.Op != x86asm.CALL || !ok || instruction.offsetInFunction < 0 || instruction.inst.Len <= 0 {
		return 0, false
	}
	instructionELFAddress, ok := procs.AddSignedOffset(functionELFAddress, int64(instruction.offsetInFunction))
	if !ok {
		return 0, false
	}
	// The displacement is relative to the address immediately after the CALL.
	nextInstructionELFAddress, ok := procs.AddSignedOffset(instructionELFAddress, int64(instruction.inst.Len))
	if !ok {
		return 0, false
	}
	return procs.AddSignedOffset(nextInstructionELFAddress, int64(relative))
}

// runtimeMetricRIPTarget calculates the ELF address read by a RIP-relative load:
// function address + instruction offset + instruction length + displacement.
func runtimeMetricRIPTarget(functionELFAddress uint64, instruction runtimeMetricX86Instruction) (uint64, bool) {
	memory, ok := instruction.inst.Args[1].(x86asm.Mem)
	if !ok || memory.Base != x86asm.RIP || instruction.offsetInFunction < 0 || instruction.inst.Len <= 0 {
		return 0, false
	}
	instructionELFAddress, ok := procs.AddSignedOffset(functionELFAddress, int64(instruction.offsetInFunction))
	if !ok {
		return 0, false
	}
	// RIP-relative operands use the address immediately after this instruction.
	nextInstructionELFAddress, ok := procs.AddSignedOffset(instructionELFAddress, int64(instruction.inst.Len))
	if !ok {
		return 0, false
	}
	// RIP-relative operands encode a signed 32-bit displacement. x86asm can
	// expose its raw bits as a positive int64, so sign-extend before adding it.
	return procs.AddSignedOffset(nextInstructionELFAddress, int64(int32(memory.Disp)))
}
