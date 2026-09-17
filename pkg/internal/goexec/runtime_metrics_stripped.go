// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"debug/elf"
	"errors"
)

// resolveRuntimeMetricSymbolsFromCode recovers runtime global addresses from Go
// machine code and applies the executable's load bias to obtain process addresses.
func resolveRuntimeMetricSymbolsFromCode(f *elf.File, loadBias uint64) (RuntimeMetricSymbols, error) {
	if f.Machine != elf.EM_X86_64 {
		return RuntimeMetricSymbols{}, errors.New("stripped Go runtime global address recovery requires amd64")
	}

	// Stripped binaries retain Go's function metadata after their ELF object
	// symbols are removed. It gives us the bounds of runtime functions whose
	// machine code still refers to the globals we need.
	table, err := findGoSymbolTable(f)
	if err != nil {
		return RuntimeMetricSymbols{}, err
	}

	// procresize is the anchor for gomaxprocs because it validates the current
	// processor count before changing the scheduler.
	procresize := table.LookupFunc("runtime.procresize")
	if procresize == nil {
		return RuntimeMetricSymbols{}, errors.New("runtime.procresize function not found")
	}
	const maximumRuntimeFunctionSize = 64 << 10
	if procresize.End <= procresize.Entry || procresize.End-procresize.Entry > maximumRuntimeFunctionSize {
		return RuntimeMetricSymbols{}, errors.New("invalid runtime.procresize function bounds")
	}

	code, err := readVirtualMemoryWithFlags(f, procresize.Entry, procresize.End-procresize.Entry, elf.PF_X)
	if err != nil {
		return RuntimeMetricSymbols{}, err
	}
	gomaxprocsELFAddress, err := resolveGOMAXPROCSFromCode(f, procresize.Entry, code)
	if err != nil {
		return RuntimeMetricSymbols{}, err
	}
	// A PIE executable can be loaded at a different address on each run. Apply
	// that process's adjustment once, after identifying the global in the file.
	if loadBias > ^uint64(0)-gomaxprocsELFAddress {
		return RuntimeMetricSymbols{}, errors.New("gomaxprocs process address overflows")
	}
	gomaxprocsProcessAddress := loadBias + gomaxprocsELFAddress
	return RuntimeMetricSymbols{GOMAXPROCSAddr: gomaxprocsProcessAddress}, errors.New("stripped Go runtime global address recovery is not implemented")
}

// runtimeMetricWritableRange checks that the whole global fits in a readable,
// writable load segment. It uses the segment's in-memory size so zero-initialized
// globals in BSS remain valid even when the ELF stores no bytes for them.
func runtimeMetricWritableRange(f *elf.File, address, size uint64) bool {
	if size == 0 || size > ^uint64(0)-address {
		return false
	}
	for _, prog := range f.Progs {
		const requiredFlags = elf.PF_R | elf.PF_W
		if prog.Type != elf.PT_LOAD || prog.Flags&requiredFlags != requiredFlags || address < prog.Vaddr {
			continue
		}
		if prog.Memsz > ^uint64(0)-prog.Vaddr {
			continue
		}
		// Subtract only after checking the lower bound; avoid adding range ends.
		offset := address - prog.Vaddr
		if offset < prog.Memsz && size <= prog.Memsz-offset {
			return true
		}
	}
	return false
}

// uniqueRuntimeMetricAddress accepts repeated references to one address, but
// rejects distinct candidates because instruction matching cannot choose between them.
func uniqueRuntimeMetricAddress(candidates []uint64) (uint64, error) {
	if len(candidates) == 0 {
		return 0, errors.New("runtime global address not found")
	}
	address := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidate != address {
			return 0, errors.New("ambiguous runtime global address")
		}
	}
	return address, nil
}
