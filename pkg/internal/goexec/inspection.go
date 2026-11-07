// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/dwarf"
	"debug/elf"
	"sync"

	"go.opentelemetry.io/obi/internal/goabi"
)

// inspection shares what one InspectOffsets call derives from an executable
// between its steps, so that DWARF is parsed, and the runtime ABI and
// moduledata are resolved, at most once. It must not outlive that call.
type inspection struct {
	elf *elf.File
	// loadDWARF is elf.File.DWARF; tests replace it to count the parses.
	loadDWARF func() (*dwarf.Data, error)

	dwarf      func() dwarfFacts
	runtimeABI func() (goabi.ABI, error)
	moduledata func() (runtimeModuledata, error)
}

// dwarfFacts holds what the runtime ABI and struct member lookups read from
// DWARF. Both read the same parse, which is then released instead of being
// kept in memory while the Go symbol table is built.
type dwarfFacts struct {
	err           error
	runtimeABI    goabi.ABI
	runtimeABIErr error
	fieldOffsets  FieldOffsets
	missingFields map[GoOffset]struct{}
}

// runtimeModuledata is the address of an executable's runtime.firstmoduledata
// and the start of its Go text.
type runtimeModuledata struct {
	addr uint64
	text uint64
}

func newInspection(ef *elf.File) *inspection {
	in := &inspection{elf: ef, loadDWARF: ef.DWARF}
	in.dwarf = sync.OnceValue(in.readDWARFFacts)
	in.runtimeABI = sync.OnceValues(in.loadRuntimeABI)
	in.moduledata = sync.OnceValues(in.findModuledata)
	return in
}

func (in *inspection) readDWARFFacts() dwarfFacts {
	data, err := in.loadDWARF()
	if err != nil {
		return dwarfFacts{err: err}
	}

	var facts dwarfFacts
	facts.fieldOffsets, facts.missingFields = structMemberOffsetsFromDwarf(data)
	if targetVersion, ok := runtimeABIVersion(in.elf); ok {
		facts.runtimeABI, facts.runtimeABIErr = goabi.Extract(data, targetVersion)
	}
	return facts
}

// loadRuntimeABI is loadGoRuntimeABI for the executable's own Go version,
// using the shared DWARF parse. Callers check runtimeABIVersion first.
func (in *inspection) loadRuntimeABI() (goabi.ABI, error) {
	targetVersion, _ := runtimeABIVersion(in.elf)
	return resolveGoRuntimeABI(
		func() (goabi.ABI, error) {
			facts := in.dwarf()
			if facts.err != nil {
				return goabi.ABI{}, facts.err
			}
			return facts.runtimeABI, facts.runtimeABIErr
		},
		func() (goabi.ABI, error) {
			return loadGeneratedGoRuntimeABI(targetVersion)
		},
	)
}
