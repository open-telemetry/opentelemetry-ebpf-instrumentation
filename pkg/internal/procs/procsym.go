// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import "debug/elf"

type Sym struct {
	Name string
	Off  uint64
	// Value is the raw ELF virtual address; Off may be a translated file offset.
	Value uint64
	Len   uint64
	Prog  *elf.Prog
	// ColdParts are the <Name>.cold and <Name>.cold.<N> parts that GCC splits
	// out of a function. They can hold some or all of its returns.
	ColdParts []Sym
}
