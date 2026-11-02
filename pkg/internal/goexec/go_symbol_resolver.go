// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
)

// GoFrame is one call frame of a symbolized Go stack.
type GoFrame struct {
	Function string
	File     string
	Line     int
}

// GoSymbolResolver symbolizes executable PCs with the ebpf-profiler reader of
// the Go PC table, which maps the executable read-only.
type GoSymbolResolver struct {
	mu    sync.RWMutex
	elf   *pfelf.File
	table *elfunwindinfo.Gopclntab
}

// NewGoSymbolResolver maps file until Close, but does not take ownership of it.
func NewGoSymbolResolver(file *os.File) (*GoSymbolResolver, error) {
	elfFile, err := pfelf.NewFile(file, 0, false)
	if err != nil {
		return nil, err
	}
	table, err := elfunwindinfo.NewGopclntab(elfFile)
	if err != nil {
		_ = elfFile.Close()
		return nil, err
	}
	return &GoSymbolResolver{elf: elfFile, table: table}, nil
}

// A retained executable mapping can fault after the process exits and its
// backing inode is truncated. Bounds and other programming panics still escape.
type goMappedMemoryFault interface {
	runtime.Error
	Addr() uintptr
}

// PCToFrame returns the frame of a call PC, or false when the PC is unknown or
// the executable was truncated.
func (r *GoSymbolResolver) PCToFrame(pc uint64) (frame GoFrame, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.table == nil {
		return GoFrame{}, false
	}

	previousPanicOnFault := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(previousPanicOnFault)
	defer func() {
		if value := recover(); value != nil {
			if _, ok := value.(goMappedMemoryFault); !ok {
				panic(value)
			}
			frame, ok = GoFrame{}, false
		}
	}()

	file, line, function := r.table.Symbolize(uintptr(pc))
	if function == "" || file == "" || line == 0 {
		return GoFrame{}, false
	}
	// Symbolize returns strings that alias the mapping, which Close unmaps.
	return GoFrame{Function: strings.Clone(function), File: strings.Clone(file), Line: int(line)}, true
}

// SetDontNeed drops the mapped pages from the process RSS. Later lookups fault
// back in only the pages they read.
func (r *GoSymbolResolver) SetDontNeed() {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.table != nil {
		_ = r.table.SetDontNeed()
	}
}

func (r *GoSymbolResolver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.table == nil {
		return nil
	}
	err := r.table.Close()
	if closeErr := r.elf.Close(); err == nil {
		err = closeErr
	}
	r.table = nil
	r.elf = nil
	return err
}
