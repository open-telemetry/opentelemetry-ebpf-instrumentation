// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

type goExecutableID struct {
	device uint64
	inode  uint64
}

type goSymbolTableEntry struct {
	mu         sync.Mutex
	source     GoSymbolSource
	resolver   GoSymbolResolver
	loadError  error
	retryAfter time.Time
	closed     bool
}

// GoSymbolResolver resolves executable-relative PCs. Close releases its backing
// storage once the executable is no longer instrumented.
type GoSymbolResolver interface {
	PCToFrame(uint64) (goexec.GoFrame, bool)
	// SetDontNeed releases memory the resolver can reload on its next lookup.
	SetDontNeed()
	Close() error
}

// GoSymbolSource retains access to an executable across process exit or unlink.
// Open constructs the resolver on its first use; Close releases the source.
type GoSymbolSource struct {
	Open  func() (GoSymbolResolver, error)
	Close func() error
}

type goPIDSymbolBinding struct {
	executable goExecutableID
	loadBias   uint64
}

// GoSymbolRegistry shares lazy executable resolvers across processes while
// retaining each process's executable load bias.
type GoSymbolRegistry struct {
	mu          sync.RWMutex
	executables map[goExecutableID]*goSymbolTableEntry
	pids        map[app.PID]goPIDSymbolBinding
}

func NewGoSymbolRegistry() *GoSymbolRegistry {
	return &GoSymbolRegistry{
		executables: map[goExecutableID]*goSymbolTableEntry{},
		pids:        map[app.PID]goPIDSymbolBinding{},
	}
}

// AddExecutable shares one lazily opened symbol table among all processes of
// an executable. openSource is only called when the executable is new.
func (r *GoSymbolRegistry) AddExecutable(device, inode uint64, openSource func() (GoSymbolSource, error)) error {
	if r == nil {
		return errors.New("go symbol registry is nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.initMaps()
	key := goExecutableID{device: device, inode: inode}
	if _, ok := r.executables[key]; ok {
		return nil
	}

	source, err := openSource()
	if err != nil {
		return fmt.Errorf("opening Go symbol source: %w", err)
	}
	if source.Open == nil || source.Close == nil {
		if source.Close != nil {
			_ = source.Close()
		}
		return errors.New("go symbol source requires Open and Close")
	}
	r.executables[key] = &goSymbolTableEntry{source: source}
	return nil
}

// RemoveExecutable releases the executable's symbol table, waiting for any
// lookup that is still using it.
func (r *GoSymbolRegistry) RemoveExecutable(device, inode uint64) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	key := goExecutableID{device: device, inode: inode}
	if entry, ok := r.executables[key]; ok {
		entry.close()
		delete(r.executables, key)
	}
}

// BindPID maps a process to its executable and the address it is loaded at.
func (r *GoSymbolRegistry) BindPID(pid app.PID, device, inode, loadBias uint64) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.initMaps()
	r.pids[pid] = goPIDSymbolBinding{executable: goExecutableID{device: device, inode: inode}, loadBias: loadBias}
}

func (r *GoSymbolRegistry) RemovePID(pid app.PID) {
	if r == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.pids, pid)
}

// Frames resolves runtime return PCs for an exact host PID, innermost first.
// Resolution stops at the first zero or unknown PC and retains preceding frames.
func (r *GoSymbolRegistry) Frames(pid app.PID, pcs []uint64) ([]goexec.GoFrame, error) {
	if r == nil {
		return nil, errors.New("go symbol registry is nil")
	}

	r.mu.RLock()
	binding, ok := r.pids[pid]
	if !ok {
		r.mu.RUnlock()
		return nil, fmt.Errorf("go symbol binding not found for PID %d", pid)
	}
	entry, ok := r.executables[binding.executable]
	if !ok || entry == nil {
		r.mu.RUnlock()
		return nil, fmt.Errorf("go symbol table not found for PID %d", pid)
	}
	loadBias := binding.loadBias
	// Pin the entry while resolving so removal cannot close its file mapping.
	entry.mu.Lock()
	r.mu.RUnlock()
	defer entry.mu.Unlock()
	if len(pcs) == 0 || pcs[0] == 0 || pcs[0] <= loadBias {
		return nil, nil
	}
	if entry.resolver == nil {
		if entry.loadError != nil && time.Now().Before(entry.retryAfter) {
			return nil, entry.loadError
		}
		resolver, err := entry.source.Open()
		if err == nil && resolver == nil {
			err = errors.New("go symbol source returned a nil resolver")
		}
		if err != nil {
			if resolver != nil {
				_ = resolver.Close()
			}
			entry.loadError = err
			entry.retryAfter = time.Now().Add(time.Second)
			return nil, err
		}
		entry.resolver = resolver
		entry.loadError = nil
	}

	var stack []goexec.GoFrame
	// A return address follows its call, so the call's line is one byte back.
	callOffset := uint64(1)
	for _, runtimePC := range pcs {
		if runtimePC == 0 || runtimePC <= loadBias {
			break
		}

		frame, ok := entry.resolver.PCToFrame(runtimePC - loadBias - callOffset)
		if !ok {
			break
		}
		// The caller of runtime.sigpanic faulted at its PC instead of calling.
		callOffset = 1
		if frame.Function == "runtime.sigpanic" {
			callOffset = 0
		}
		// Skip error constructors captured as the innermost frames.
		if len(stack) == 0 && goErrorHelper(frame.Function) {
			continue
		}
		stack = append(stack, frame)
	}
	entry.resolver.SetDontNeed()
	return stack, nil
}

func (r *GoSymbolRegistry) initMaps() {
	if r.executables == nil {
		r.executables = map[goExecutableID]*goSymbolTableEntry{}
	}
	if r.pids == nil {
		r.pids = map[app.PID]goPIDSymbolBinding{}
	}
}

func (e *goSymbolTableEntry) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.closed = true
	if e.resolver != nil {
		_ = e.resolver.Close()
		e.resolver = nil
	}
	_ = e.source.Close()
}

// Close releases remaining executable sources when the event pipeline stops.
func (r *GoSymbolRegistry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, entry := range r.executables {
		entry.close()
	}
	clear(r.executables)
	clear(r.pids)
	return nil
}

func goErrorHelper(function string) bool {
	switch function {
	case "fmt.Errorf", "fmt.errorf", "errors.New", "runtime.gopanic":
		return true
	default:
		return false
	}
}
