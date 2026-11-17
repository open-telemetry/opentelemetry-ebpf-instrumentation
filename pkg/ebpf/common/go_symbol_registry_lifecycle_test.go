// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpfcommon

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

type lifecycleSymbolResolver struct {
	closed   atomic.Int32
	released atomic.Int32
	entered  chan struct{}
	proceed  chan struct{}
}

func (r *lifecycleSymbolResolver) PCToFrame(uint64) (goexec.GoFrame, bool) {
	if r.entered != nil {
		close(r.entered)
		<-r.proceed
	}
	return goexec.GoFrame{File: "handler.go", Line: 42, Function: "main.handler"}, true
}

func (*lifecycleSymbolResolver) ValueType(uint64) (goexec.GoValueType, bool) {
	return goexec.GoValueType{}, false
}

func (*lifecycleSymbolResolver) ReadOnlyData(uint64, uint64) ([]byte, bool) {
	return nil, false
}

func (r *lifecycleSymbolResolver) SetDontNeed() { r.released.Add(1) }

func (r *lifecycleSymbolResolver) Close() error { r.closed.Add(1); return nil }

func TestGoSymbolsLazyOpenSharedAcrossReplicas(t *testing.T) {
	r := NewGoSymbolRegistry()
	defer r.Close()
	info := testGoExecutableInfo(t)
	_, fn := testGoSymbolTable(t)
	for pid := app.PID(1); pid <= 10; pid++ {
		require.NoError(t, r.AddExecutable(info))
		r.BindPID(pid, info.Dev(), info.Ino(), 0)
		_, err := stackText(r, pid, nil)
		require.NoError(t, err)
		_, err = stackText(r, pid, []uint64{0})
		require.NoError(t, err)
	}
	entry := r.executables[goExecutableID{device: info.Dev(), inode: info.Ino()}]
	file := entry.file
	require.Nil(t, entry.resolver)
	var workers sync.WaitGroup
	for pid := app.PID(1); pid <= 10; pid++ {
		workers.Go(func() {
			stack, err := stackText(r, pid, []uint64{fn.Entry + 1})
			if err != nil || !strings.Contains(stack, "goSymbolRegistryFixture") {
				t.Errorf("stack=%q error=%v", stack, err)
			}
		})
	}
	workers.Wait()
	require.NotNil(t, entry.resolver)
	for pid := app.PID(1); pid <= 10; pid++ {
		r.RemovePID(pid)
	}
	_, err := file.Stat()
	require.NoError(t, err)
	r.RemoveExecutable(info.Dev(), info.Ino())
	_, err = file.Stat()
	require.ErrorIs(t, err, os.ErrClosed)
	require.Nil(t, entry.resolver)
	require.NoError(t, r.Close())
}

func TestGoSymbolsReleasePagesAfterPanicFrames(t *testing.T) {
	for _, pcs := range [][]uint64{nil, {2}} {
		t.Run(fmt.Sprint(pcs), func(t *testing.T) {
			r := NewGoSymbolRegistry()
			defer r.Close()
			resolver := &lifecycleSymbolResolver{}
			registerGoSymbols(t, r, 1, resolver)
			r.PanicValueType(1, 2)
			require.Zero(t, resolver.released.Load(), "type lookup retains pages for frame lookup")
			_, err := r.Frames(1, pcs)
			require.NoError(t, err)
			require.EqualValues(t, 1, resolver.released.Load())
		})
	}
}

func TestGoSymbolsRemovalWaitsForActiveLookup(t *testing.T) {
	r := NewGoSymbolRegistry()
	defer r.Close()
	resolver := &lifecycleSymbolResolver{entered: make(chan struct{}), proceed: make(chan struct{})}
	registerGoSymbols(t, r, 1, resolver)
	entry := r.executables[goExecutableID{device: 7, inode: 11}]
	file, err := os.CreateTemp(t.TempDir(), "executable")
	require.NoError(t, err)
	entry.file = file
	lookup := make(chan error, 1)
	go func() { _, err := stackText(r, 1, []uint64{2}); lookup <- err }()
	select {
	case <-resolver.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("lookup did not enter resolver")
	}
	removed := make(chan struct{})
	go func() { r.RemoveExecutable(7, 11); close(removed) }()
	require.Zero(t, resolver.closed.Load())
	close(resolver.proceed)
	require.NoError(t, <-lookup)
	select {
	case <-removed:
	case <-time.After(5 * time.Second):
		t.Fatal("removal did not finish")
	}
	_, err = file.Stat()
	require.ErrorIs(t, err, os.ErrClosed)
	require.EqualValues(t, 1, resolver.closed.Load())
	require.EqualValues(t, 1, resolver.released.Load())
}

func TestGoSymbolsFailedLazyOpenBacksOffAndRetries(t *testing.T) {
	r := NewGoSymbolRegistry()
	defer r.Close()
	file, err := os.CreateTemp(t.TempDir(), "executable")
	require.NoError(t, err)
	defer file.Close()
	info := testGoFileInfo(t, file.Name())
	require.NoError(t, r.AddExecutable(info))
	r.BindPID(1, info.Dev(), info.Ino(), 0)
	_, fn := testGoSymbolTable(t)
	_, failure := stackText(r, 1, []uint64{fn.Entry + 1})
	require.Error(t, failure)

	// Repair the same inode while the failed load is still backed off.
	source, err := os.Open(testGoExecutableInfo(t).ProExeLinkPath())
	require.NoError(t, err)
	defer source.Close()
	_, err = io.Copy(file, source)
	require.NoError(t, err)
	_, err = stackText(r, 1, []uint64{fn.Entry + 1})
	require.ErrorIs(t, err, failure)

	r.executables[goExecutableID{device: info.Dev(), inode: info.Ino()}].retryAfter = time.Time{}
	stack, err := stackText(r, 1, []uint64{fn.Entry + 1})
	require.NoError(t, err)
	require.Contains(t, stack, "goSymbolRegistryFixture")
}

func TestGoSymbolsCloseUnusedFile(t *testing.T) {
	r := NewGoSymbolRegistry()
	info := testGoExecutableInfo(t)
	require.NoError(t, r.AddExecutable(info))
	entry := r.executables[goExecutableID{device: info.Dev(), inode: info.Ino()}]
	file := entry.file
	require.Nil(t, entry.resolver)
	require.NoError(t, r.Close())
	require.NoError(t, r.Close())
	_, err := file.Stat()
	require.ErrorIs(t, err, os.ErrClosed)
}

// registerGoSymbols injects a resolver for tests of frame lookup and PID bindings.
func registerGoSymbols(t *testing.T, r *GoSymbolRegistry, pid app.PID, resolver GoSymbolResolver) {
	t.Helper()
	key := goExecutableID{device: 7, inode: 11}
	if r.executables[key] == nil {
		r.executables[key] = &goSymbolTableEntry{resolver: resolver}
		t.Cleanup(func() { require.NoError(t, r.Close()) })
	}
	r.BindPID(pid, 7, 11, 0)
}

// stackText renders resolved frames one "function\n\tfile:line" pair per frame.
func stackText(r *GoSymbolRegistry, pid app.PID, pcs []uint64) (string, error) {
	frames, err := r.Frames(pid, pcs)
	lines := make([]string, 0, len(frames))
	for _, frame := range frames {
		lines = append(lines, fmt.Sprintf("%s\n\t%s:%d", frame.Function, frame.File, frame.Line))
	}
	return strings.Join(lines, "\n"), err
}
