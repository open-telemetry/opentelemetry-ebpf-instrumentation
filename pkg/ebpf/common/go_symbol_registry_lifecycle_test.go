// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"errors"
	"fmt"
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

func (r *lifecycleSymbolResolver) SetDontNeed() { r.released.Add(1) }

func (r *lifecycleSymbolResolver) Close() error { r.closed.Add(1); return nil }

func TestGoSymbolsLazyOpenSharedAcrossReplicas(t *testing.T) {
	r := NewGoSymbolRegistry()
	defer r.Close()
	var sources, opens, closes atomic.Int32
	resolver := &lifecycleSymbolResolver{}
	source := func() (GoSymbolSource, error) {
		sources.Add(1)
		return GoSymbolSource{
			Open:  func() (GoSymbolResolver, error) { opens.Add(1); return resolver, nil },
			Close: func() error { closes.Add(1); return nil },
		}, nil
	}
	for pid := app.PID(1); pid <= 10; pid++ {
		registerGoSymbols(t, r, pid, source)
		_, err := stackText(r, pid, nil)
		require.NoError(t, err)
		_, err = stackText(r, pid, []uint64{0})
		require.NoError(t, err)
	}
	require.EqualValues(t, 1, sources.Load())
	require.Zero(t, opens.Load())
	var workers sync.WaitGroup
	for pid := app.PID(1); pid <= 10; pid++ {
		workers.Go(func() {
			stack, err := stackText(r, pid, []uint64{2})
			if err != nil || stack != "main.handler\n\thandler.go:42" {
				t.Errorf("stack=%q error=%v", stack, err)
			}
		})
	}
	workers.Wait()
	require.EqualValues(t, 1, opens.Load())
	require.EqualValues(t, 10, resolver.released.Load(), "every resolved stack releases the mapped pages")
	for pid := app.PID(1); pid <= 10; pid++ {
		r.RemovePID(pid)
	}
	require.Zero(t, closes.Load())
	r.RemoveExecutable(7, 11)
	require.EqualValues(t, 1, closes.Load())
	require.EqualValues(t, 1, resolver.closed.Load())
	require.NoError(t, r.Close())
	require.EqualValues(t, 1, closes.Load())
}

func TestGoSymbolsRemovalWaitsForActiveLookup(t *testing.T) {
	r := NewGoSymbolRegistry()
	resolver := &lifecycleSymbolResolver{entered: make(chan struct{}), proceed: make(chan struct{})}
	var closed atomic.Bool
	registerGoSymbols(t, r, 1, func() (GoSymbolSource, error) {
		return GoSymbolSource{Open: func() (GoSymbolResolver, error) { return resolver, nil }, Close: func() error { closed.Store(true); return nil }}, nil
	})
	lookup := make(chan error, 1)
	go func() { _, err := stackText(r, 1, []uint64{2}); lookup <- err }()
	select {
	case <-resolver.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("lookup did not enter resolver")
	}
	removed := make(chan struct{})
	go func() { r.RemoveExecutable(7, 11); close(removed) }()
	require.False(t, closed.Load())
	close(resolver.proceed)
	require.NoError(t, <-lookup)
	select {
	case <-removed:
	case <-time.After(5 * time.Second):
		t.Fatal("removal did not finish")
	}
	require.True(t, closed.Load())
	require.EqualValues(t, 1, resolver.closed.Load())
}

func TestGoSymbolsFailedLazyOpenBacksOffAndRetries(t *testing.T) {
	r := NewGoSymbolRegistry()
	defer r.Close()
	var opens int
	failure := errors.New("temporary mapping failure")
	resolver := &lifecycleSymbolResolver{}
	registerGoSymbols(t, r, 1, func() (GoSymbolSource, error) {
		return GoSymbolSource{Open: func() (GoSymbolResolver, error) {
			opens++
			if opens == 1 {
				return nil, failure
			}
			return resolver, nil
		}, Close: func() error { return nil }}, nil
	})
	for range 10 {
		_, err := stackText(r, 1, []uint64{2})
		require.ErrorIs(t, err, failure)
	}
	require.Equal(t, 1, opens)
	r.executables[goExecutableID{device: 7, inode: 11}].retryAfter = time.Time{}
	stack, err := stackText(r, 1, []uint64{2})
	require.NoError(t, err)
	require.NotEmpty(t, stack)
	require.Equal(t, 2, opens)
}

func TestGoSymbolsCloseUnusedSource(t *testing.T) {
	r := NewGoSymbolRegistry()
	closed := 0
	registerGoSymbols(t, r, 1, func() (GoSymbolSource, error) {
		return GoSymbolSource{Open: func() (GoSymbolResolver, error) { t.Error("unused source opened"); return nil, nil }, Close: func() error { closed++; return nil }}, nil
	})
	require.NoError(t, r.Close())
	require.NoError(t, r.Close())
	require.Equal(t, 1, closed)
}

// registerGoSymbols registers pid as a process of the test executable (7, 11).
func registerGoSymbols(t *testing.T, r *GoSymbolRegistry, pid app.PID, openSource func() (GoSymbolSource, error)) {
	t.Helper()
	require.NoError(t, r.AddExecutable(7, 11, openSource))
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
