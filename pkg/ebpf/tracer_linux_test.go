// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

type libUnlinkingTracer struct {
	Tracer
	mu       sync.Mutex
	unlinked []uint64
}

func (t *libUnlinkingTracer) UnlinkInstrumentedLib(id uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.unlinked = append(t.unlinked, id)
}

func TestCloseInstrumentersReleasesEveryExecutableOnce(t *testing.T) {
	shared := &instrumenter{
		closables: []io.Closer{&countingCloser{}, &countingCloser{}},
		modules:   map[uint64]struct{}{7: {}},
	}
	single := &instrumenter{
		closables: []io.Closer{&countingCloser{}},
	}
	tracer := &libUnlinkingTracer{}
	pt := &ProcessTracer{
		log:      slog.Default(),
		Programs: []Tracer{tracer},
		Instrumentables: map[ExecutableKey]*instrumenter{
			{Dev: 1, Ino: 1}: shared,
			{Dev: 1, Ino: 2}: shared,
			{Dev: 1, Ino: 3}: single,
		},
		instrumentableGenerations: map[ExecutableKey]uint64{
			{Dev: 1, Ino: 1}: 1,
			{Dev: 1, Ino: 2}: 2,
			{Dev: 1, Ino: 3}: 3,
		},
	}

	pt.closeInstrumenters()

	for _, i := range []*instrumenter{shared, single} {
		for _, c := range i.closables {
			assert.Equal(t, int32(1), c.(*countingCloser).closes.Load())
		}
	}
	assert.Equal(t, []uint64{7}, tracer.unlinked)
	assert.Empty(t, pt.Instrumentables)
	assert.Empty(t, pt.instrumentableGenerations)
}

func TestCloseInstrumentersWithoutExecutables(t *testing.T) {
	pt := &ProcessTracer{log: slog.Default()}

	pt.closeInstrumenters()

	assert.Empty(t, pt.Instrumentables)
}

// an executable that fails to attach is never committed, so its probes and its
// shared library references are only ever released here
func TestUnlinkInstrumenterReleasesProbesAndModules(t *testing.T) {
	baseline := &countingCloser{}
	group := &reverseCloser{closers: []io.Closer{&countingCloser{}}}
	tracer := &libUnlinkingTracer{}
	pt := &ProcessTracer{log: slog.Default(), Programs: []Tracer{tracer}}
	i := &instrumenter{
		closables: []io.Closer{baseline, group},
		modules:   map[uint64]struct{}{11: {}},
	}

	pt.unlinkInstrumenter(i)

	assert.Equal(t, int32(1), baseline.closes.Load())
	assert.Equal(t, int32(1), group.closers[0].(*countingCloser).closes.Load())
	assert.Equal(t, []uint64{11}, tracer.unlinked)
}

// shutdown may not clear the committed set while an attachment is between its
// probe setup and its commit, or those probes are left to the kernel
func TestCloseInstrumentersWaitsForInFlightAttachment(t *testing.T) {
	pt := &ProcessTracer{
		log:                       slog.Default(),
		Instrumentables:           map[ExecutableKey]*instrumenter{},
		instrumentableGenerations: map[ExecutableKey]uint64{},
	}
	attached := &countingCloser{}
	holdsLock := make(chan struct{})
	commitDone := make(chan struct{})

	// mirrors NewExecutable: the mutex is held from before the probes are
	// attached until after the instrumenter is committed
	go func() {
		defer close(commitDone)
		pt.instrumentablesMu.Lock()
		defer pt.instrumentablesMu.Unlock()
		close(holdsLock)
		time.Sleep(20 * time.Millisecond)
		pt.commitInstrumenter(&instrumenter{
			key:       ExecutableKey{Dev: 1, Ino: 1},
			closables: []io.Closer{attached},
			modules:   map[uint64]struct{}{},
		}, &Instrumentable{})
	}()

	<-holdsLock
	pt.closeInstrumenters()
	<-commitDone

	assert.Equal(t, int32(1), attached.closes.Load())
	assert.Empty(t, pt.Instrumentables)
}

func TestNewExecutableRejectedAfterShutdown(t *testing.T) {
	pt := &ProcessTracer{log: slog.Default(), Instrumentables: map[ExecutableKey]*instrumenter{}}

	pt.closeInstrumenters()

	// nothing is dereferenced because no probe is attached after shutdown
	require.ErrorIs(t, pt.NewExecutable(nil, &Instrumentable{}), errTracerStopped)
	require.ErrorIs(t, pt.NewExecutableInstance(&Instrumentable{
		FileInfo: exec.New(exec.Init{Dev: 1, Ino: 2}),
	}), errTracerStopped)
	assert.Empty(t, pt.Instrumentables)
}
