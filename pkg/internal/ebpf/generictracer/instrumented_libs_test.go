// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

// blocks in Close until released, so a test can observe how many closes run at once
type gatedCloser struct {
	entered *sync.WaitGroup
	release <-chan struct{}
	closed  atomic.Bool
}

func (c *gatedCloser) Close() error {
	c.entered.Done()
	<-c.release
	c.closed.Store(true)
	return nil
}

// every probe release waits for kernel grace periods: the probes of a released library
// close in parallel and the other libraries do not queue behind them
func TestUnlinkInstrumentedLibClosesProbesInParallelOutsideTheLock(t *testing.T) {
	const probes = 3

	var entered sync.WaitGroup
	entered.Add(probes)
	release := make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)

	gated := make([]*gatedCloser, probes)
	closers := make([]io.Closer, probes)
	for i := range gated {
		gated[i] = &gatedCloser{entered: &entered, release: release}
		closers[i] = gated[i]
	}

	p := &Tracer{log: slog.Default(), instrumentedLibs: ebpfcommon.InstrumentedLibsT{}}
	p.RecordInstrumentedLib(1, closers)
	p.RecordInstrumentedLib(2, nil)

	unlinked := make(chan struct{})
	go func() {
		p.UnlinkInstrumentedLib(1)
		close(unlinked)
	}()

	allEntered := make(chan struct{})
	go func() {
		entered.Wait()
		close(allEntered)
	}()
	select {
	case <-allEntered:
	case <-time.After(5 * time.Second):
		require.Fail(t, "the probes of a released library were not closed in parallel")
	}

	lookup := make(chan bool)
	go func() { lookup <- p.AlreadyInstrumentedLib(2) }()
	select {
	case found := <-lookup:
		assert.True(t, found)
	case <-time.After(5 * time.Second):
		require.Fail(t, "the library lock was held while probes were being closed")
	}
	assert.False(t, p.AlreadyInstrumentedLib(1))

	unblock()
	<-unlinked
	for _, c := range gated {
		assert.True(t, c.closed.Load())
	}
}

func TestUnlinkInstrumentedLibKeepsProbesOfReferencedLibrary(t *testing.T) {
	var entered sync.WaitGroup
	entered.Add(1)
	release := make(chan struct{})
	close(release)
	closer := &gatedCloser{entered: &entered, release: release}

	p := &Tracer{log: slog.Default(), instrumentedLibs: ebpfcommon.InstrumentedLibsT{}}
	p.RecordInstrumentedLib(1, []io.Closer{closer})
	p.AddInstrumentedLibRef(1)

	p.UnlinkInstrumentedLib(1)
	assert.False(t, closer.closed.Load())
	assert.True(t, p.AlreadyInstrumentedLib(1))

	p.UnlinkInstrumentedLib(1)
	assert.True(t, closer.closed.Load())
	assert.False(t, p.AlreadyInstrumentedLib(1))
}
