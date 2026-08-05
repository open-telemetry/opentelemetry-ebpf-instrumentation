// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type waitingResourceTracer struct {
	stubTracer
	started      chan struct{}
	runReturned  chan struct{}
	cleanupSafe  chan struct{}
	cleanupDone  chan struct{}
	resource     io.Closer
	teardownSafe atomic.Bool
}

type executableUpdateRecordingTracer struct {
	stubTracer
	processed int
	unlinked  []uint64
}

func (t *executableUpdateRecordingTracer) ProcessBinary(*exec.FileInfo) {
	t.processed++
}

func (t *executableUpdateRecordingTracer) UnlinkInstrumentedLib(inode uint64) {
	t.unlinked = append(t.unlinked, inode)
}

func (t *waitingResourceTracer) Run(
	ctx context.Context,
	_ *ebpfcommon.EBPFEventContext,
	_ *msg.Queue[[]request.Span],
) {
	close(t.started)
	<-ctx.Done()
	go func() {
		<-t.cleanupSafe
		_ = t.resource.Close()
		t.teardownSafe.Store(true)
		close(t.cleanupDone)
	}()
	close(t.runReturned)
}

func (t *waitingResourceTracer) ResourceTeardownReady() bool {
	return t.teardownSafe.Load()
}

func (t *waitingResourceTracer) WaitForResourceTeardown() {
	<-t.cleanupDone
}

func TestProcessTracerWaitsForPostRunResourceCleanup(t *testing.T) {
	programCloser := &countingCloser{}
	instrumenterCloser := &countingCloser{}
	program := &waitingResourceTracer{
		started:     make(chan struct{}),
		runReturned: make(chan struct{}),
		cleanupSafe: make(chan struct{}),
		cleanupDone: make(chan struct{}),
		resource:    programCloser,
	}
	processTracer := &ProcessTracer{
		shutdownTimeout: time.Second,
		Type:            Generic,
		Programs:        []Tracer{program},
		Instrumentables: map[ExecutableKey]*instrumenter{
			{Ino: 1}: {
				closables: []io.Closer{instrumenterCloser},
			},
		},
	}
	eventContext := ebpfcommon.NewEBPFEventContext()
	eventContext.EBPFMaps["shared"] = nil
	runCtx, cancel := context.WithCancel(t.Context())
	processDone := make(chan struct{})
	go func() {
		processTracer.Run(runCtx, eventContext, nil)
		close(processDone)
	}()

	select {
	case <-program.started:
	case <-time.After(time.Second):
		t.Fatal("process tracer did not start its program")
	}
	cancel()
	select {
	case <-program.runReturned:
	case <-time.After(time.Second):
		t.Fatal("program Run did not hand cleanup to its post-run owner")
	}
	select {
	case <-processDone:
		t.Fatal("process tracer returned before post-run cleanup became safe")
	case <-time.After(20 * time.Millisecond):
	}
	assert.Zero(t, programCloser.closes.Load())
	assert.Zero(t, instrumenterCloser.closes.Load())
	assert.False(t, eventContext.ResourcesRetained())

	close(program.cleanupSafe)
	select {
	case <-processDone:
	case <-time.After(time.Second):
		t.Fatal("process tracer did not finish after post-run cleanup")
	}

	assert.Equal(t, int32(1), programCloser.closes.Load())
	assert.Equal(t, int32(1), instrumenterCloser.closes.Load())
	assert.True(t, program.ResourceTeardownReady())
	assert.False(t, eventContext.ResourcesRetained())
	require.Len(t, eventContext.EBPFMaps, 1)

	ShutdownSharedMaps(eventContext)
	assert.Empty(t, eventContext.EBPFMaps)
	ShutdownSharedMaps(eventContext)
	assert.Empty(t, eventContext.EBPFMaps)
}

func TestExecutableInstanceUpdateRollbackPreservesExistingResources(t *testing.T) {
	preexistingCloser := &countingCloser{}
	addedCloser := &countingCloser{}
	program := &executableUpdateRecordingTracer{}
	instrumenter := &instrumenter{
		closables: []io.Closer{preexistingCloser, addedCloser},
		modules: []instrumentedModule{
			{tracer: program, inode: 10},
			{tracer: program, inode: 20},
		},
	}
	processTracer := &ProcessTracer{Programs: []Tracer{program}}
	processTracer.instrumentablesMu.Lock()
	update := processTracer.newExecutableInstanceUpdateLocked(
		exec.New(exec.Init{Pid: 42, Ino: 1234}),
		instrumenter,
		1,
		1,
	)

	update.Rollback()
	update.Rollback()

	assert.Zero(t, preexistingCloser.closes.Load())
	assert.Equal(t, int32(1), addedCloser.closes.Load())
	assert.Equal(t, []uint64{20}, program.unlinked)
	assert.Zero(t, program.processed)
	assert.Equal(t, []io.Closer{preexistingCloser}, instrumenter.closables)
	require.Len(t, instrumenter.modules, 1)
	assert.Equal(t, uint64(10), instrumenter.modules[0].inode)
}

func TestExecutableInstanceUpdateCommitPublishesWithoutRollback(t *testing.T) {
	preexistingCloser := &countingCloser{}
	addedCloser := &countingCloser{}
	program := &executableUpdateRecordingTracer{}
	instrumenter := &instrumenter{
		closables: []io.Closer{preexistingCloser, addedCloser},
		modules: []instrumentedModule{
			{tracer: program, inode: 10},
			{tracer: program, inode: 20},
		},
	}
	processTracer := &ProcessTracer{Programs: []Tracer{program}}
	processTracer.instrumentablesMu.Lock()
	update := processTracer.newExecutableInstanceUpdateLocked(
		exec.New(exec.Init{Pid: 42, Ino: 1234}),
		instrumenter,
		1,
		1,
	)

	update.Commit()
	update.Rollback()

	assert.Zero(t, preexistingCloser.closes.Load())
	assert.Zero(t, addedCloser.closes.Load())
	assert.Empty(t, program.unlinked)
	assert.Equal(t, 1, program.processed)
	assert.Len(t, instrumenter.closables, 2)
	assert.Len(t, instrumenter.modules, 2)
}
