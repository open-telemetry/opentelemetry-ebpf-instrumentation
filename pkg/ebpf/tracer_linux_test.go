// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/obi"
)

type libUnlinkingTracer struct {
	Tracer
	mu       sync.Mutex
	unlinked []uint64
}

type closeTrackingTracer struct {
	stubTracer
	closes int
}

func (t *closeTrackingTracer) Close() error {
	t.closes++
	return nil
}

type initProbeTracer struct {
	closeTrackingTracer
	probes map[string]ebpfcommon.ProbeDesc
}

func (t *initProbeTracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	return t.probes
}

func (t *initProbeTracer) Required() bool { return true }

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

func TestCloseReleasesProgramsBeforeRun(t *testing.T) {
	program := &closeTrackingTracer{}
	pt := &ProcessTracer{log: slog.Default(), Programs: []Tracer{program}}

	require.NoError(t, pt.Close())
	assert.Equal(t, 1, program.closes)
	require.ErrorIs(t, pt.NewExecutable(nil, nil), errTracerStopped)

	require.NoError(t, pt.Close())
	assert.Equal(t, 1, program.closes)
}

func TestInitClosesPartialInitProbesOnRequiredProbeFailure(t *testing.T) {
	originalKprobe := attachKprobe
	originalKretprobe := attachKretprobe
	t.Cleanup(func() {
		attachKprobe = originalKprobe
		attachKretprobe = originalKretprobe
	})

	attached := &countingCloser{}
	attachKprobe = func(string, *cebpf.Program, *link.KprobeOptions) (io.Closer, error) {
		return attached, nil
	}
	attachKretprobe = func(string, *cebpf.Program, *link.KprobeOptions) (io.Closer, error) {
		return nil, errors.New("required probe failed")
	}

	program := &initProbeTracer{
		probes: map[string]ebpfcommon.ProbeDesc{
			"required_probe": {
				Start:    &cebpf.Program{},
				End:      &cebpf.Program{},
				Required: true,
			},
		},
	}
	unattemptedProgram := &closeTrackingTracer{}
	cfg := &obi.Config{}
	cfg.EBPF.BPFFSPath = t.TempDir()
	pt := NewProcessTracer(Generic, []Tracer{program, unattemptedProgram}, cfg, imetrics.NoopReporter{})

	err := pt.Init(&ebpfcommon.EBPFEventContext{}, cfg)

	require.Error(t, err)
	require.NoError(t, pt.Close())
	assert.Equal(t, int32(1), attached.closes.Load())
	assert.Equal(t, 1, program.closes)
	assert.Equal(t, 1, unattemptedProgram.closes)
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
