// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer

import (
	"bytes"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
)

func newTestValidPids(t *testing.T, words uint32) *ebpf.Map {
	t.Helper()
	require.NoError(t, rlimit.RemoveMemlock())

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: words,
	})
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })

	return m
}

func newTestValidPidsTracer(t *testing.T, pids ...app.PID) *Tracer {
	t.Helper()

	tracer := &Tracer{log: tlog(), pidsFilter: fakeServiceFilter{procPIDs: pids}}
	tracer.bpfObjects.ValidPids = newTestValidPids(t, validPidsWords)

	return tracer
}

func validPidsWord(t *testing.T, m *ebpf.Map, word uint32) uint64 {
	t.Helper()

	var bits uint64
	require.NoError(t, m.Lookup(word, &bits))

	return bits
}

func TestRebuildValidPidsSetsOneBitPerPid(t *testing.T) {
	// 41000 and 41007 share word 640; 7 is a pod pid when OBI runs as a sidecar
	tracer := newTestValidPidsTracer(t, 41000, 41007, 7)

	require.NoError(t, tracer.rebuildValidPids())

	m := tracer.bpfObjects.ValidPids
	assert.Equal(t, uint64(1<<40|1<<47), validPidsWord(t, m, 640))
	assert.Equal(t, uint64(1<<7), validPidsWord(t, m, 0))
	assert.Equal(t, uint64(0), validPidsWord(t, m, 641))
}

func TestRebuildValidPidsClearsRemovedPids(t *testing.T) {
	tracer := newTestValidPidsTracer(t, 41000, 41007)
	require.NoError(t, tracer.rebuildValidPids())

	tracer.pidsFilter = fakeServiceFilter{procPIDs: []app.PID{41007}}
	require.NoError(t, tracer.rebuildValidPids())
	assert.Equal(t, uint64(1<<47), validPidsWord(t, tracer.bpfObjects.ValidPids, 640))

	tracer.pidsFilter = fakeServiceFilter{}
	require.NoError(t, tracer.rebuildValidPids())
	assert.Equal(t, uint64(0), validPidsWord(t, tracer.bpfObjects.ValidPids, 640))
}

func TestRebuildValidPidsWritesOnlyChangedWords(t *testing.T) {
	tracer := newTestValidPidsTracer(t, 41000)

	// a word the tracer never wrote: a rebuild that rewrote every word would zero it
	const untouchedWord = 5
	require.NoError(t, tracer.bpfObjects.ValidPids.Put(uint32(untouchedWord), uint64(0xff)))

	require.NoError(t, tracer.rebuildValidPids())

	assert.Equal(t, uint64(0xff), validPidsWord(t, tracer.bpfObjects.ValidPids, untouchedWord))
	assert.Equal(t, uint64(1<<40), validPidsWord(t, tracer.bpfObjects.ValidPids, 640))
}

func TestRebuildValidPidsSkipsPidsPastTheBitmap(t *testing.T) {
	tracer := newTestValidPidsTracer(t, app.PID(validPidsWords*64), 41000)

	require.NoError(t, tracer.rebuildValidPids())

	assert.Equal(t, uint64(1<<40), validPidsWord(t, tracer.bpfObjects.ValidPids, 640))
}

func TestValidateValidPidsMapRejectsAnotherSize(t *testing.T) {
	tracer := &Tracer{log: tlog()}

	tracer.bpfObjects.ValidPids = newTestValidPids(t, validPidsWords)
	require.NoError(t, tracer.validateValidPidsMap())

	tracer.bpfObjects.ValidPids = newTestValidPids(t, validPidsWords-1)
	require.Error(t, tracer.validateValidPidsMap())
}

// mirrors unloadInternalMaps in pkg/ebpf, which this package can't import
func unloadTestInternalMaps(eventCtx *ebpfcommon.EBPFEventContext) {
	eventCtx.MapsLock.Lock()
	defer eventCtx.MapsLock.Unlock()

	for _, m := range eventCtx.EBPFMaps {
		m.Close()
	}
	eventCtx.EBPFMaps = map[string]*ebpf.Map{}
}

func newTestSharedValidPidsTracer(t *testing.T, pids ...app.PID) *Tracer {
	t.Helper()

	tracer := newTestValidPidsTracer(t, pids...)
	tracer.eventCtx = &ebpfcommon.EBPFEventContext{
		EBPFMaps: map[string]*ebpf.Map{"valid_pids": tracer.bpfObjects.ValidPids},
	}

	return tracer
}

func TestValidPidsUpdateAfterUnloadIsSkipped(t *testing.T) {
	// on shutdown the shared valid_pids map is unloaded while the attacher can still update it
	tracer := newTestSharedValidPidsTracer(t, 41000)
	var logs bytes.Buffer
	tracer.log = slog.New(slog.NewJSONHandler(&logs, nil))

	tracer.AllowPID(41000, 0, exec.New(exec.Init{Pid: 41000}))
	assert.Equal(t, uint64(1<<40), validPidsWord(t, tracer.bpfObjects.ValidPids, 640))

	unloadTestInternalMaps(tracer.eventCtx)
	tracer.pidsFilter = fakeServiceFilter{}
	tracer.BlockPID(41000, 0)
	tracer.pidsFilter = fakeServiceFilter{procPIDs: []app.PID{41007}}
	tracer.AllowPID(41007, 0, exec.New(exec.Init{Pid: 41007}))

	assert.NotContains(t, logs.String(), `"level":"ERROR"`)
}

// alternates two pids of the same word, so every rebuild writes the map
type alternatingPidsFilter struct {
	fakeServiceFilter
	calls atomic.Uint64
}

func (f *alternatingPidsFilter) ProcPIDs(ebpfcommon.PIDType) []app.PID {
	if f.calls.Add(1)%2 == 0 {
		return []app.PID{41000}
	}
	return []app.PID{41007}
}

func TestValidPidsRebuildRacingUnloadNeverWritesAClosedMap(t *testing.T) {
	tracer := newTestSharedValidPidsTracer(t)
	tracer.pidsFilter = &alternatingPidsFilter{}

	started := make(chan struct{})
	unloaded := make(chan struct{})
	errs := make(chan error, 1)
	go func() {
		defer close(errs)
		// keeps rebuilding after the unload, like an attacher batch still in flight
		for i, after := 0, 0; after < 100; i++ {
			if err := tracer.rebuildValidPids(); err != nil {
				errs <- err
				return
			}
			if i == 10 {
				close(started)
			}
			select {
			case <-unloaded:
				after++
			default:
			}
		}
	}()

	<-started
	unloadTestInternalMaps(tracer.eventCtx)
	close(unloaded)

	require.NoError(t, <-errs)
}
