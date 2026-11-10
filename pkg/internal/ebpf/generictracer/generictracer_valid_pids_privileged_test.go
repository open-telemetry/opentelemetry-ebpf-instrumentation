// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer

import (
	"bytes"
	"log/slog"
	"testing"
	"time"

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

func TestValidPidsUpdateAfterCloseIsSkipped(t *testing.T) {
	// on cancellation the ringbuf closes the tracer while the attacher can still update it
	tracer := newTestValidPidsTracer(t, 41000)
	var logs bytes.Buffer
	tracer.log = slog.New(slog.NewJSONHandler(&logs, nil))

	tracer.AllowPID(41000, 0, exec.New(exec.Init{Pid: 41000}))
	require.NoError(t, tracer.Close())

	tracer.pidsFilter = fakeServiceFilter{}
	tracer.BlockPID(41000, 0)
	tracer.pidsFilter = fakeServiceFilter{procPIDs: []app.PID{41007}}
	tracer.AllowPID(41007, 0, exec.New(exec.Init{Pid: 41007}))

	assert.NotContains(t, logs.String(), `"level":"ERROR"`)
}

// holds the valid_pids rebuild in flight until released
type blockingPidsFilter struct {
	fakeServiceFilter
	entered chan struct{}
	release chan struct{}
}

func (f *blockingPidsFilter) ProcPIDs(ebpfcommon.PIDType) []app.PID {
	close(f.entered)
	<-f.release
	return []app.PID{41000}
}

func TestCloseWaitsForAnInFlightValidPidsUpdate(t *testing.T) {
	tracer := newTestValidPidsTracer(t)
	filter := &blockingPidsFilter{entered: make(chan struct{}), release: make(chan struct{})}
	tracer.pidsFilter = filter
	var logs bytes.Buffer
	tracer.log = slog.New(slog.NewJSONHandler(&logs, nil))
	// a second handle reads the map after Close closes the tracer's one
	readback, err := tracer.bpfObjects.ValidPids.Clone()
	require.NoError(t, err)
	t.Cleanup(func() { readback.Close() })

	updated := make(chan struct{})
	go func() {
		defer close(updated)
		tracer.BlockPID(41007, 0)
	}()
	<-filter.entered

	closed := make(chan error, 1)
	go func() { closed <- tracer.Close() }()
	require.Never(t, func() bool { return len(closed) > 0 }, 100*time.Millisecond, 10*time.Millisecond,
		"Close returned while a valid_pids update was in flight")

	close(filter.release)
	<-updated
	require.NoError(t, <-closed)

	assert.NotContains(t, logs.String(), `"level":"ERROR"`)
	// the in-flight update was written before the map was closed
	assert.Equal(t, uint64(1<<40), validPidsWord(t, readback, 640))
}
