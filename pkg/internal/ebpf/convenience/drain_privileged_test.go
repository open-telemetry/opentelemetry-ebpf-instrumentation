// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package ebpfconvenience // import "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"

import (
	"encoding/binary"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
)

// Same layout as the bpf2go-generated obi_ctx_info_t the production callers pass.
type drainValue struct {
	TraceID [16]byte
	SpanID  [8]byte
}

// An LRU hash starts evicting before it is full, because its free list is split
// per CPU, so the test map gets headroom: every entry a test puts must stay put.
const lruHeadroom = 2

func newDrainTestMap(t *testing.T, entries uint32) *ebpf.Map {
	t.Helper()

	require.NoError(t, rlimit.RemoveMemlock())

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LRUHash,
		KeySize:    uint32(binary.Size(uint64(0))),
		ValueSize:  uint32(binary.Size(drainValue{})),
		MaxEntries: entries * lruHeadroom,
	})
	require.NoError(t, err)
	t.Cleanup(func() { m.Close() })

	return m
}

func fill(t *testing.T, m *ebpf.Map, n uint64) {
	t.Helper()

	for i := range n {
		require.NoError(t, m.Put(i, drainValue{}))
	}
}

func countEntries(t *testing.T, m *ebpf.Map) int {
	t.Helper()

	var (
		key   uint64
		value drainValue
		n     int
	)

	it := m.Iterate()
	for it.Next(&key, &value) {
		n++
	}
	require.NoError(t, it.Err())

	return n
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// The whole point of the batch path is that a full map costs a handful of
// syscalls rather than two per entry, so the batch length must not bound what
// it removes.
func TestDrainMapEmptiesBeyondOneBatch(t *testing.T) {
	const entries = drainBatchLen * 3

	m := newDrainTestMap(t, entries)
	fill(t, m, entries)

	drained, err := drainMap[drainValue](m)
	require.NoError(t, err)
	require.Equal(t, entries, drained)
	require.Zero(t, countEntries(t, m))
}

// The fallback path is what runs on RHEL8 derivatives, which ship a 4.18 kernel
// without batch map operations.
func TestIterateDrainEmptiesMap(t *testing.T) {
	const entries = 128

	m := newDrainTestMap(t, entries)
	fill(t, m, entries)

	drained, err := iterateDrain[drainValue](m)
	require.NoError(t, err)
	require.Equal(t, entries, drained)
	require.Zero(t, countEntries(t, m))
}

func TestDrainMapOnEmptyMap(t *testing.T) {
	m := newDrainTestMap(t, 64)

	drained, err := drainMap[drainValue](m)
	require.NoError(t, err)
	require.Zero(t, drained)
}

func TestDrainTraceContextMapEmptiesThePin(t *testing.T) {
	const entries = 64

	m := newDrainTestMap(t, entries)
	fill(t, m, entries)

	drainTraceContextMap[drainValue](discardLogger(), m)
	require.Zero(t, countEntries(t, m))
}

// Each tracer calls the exported function when it starts, and they start at
// different times: only the first call may sweep.
func TestDrainTraceContextMapSweepsOncePerProcess(t *testing.T) {
	drainOnce = sync.Once{}
	t.Cleanup(func() { drainOnce = sync.Once{} })

	const entries = 64

	m := newDrainTestMap(t, entries)
	fill(t, m, entries)

	DrainTraceContextMap[drainValue](discardLogger(), m)
	require.Zero(t, countEntries(t, m))

	fill(t, m, entries)
	DrainTraceContextMap[drainValue](discardLogger(), m)
	require.Equal(t, entries, countEntries(t, m), "a second tracer must not sweep again")
}

func TestDrainTraceContextMapWithoutMap(t *testing.T) {
	require.NotPanics(t, func() {
		DrainTraceContextMap[drainValue](discardLogger(), nil)
	})
}
