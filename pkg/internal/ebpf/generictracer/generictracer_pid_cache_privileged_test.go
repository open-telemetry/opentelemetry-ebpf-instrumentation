// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"log/slog"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

const testPidCacheEntries = 4096

func newTestBPFMap(t *testing.T, spec *ebpf.MapSpec) *ebpf.Map {
	t.Helper()

	require.NoError(t, rlimit.RemoveMemlock())

	m, err := ebpf.NewMap(spec)
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Close() })

	return m
}

func newTestValidPids(t *testing.T) *ebpf.Map {
	return newTestBPFMap(t, &ebpf.MapSpec{
		Name:       "valid_pids_test",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: maxConcurrentPids,
	})
}

func newTestPidCache(t *testing.T) *ebpf.Map {
	return newTestBPFMap(t, &ebpf.MapSpec{
		Name:       "pid_cache_test",
		Type:       ebpf.LRUHash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: testPidCacheEntries,
	})
}

func newTestPidFilterTracer(t *testing.T, ns uint32, nsPid app.PID) *Tracer {
	tracer := &Tracer{
		log: slog.Default(),
		pidsFilter: fakeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{
			ns: {nsPid: {}},
		}},
	}
	tracer.bpfObjects.ValidPids = newTestValidPids(t)
	tracer.bpfObjects.PidCache = newTestPidCache(t)

	return tracer
}

func pidCacheLen(t *testing.T, m *ebpf.Map) int {
	t.Helper()

	var key, value uint32
	n := 0
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		n++
	}
	require.NoError(t, iter.Err())

	return n
}

// one positive and many negative entries, as the BPF side leaves them; more
// than one drain batch so the cursor is exercised
func fillPidCache(t *testing.T, m *ebpf.Map, entries int) {
	t.Helper()

	require.NoError(t, m.Put(uint32(41007), uint32(41007)))
	for pid := uint32(1); pid < uint32(entries); pid++ {
		require.NoError(t, m.Put(pid, uint32(0)))
	}
	require.Equal(t, entries, pidCacheLen(t, m))
}

// pid_cache holds negative answers too (bpf/pid/pid.h), so every rebuild of the
// filter must drop the whole cache or a stale "not selected" would outlive the
// filter change that authorized the process.
func TestRebuildValidPidsClearsPidCache(t *testing.T) {
	const ns, nsPid = uint32(4026532701), app.PID(7)
	tracer := newTestPidFilterTracer(t, ns, nsPid)
	fillPidCache(t, tracer.bpfObjects.PidCache, 3*pidCacheDrainBatchLen)

	require.NoError(t, tracer.rebuildValidPids())

	assert.Equal(t, 0, pidCacheLen(t, tracer.bpfObjects.PidCache), "rebuild must clear every cached answer")

	segment, bit := pidSegmentBit((uint64(ns) << 32) | uint64(nsPid))
	var word uint64
	require.NoError(t, tracer.bpfObjects.ValidPids.Lookup(segment, &word))
	assert.Equal(t, uint64(1)<<bit, word, "the selected (ns, pid) bit is set")
}

// The fallback for kernels without the map batch API must drain the map too.
func TestDrainPidCacheByKey(t *testing.T) {
	tracer := &Tracer{log: slog.Default()}
	cache := newTestPidCache(t)
	fillPidCache(t, cache, 3*pidCacheDrainBatchLen)

	require.NoError(t, tracer.drainPidCacheByKey(cache))
	assert.Equal(t, 0, pidCacheLen(t, cache))
}

func TestClearPidCacheOnEmptyMap(t *testing.T) {
	tracer := &Tracer{log: slog.Default()}
	tracer.bpfObjects.PidCache = newTestPidCache(t)

	require.NoError(t, tracer.clearPidCache())
	assert.Equal(t, 0, pidCacheLen(t, tracer.bpfObjects.PidCache))
}

// A clear that cannot run (here: the map is gone) must not fail the rebuild:
// the filter bits are already written and AllowPID still has to put its
// positive entry.
func TestRebuildValidPidsSurvivesClearFailure(t *testing.T) {
	const ns, nsPid = uint32(4026532701), app.PID(7)
	tracer := newTestPidFilterTracer(t, ns, nsPid)

	require.NoError(t, tracer.bpfObjects.PidCache.Close())

	require.NoError(t, tracer.rebuildValidPids())

	segment, bit := pidSegmentBit((uint64(ns) << 32) | uint64(nsPid))
	var word uint64
	require.NoError(t, tracer.bpfObjects.ValidPids.Lookup(segment, &word))
	assert.Equal(t, uint64(1)<<bit, word, "the filter is written even when the cache cannot be cleared")
}
