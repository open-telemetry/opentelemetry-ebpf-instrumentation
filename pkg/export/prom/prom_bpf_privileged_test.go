// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package prom

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

func TestBPFStatsRuntimeDoesNotLeakFDsAcrossScrapes(t *testing.T) {
	collector := newPrivilegedTestCollector(t)
	loadTestPrograms(t, 1, ebpf.SocketFilter)

	previousGCPercent := debug.SetGCPercent(-1)
	t.Cleanup(func() {
		debug.SetGCPercent(previousGCPercent)
	})

	before := openFDCount(t)

	for range 10 {
		collector.getProbeMetrics()
	}

	require.Equal(t, before, openFDCount(t))
}

func TestGetProbeMetricsCachesProgramMetadataAndDiscoversNewIDs(t *testing.T) {
	collector := newPrivilegedTestCollector(t)
	firstProgram := loadTestPrograms(t, 1, ebpf.SocketFilter)[0]
	firstID := programID(t, firstProgram)

	metrics := collector.getProbeMetrics()

	firstCached, ok := collector.programCache[firstID]
	require.True(t, ok)
	requireProbeMetric(t, metrics, firstID, ebpf.SocketFilter, "metric_0")

	collector.getProbeMetrics()
	require.Same(t, firstCached, collector.programCache[firstID])

	require.NoError(t, firstProgram.Close())
	metrics = collector.getProbeMetrics()
	requireNoProbeMetric(t, metrics, firstID)
	_, ok = collector.programCache[firstID]
	require.False(t, ok)
	_, ok = collector.progs[firstID]
	require.False(t, ok)

	secondProgram := loadTestPrograms(t, 1, ebpf.SocketFilter)[0]
	secondID := programID(t, secondProgram)
	require.Greater(t, secondID, firstID)

	metrics = collector.getProbeMetrics()

	require.Contains(t, collector.programCache, secondID)
	requireProbeMetric(t, metrics, secondID, ebpf.SocketFilter, "metric_0")
}

func TestGetProbeMetricsReportsAllProgramTypes(t *testing.T) {
	collector := newPrivilegedTestCollector(t)
	xdpID := programID(t, loadTestPrograms(t, 1, ebpf.XDP)[0])
	cgroupID := programID(t, loadTestPrograms(t, 1, ebpf.CGroupSKB)[0])
	iterID := programID(t, loadIterProgram(t))

	metrics := collector.getProbeMetrics()

	requireProbeMetric(t, metrics, xdpID, ebpf.XDP, "metric_0")
	requireProbeMetric(t, metrics, cgroupID, ebpf.CGroupSKB, "metric_0")
	requireProbeMetric(t, metrics, iterID, ebpf.Tracing, "metric_iter")
}

func TestInternalCollectorReportsOnlyOwnedPrograms(t *testing.T) {
	collector := newPrivilegedInternalCollector(t)
	programs := loadTestPrograms(t, 2, ebpf.SocketFilter)
	ownedID := programID(t, programs[0])
	otherID := programID(t, programs[1])

	fdinfoDir := t.TempDir()
	writeFDInfo(t, fdinfoDir, map[string]string{
		"3": fmt.Sprintf("pos:\t0\nflags:\t02000002\nprog_id:\t%d\n", ownedID),
	})
	collector.fdinfoDir = fdinfoDir

	metrics := collector.getProbeMetrics()

	requireProbeMetric(t, metrics, ownedID, ebpf.SocketFilter, "metric_0")
	requireNoProbeMetric(t, metrics, otherID)
}

func TestInternalCollectorFindsOwnedProgramsInProcFS(t *testing.T) {
	collector := newPrivilegedInternalCollector(t)
	program := loadTestPrograms(t, 1, ebpf.SocketFilter)[0]
	id := programID(t, program)

	requireProbeMetric(t, collector.getProbeMetrics(), id, ebpf.SocketFilter, "metric_0")
}

func TestInternalCollectorIgnoresProgramsOpenedByNodeWalk(t *testing.T) {
	node := newPrivilegedTestCollector(t)
	internal := newPrivilegedInternalCollector(t)
	unownedID := loadUnownedProgram(t)
	requireProbeMetric(t, node.getProbeMetrics(), unownedID, ebpf.SocketFilter, "metric_unowned")

	ctx, cancel := context.WithCancel(t.Context())
	walking := make(chan struct{})
	go func() {
		defer close(walking)
		for ctx.Err() == nil {
			node.getProbeMetrics()
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-walking
	})

	// This process holds no program descriptor of its own, so any program reported here
	// was opened by the node walk.
	for range 500 {
		require.Empty(t, internal.getProbeMetrics())
	}
}

func TestInternalCollectorReportsOnlyOwnedMaps(t *testing.T) {
	collector := newPrivilegedInternalCollector(t)
	maps := loadTestMaps(t, 2, ebpf.LRUHash, 1)
	ownedID := mapID(t, maps[0])
	otherID := mapID(t, maps[1])

	fdinfoDir := t.TempDir()
	writeFDInfo(t, fdinfoDir, map[string]string{
		"3": fmt.Sprintf("pos:\t0\nflags:\t02000002\nmap_id:\t%d\n", ownedID),
	})
	collector.fdinfoDir = fdinfoDir

	metrics := collector.getMapMetrics()

	requireMapMetric(t, metrics, ownedID, "metric_0", ebpf.LRUHash, 2, 1)
	requireNoMapMetric(t, metrics, otherID)
}

func TestInternalCollectorFindsOwnedMapsInProcFS(t *testing.T) {
	collector := newPrivilegedInternalCollector(t)
	id := mapID(t, loadTestMaps(t, 1, ebpf.LRUHash, 1)[0])

	requireMapMetric(t, collector.getMapMetrics(), id, "metric_0", ebpf.LRUHash, 2, 1)
}

func TestInternalCollectorIgnoresMapsOpenedByNodeWalk(t *testing.T) {
	node := newPrivilegedTestCollector(t)
	internal := newPrivilegedInternalCollector(t)
	unownedID := loadUnownedMap(t)
	requireMapMetric(t, node.getMapMetrics(), unownedID, "metric_unowned", ebpf.LRUHash, 2, 1)

	ctx, cancel := context.WithCancel(t.Context())
	walking := make(chan struct{})
	go func() {
		defer close(walking)
		for ctx.Err() == nil {
			node.getMapMetrics()
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-walking
	})

	// This process holds no map descriptor of its own, so any map reported here was
	// opened by the node walk.
	for range 500 {
		require.Empty(t, internal.getMapMetrics())
	}
}

func TestInternalCollectorReportsIterators(t *testing.T) {
	collector := newPrivilegedInternalCollector(t)
	id := programID(t, loadIterProgram(t))

	requireProbeMetric(t, collector.getProbeMetrics(), id, ebpf.Tracing, "metric_iter")
}

func TestCollectorShutdownClearsState(t *testing.T) {
	internalMetrics := imetrics.NewPrometheusReporter(
		&imetrics.InternalMetricsConfig{BpfMetricScrapeInterval: time.Hour},
		nil,
		prometheus.NewRegistry(),
	)
	collector := newInternalBPFCollector(
		&global.ContextInfo{Metrics: internalMetrics},
		&PrometheusConfig{},
		&perapp.GlobalMetricsConfig{},
	)
	program := loadTestPrograms(t, 1, ebpf.SocketFilter)[0]
	id := programID(t, program)
	loadTestMaps(t, 1, ebpf.LRUHash, 1)

	collector.getProbeMetrics()
	collector.getMapMetrics()
	require.Contains(t, collector.programCache, id)
	require.NotEmpty(t, collector.progs)
	require.NotEmpty(t, collector.mapCache)

	ctx, cancel := context.WithCancel(t.Context())
	collector.startInternalMetrics(ctx)
	cancel()

	require.Eventually(t, func() bool {
		collector.mu.Lock()
		defer collector.mu.Unlock()
		return len(collector.programCache) == 0 &&
			len(collector.mapCache) == 0 &&
			len(collector.progs) == 0
	}, time.Second, 10*time.Millisecond)
	_, err := program.Info()
	require.NoError(t, err)
}

func TestGetMapMetricsCachesMetadataAndEvictsMissingMaps(t *testing.T) {
	collector := newPrivilegedTestCollector(t)
	hashMap := loadTestMaps(t, 1, ebpf.LRUHash, 3)[0]
	arrayMap := loadTestMaps(t, 1, ebpf.Array, 1)[0]
	hashID := mapID(t, hashMap)
	arrayID := mapID(t, arrayMap)

	metrics := collector.getMapMetrics()

	hashCached, ok := collector.mapCache[hashID]
	require.True(t, ok)
	require.True(t, hashCached.countsEntries)
	arrayCached, ok := collector.mapCache[arrayID]
	require.True(t, ok)
	require.False(t, arrayCached.countsEntries)
	requireMapMetric(t, metrics, hashID, "metric_0", ebpf.LRUHash, 6, 3)

	collector.getMapMetrics()
	require.Same(t, hashCached, collector.mapCache[hashID])
	require.Same(t, arrayCached, collector.mapCache[arrayID])

	require.NoError(t, hashMap.Close())
	require.NoError(t, arrayMap.Close())
	collector.getMapMetrics()

	_, ok = collector.mapCache[hashID]
	require.False(t, ok)
	_, ok = collector.mapCache[arrayID]
	require.False(t, ok)
}

func TestGetMapMetricsReportsEveryMapType(t *testing.T) {
	collector := newPrivilegedTestCollector(t)
	hashID := mapID(t, loadTestMaps(t, 1, ebpf.Hash, 1)[0])
	arrayID := mapID(t, loadTestMaps(t, 1, ebpf.Array, 1)[0])
	perCPUHashID := mapID(t, loadPerCPUMap(t, ebpf.PerCPUHash, 2))
	lruPerCPUHashID := mapID(t, loadPerCPUMap(t, ebpf.LRUCPUHash, 2))
	ringbufID := mapID(t, loadRingbuf(t))
	dataID := mapID(t, loadGlobalDataMap(t))

	metrics := collector.getMapMetrics()

	requireMapMetric(t, metrics, hashID, "metric_0", ebpf.Hash, 2, 1)
	requireMapMetric(t, metrics, perCPUHashID, "metric_percpu", ebpf.PerCPUHash, 4, 2)
	requireMapMetric(t, metrics, lruPerCPUHashID, "metric_percpu", ebpf.LRUCPUHash, 4, 2)
	requireMapMetricWithoutEntries(t, metrics, arrayID, "metric_0", ebpf.Array, 2)
	requireMapMetricWithoutEntries(t, metrics, ringbufID, "metric_ringbuf", ebpf.RingBuf, os.Getpagesize())
	requireNoMapMetric(t, metrics, dataID)
}

func BenchmarkGetProbeMetrics(b *testing.B) {
	for _, count := range []int{50, 500} {
		b.Run(fmt.Sprintf("programs=%d", count), func(b *testing.B) {
			loadTestPrograms(b, count, ebpf.SocketFilter)
			collector := newPrivilegedTestCollector(b)
			collector.getProbeMetrics()

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				collector.getProbeMetrics()
			}
		})
		runtime.GC()
	}
}

func BenchmarkGetMapMetrics(b *testing.B) {
	for _, count := range []int{50, 500} {
		b.Run(fmt.Sprintf("maps=%d", count), func(b *testing.B) {
			loadTestMaps(b, count, ebpf.LRUHash, 16)
			collector := newPrivilegedTestCollector(b)
			collector.getMapMetrics()

			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				collector.getMapMetrics()
			}
		})
	}
}

func BenchmarkCountPerCPUMapEntries(b *testing.B) {
	bpfMap := loadPerCPUMap(b, ebpf.LRUCPUHash, 2500)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		count, err := countMapEntries(bpfMap)
		require.NoError(b, err)
		require.Equal(b, uint64(2500), count)
	}
}

func newPrivilegedTestCollector(tb testing.TB) *BPFCollector {
	tb.Helper()

	collector := newCollector(
		&global.ContextInfo{},
		&PrometheusConfig{},
		&perapp.GlobalMetricsConfig{},
		false,
	)
	tb.Cleanup(collector.close)
	return collector
}

func newPrivilegedInternalCollector(tb testing.TB) *BPFCollector {
	tb.Helper()

	collector := newInternalBPFCollector(
		&global.ContextInfo{},
		&PrometheusConfig{},
		&perapp.GlobalMetricsConfig{},
	)
	tb.Cleanup(collector.close)
	return collector
}

func loadTestPrograms(tb testing.TB, count int, programType ebpf.ProgramType) []*ebpf.Program {
	tb.Helper()

	programs := make([]*ebpf.Program, 0, count)
	for index := range count {
		program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
			Name:         fmt.Sprintf("metric_%d", index),
			Type:         programType,
			License:      "Dual MIT/GPL",
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		})
		require.NoError(tb, err)
		programs = append(programs, program)
	}
	tb.Cleanup(func() {
		for _, program := range programs {
			_ = program.Close()
		}
	})

	return programs
}

// loadUnownedProgram returns the ID of a program this process holds no descriptor for: a
// socket keeps it loaded after its program descriptor is closed.
func loadUnownedProgram(tb testing.TB) ebpf.ProgramID {
	tb.Helper()

	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "metric_unowned",
		Type:         ebpf.SocketFilter,
		License:      "Dual MIT/GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	require.NoError(tb, err)
	id := programID(tb, program)

	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	require.NoError(tb, err)
	tb.Cleanup(func() {
		_ = unix.Close(socket)
	})
	require.NoError(tb, unix.SetsockoptInt(socket, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, program.FD()))
	require.NoError(tb, program.Close())

	return id
}

// loadUnownedMap returns the ID of a map this process holds no descriptor for: a program
// that references it, attached to a socket, keeps it alive after both descriptors are closed.
func loadUnownedMap(tb testing.TB) ebpf.MapID {
	tb.Helper()

	bpfMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "metric_unowned",
		Type:       ebpf.LRUHash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
	})
	require.NoError(tb, err)
	require.NoError(tb, bpfMap.Put(uint32(0), uint32(0)))
	id := mapID(tb, bpfMap)

	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:    "metric_map_ref",
		Type:    ebpf.SocketFilter,
		License: "Dual MIT/GPL",
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, bpfMap.FD()),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	require.NoError(tb, err)

	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	require.NoError(tb, err)
	tb.Cleanup(func() {
		_ = unix.Close(socket)
	})
	require.NoError(tb, unix.SetsockoptInt(socket, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, program.FD()))
	require.NoError(tb, program.Close())
	require.NoError(tb, bpfMap.Close())

	return id
}

// loadPerCPUMap returns a per-CPU hash map holding entries keys, each with one value per CPU.
func loadPerCPUMap(tb testing.TB, mapType ebpf.MapType, entries int) *ebpf.Map {
	tb.Helper()

	bpfMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "metric_percpu",
		Type:       mapType,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: uint32(entries * 2),
	})
	require.NoError(tb, err)
	tb.Cleanup(func() {
		_ = bpfMap.Close()
	})

	values := make([]uint32, ebpf.MustPossibleCPU())
	for entry := range entries {
		require.NoError(tb, bpfMap.Put(uint32(entry), values))
	}

	return bpfMap
}

func loadRingbuf(tb testing.TB) *ebpf.Map {
	tb.Helper()

	bpfMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "metric_ringbuf",
		Type:       ebpf.RingBuf,
		MaxEntries: uint32(os.Getpagesize()),
	})
	require.NoError(tb, err)
	tb.Cleanup(func() {
		_ = bpfMap.Close()
	})

	return bpfMap
}

// loadGlobalDataMap returns a map shaped like the one a loader creates for a .rodata section.
func loadGlobalDataMap(tb testing.TB) *ebpf.Map {
	tb.Helper()

	bpfMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       ".rodata",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	require.NoError(tb, err)
	tb.Cleanup(func() {
		_ = bpfMap.Close()
	})

	return bpfMap
}

func loadIterProgram(tb testing.TB) *ebpf.Program {
	tb.Helper()

	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:         "metric_iter",
		Type:         ebpf.Tracing,
		AttachType:   ebpf.AttachTraceIter,
		AttachTo:     "bpf_map",
		License:      "Dual MIT/GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	require.NoError(tb, err)
	tb.Cleanup(func() {
		_ = program.Close()
	})

	return program
}

func loadTestMaps(tb testing.TB, count int, mapType ebpf.MapType, entries int) []*ebpf.Map {
	tb.Helper()

	maps := make([]*ebpf.Map, 0, count)
	for index := range count {
		bpfMap, err := ebpf.NewMap(&ebpf.MapSpec{
			Name:       fmt.Sprintf("metric_%d", index),
			Type:       mapType,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: uint32(entries * 2),
		})
		require.NoError(tb, err)
		maps = append(maps, bpfMap)

		for entry := range entries {
			require.NoError(tb, bpfMap.Put(uint32(entry), uint32(entry)))
		}
	}
	tb.Cleanup(func() {
		for _, bpfMap := range maps {
			_ = bpfMap.Close()
		}
	})

	return maps
}

func openFDCount(t *testing.T) int {
	t.Helper()

	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	return len(entries)
}

func programID(tb testing.TB, program *ebpf.Program) ebpf.ProgramID {
	tb.Helper()

	info, err := program.Info()
	require.NoError(tb, err)
	id, ok := info.ID()
	require.True(tb, ok)
	return id
}

func mapID(tb testing.TB, bpfMap *ebpf.Map) ebpf.MapID {
	tb.Helper()

	info, err := bpfMap.Info()
	require.NoError(tb, err)
	id, ok := info.ID()
	require.True(tb, ok)
	return id
}

func requireProbeMetric(
	t *testing.T,
	metrics []ProbeMetrics,
	id ebpf.ProgramID,
	programType ebpf.ProgramType,
	name string,
) {
	t.Helper()

	idString := fmt.Sprintf("%d", id)
	for _, metric := range metrics {
		if metric.probeID == idString {
			require.Equal(t, programType.String(), metric.probeType)
			require.Equal(t, name, metric.probeName)
			return
		}
	}
	require.Failf(t, "probe metric not found", "program ID %d", id)
}

func requireNoProbeMetric(t *testing.T, metrics []ProbeMetrics, id ebpf.ProgramID) {
	t.Helper()

	idString := fmt.Sprintf("%d", id)
	for _, metric := range metrics {
		if metric.probeID == idString {
			require.Failf(t, "unexpected probe metric", "program ID %d", id)
		}
	}
}

func requireMapMetricWithoutEntries(
	t *testing.T,
	metrics []BpfMapMetrics,
	id ebpf.MapID,
	name string,
	mapType ebpf.MapType,
	maxEntries int,
) {
	t.Helper()

	idString := fmt.Sprintf("%d", id)
	for _, metric := range metrics {
		if metric.mapID == idString {
			require.Equal(t, name, metric.mapName)
			require.Equal(t, mapType.String(), metric.mapType)
			require.Equal(t, maxEntries, metric.maxEntries)
			require.False(t, metric.hasEntries)
			return
		}
	}
	require.Failf(t, "map metric not found", "map ID %d", id)
}

func requireNoMapMetric(t *testing.T, metrics []BpfMapMetrics, id ebpf.MapID) {
	t.Helper()

	idString := fmt.Sprintf("%d", id)
	for _, metric := range metrics {
		if metric.mapID == idString {
			require.Failf(t, "unexpected map metric", "map ID %d", id)
		}
	}
}

func requireMapMetric(
	t *testing.T,
	metrics []BpfMapMetrics,
	id ebpf.MapID,
	name string,
	mapType ebpf.MapType,
	maxEntries int,
	entries uint64,
) {
	t.Helper()

	idString := fmt.Sprintf("%d", id)
	for _, metric := range metrics {
		if metric.mapID == idString {
			require.Equal(t, name, metric.mapName)
			require.Equal(t, mapType.String(), metric.mapType)
			require.Equal(t, maxEntries, metric.maxEntries)
			require.True(t, metric.hasEntries)
			require.Equal(t, entries, metric.entries)
			return
		}
	}
	require.Failf(t, "map metric not found", "map ID %d", id)
}
