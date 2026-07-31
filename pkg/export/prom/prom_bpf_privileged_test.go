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

	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

func TestGetProbeMetricsClosesStatsFD(t *testing.T) {
	collector := newPrivilegedTestCollector(t)
	loadTestPrograms(t, 1, ebpf.SocketFilter)

	previousGCPercent := debug.SetGCPercent(-1)
	t.Cleanup(func() {
		debug.SetGCPercent(previousGCPercent)
	})

	collector.getProbeMetrics()
	before := openFDCount(t)

	for range 10 {
		collector.getProbeMetrics()
	}

	require.Equal(t, before, openFDCount(t))
}

func TestGetProbeMetricsCachesProgramsAndDiscoversNewIDs(t *testing.T) {
	collector := newPrivilegedTestCollector(t)
	firstProgram := loadTestPrograms(t, 1, ebpf.SocketFilter)[0]
	firstID := programID(t, firstProgram)

	metrics := collector.getProbeMetrics()

	firstCached, ok := collector.programCache[firstID]
	require.True(t, ok)
	require.NotNil(t, firstCached.program)
	require.Equal(t, firstCached.program.FD(), cachedProgramFD(t, collector, firstID))
	requireProbeMetric(t, metrics, firstID, ebpf.SocketFilter, "metric_0")

	require.NoError(t, firstProgram.Close())
	requireProbeMetric(t, collector.getProbeMetrics(), firstID, ebpf.SocketFilter, "metric_0")

	secondProgram := loadTestPrograms(t, 1, ebpf.SocketFilter)[0]
	secondID := programID(t, secondProgram)
	require.Greater(t, secondID, firstID)

	metrics = collector.getProbeMetrics()

	require.Same(t, firstCached, collector.programCache[firstID])
	require.NotNil(t, collector.programCache[secondID].program)
	requireProbeMetric(t, metrics, secondID, ebpf.SocketFilter, "metric_0")
}

func TestGetProbeMetricsNegativelyCachesUnsupportedPrograms(t *testing.T) {
	collector := newPrivilegedTestCollector(t)
	program := loadTestPrograms(t, 1, ebpf.XDP)[0]
	id := programID(t, program)

	collector.getProbeMetrics()

	cached, ok := collector.programCache[id]
	require.True(t, ok)
	require.Nil(t, cached.program)
}

func TestCollectorShutdownClosesProgramsAndClearsState(t *testing.T) {
	internalMetrics := imetrics.NewPrometheusReporter(
		&imetrics.InternalMetricsConfig{BpfMetricScrapeInterval: time.Hour},
		nil,
		prometheus.NewRegistry(),
	)
	collector := newInternalBPFCollector(
		&global.ContextInfo{Metrics: internalMetrics},
		&PrometheusConfig{},
		&perapp.MetricsConfig{},
	)
	program := loadTestPrograms(t, 1, ebpf.SocketFilter)[0]
	id := programID(t, program)
	loadTestMaps(t, 1, ebpf.LRUHash, 1)

	collector.getProbeMetrics()
	collector.getMapMetrics()
	cachedProgram := collector.programCache[id].program
	require.NotNil(t, cachedProgram)
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
	_, err := cachedProgram.Info()
	require.Error(t, err)
}

func TestGetMapMetricsCachesMetadataAndEvictsMissingMaps(t *testing.T) {
	collector := newPrivilegedTestCollector(t)
	supportedMap := loadTestMaps(t, 1, ebpf.LRUHash, 3)[0]
	unsupportedMap := loadTestMaps(t, 1, ebpf.Hash, 1)[0]
	supportedID := mapID(t, supportedMap)
	unsupportedID := mapID(t, unsupportedMap)

	metrics := collector.getMapMetrics()

	supportedCached, ok := collector.mapCache[supportedID]
	require.True(t, ok)
	require.True(t, supportedCached.supported)
	unsupportedCached, ok := collector.mapCache[unsupportedID]
	require.True(t, ok)
	require.False(t, unsupportedCached.supported)
	require.Equal(t, ebpf.Hash.String(), unsupportedCached.mapType)
	require.Equal(t, "metric_0", unsupportedCached.mapName)
	require.Equal(t, fmt.Sprintf("%d", unsupportedID), unsupportedCached.mapID)
	require.Equal(t, 2, unsupportedCached.maxEntries)
	requireMapMetric(t, metrics, supportedID, "metric_0", ebpf.LRUHash, 6, 3)

	collector.getMapMetrics()
	require.Same(t, supportedCached, collector.mapCache[supportedID])
	require.Same(t, unsupportedCached, collector.mapCache[unsupportedID])

	require.NoError(t, supportedMap.Close())
	require.NoError(t, unsupportedMap.Close())
	collector.getMapMetrics()

	_, ok = collector.mapCache[supportedID]
	require.False(t, ok)
	_, ok = collector.mapCache[unsupportedID]
	require.False(t, ok)
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

func newPrivilegedTestCollector(tb testing.TB) *BPFCollector {
	tb.Helper()

	collector := newCollector(
		&global.ContextInfo{},
		&PrometheusConfig{},
		&perapp.MetricsConfig{},
		false,
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

func cachedProgramFD(t *testing.T, collector *BPFCollector, id ebpf.ProgramID) int {
	t.Helper()

	collector.getProbeMetrics()
	cached, ok := collector.programCache[id]
	require.True(t, ok)
	require.NotNil(t, cached.program)
	return cached.program.FD()
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
			require.Equal(t, entries, metric.entries)
			return
		}
	}
	require.Failf(t, "map metric not found", "map ID %d", id)
}
