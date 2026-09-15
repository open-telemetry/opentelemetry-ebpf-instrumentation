// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"context"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestBitPositionCalculation(t *testing.T) {
	for _, v := range [][4]uint32{
		{0, 1, 0, 1},
		{0, 2, 0, 2},
		{0, 65, 1, 1},
		{0, 66, 1, 2},
		{0, primeHash, 0, 0},
		{0, primeHash + 1, 0, 1},
	} {
		k := makeKey(v[0], v[1])
		segment, bit := pidSegmentBit(k)
		assert.Equal(t, segment, v[2])
		assert.Equal(t, bit, v[3])
	}
}

func makeKey(first, second uint32) uint64 {
	return (uint64(first) << 32) | uint64(second)
}

// Mirrors the _Static_assert in bpf/pid/pid.h.
func TestPidFilterIndexSpaceFitsMap(t *testing.T) {
	highestSegment := (primeHash - 1) / 64

	assert.Less(t, highestSegment, maxConcurrentPids,
		"primeHash %d needs %d segments but valid_pids holds %d",
		primeHash, highestSegment+1, maxConcurrentPids)

	// buildPidFilter must allocate a slot for every reachable segment.
	assert.Len(t, (&Tracer{pidsFilter: fakeServiceFilter{}}).buildPidFilter(), maxConcurrentPids)
}

func TestParseJVMMemoryPoolRecordDecoratesServiceByPIDNamespace(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders", Namespace: "prod"}}
	currentPIDsCalls := 0
	tracer := &Tracer{
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				7:  {1234: {UID: svc.UID{Name: "wrong"}}},
				42: {1234: service},
			},
			currentPIDsCalls: &currentPIDsCalls,
		},
	}

	events, ignore, err := tracer.parseJVMMemoryPoolRecord(&ringbuf.Record{
		RawSample: rawMemoryPoolPayload(t, BpfJvmMemPoolGcEvent{
			Timestamp:  123,
			NsPid:      1234,
			PidNsId:    42,
			GcWhenType: uint32(jvmruntime.RawJVMGCWhenAfter),
			Used:       100,
			Committed:  200,
			MaxSize:    300,
			Pool:       rawJVMString("G1 Eden Space"),
		}),
	})

	require.NoError(t, err)
	require.False(t, ignore)
	require.Len(t, events, 4)
	for _, event := range events {
		assert.Equal(t, service, event.Service)
	}
	assert.Equal(t, 1, currentPIDsCalls)
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsed, events[0].Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryCommitted, events[1].Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryLimit, events[2].Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsedAfterLastGC, events[3].Kind)
}

func TestParseJVMMemoryPoolRecordIgnoresUnknownPID(t *testing.T) {
	tracer := &Tracer{
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				42: {1234: {UID: svc.UID{Name: "orders"}}},
			},
		},
	}

	events, ignore, err := tracer.parseJVMMemoryPoolRecord(&ringbuf.Record{
		RawSample: rawMemoryPoolPayload(t, BpfJvmMemPoolGcEvent{
			NsPid:      9999,
			PidNsId:    42,
			GcWhenType: uint32(jvmruntime.RawJVMGCWhenAfter),
			Used:       100,
			Committed:  200,
			Pool:       rawJVMString("G1 Eden Space"),
		}),
	})

	require.NoError(t, err)
	assert.True(t, ignore)
	assert.Empty(t, events)
}

func TestProcessSharedRingbufRecordConsumesJVMRuntimeMetricRecordsWithoutForwarding(t *testing.T) {
	for _, tt := range []struct {
		name    string
		enabled bool
	}{
		{name: "metrics disabled"},
		{name: "queue missing", enabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tracer := &Tracer{cfg: &obi.Config{}}
			if tt.enabled {
				tracer.cfg.Metrics.Features = export.FeatureApplicationRuntime
			}

			span, ignore, err := tracer.processSharedRingbufRecord(context.Background(), nil, &tracer.cfg.EBPF, &ringbuf.Record{
				RawSample: []byte{ebpfcommon.EventTypeJVMMemoryPoolGC},
			})

			require.NoError(t, err)
			assert.True(t, ignore)
			assert.Empty(t, span)
		})
	}
}

func TestProcessSharedRingbufRecordDispatchesRegisteredInternalEvent(t *testing.T) {
	const testInternalEventType uint8 = 0xfe

	eventContext := ebpfcommon.NewEBPFEventContext()
	handled := false
	eventContext.RegisterInternalEventHandler(
		testInternalEventType,
		func(*ringbuf.Record) error {
			handled = true
			return nil
		},
	)
	tracer := &Tracer{
		cfg:      &obi.Config{},
		eventCtx: eventContext,
	}

	span, ignore, err := tracer.processSharedRingbufRecord(
		context.Background(),
		nil,
		&tracer.cfg.EBPF,
		&ringbuf.Record{RawSample: []byte{testInternalEventType}},
	)

	require.NoError(t, err)
	assert.True(t, handled)
	assert.True(t, ignore)
	assert.Empty(t, span)
}

func TestProcessSharedRingbufRecordDispatchesJVMMemoryPoolRecord(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders", Namespace: "prod"}}
	runtimeMetrics := msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(1))
	received := runtimeMetrics.Subscribe(msg.SubscriberName("jvm-test"))
	tracer := &Tracer{
		cfg: &obi.Config{},
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				42: {1234: service},
			},
		},
		eventCtx: &ebpfcommon.EBPFEventContext{RuntimeMetrics: runtimemetrics.NewQueueSender(runtimeMetrics)},
	}
	tracer.cfg.Metrics.Features = export.FeatureApplicationRuntime

	span, ignore, err := tracer.processSharedRingbufRecord(context.Background(), nil, &tracer.cfg.EBPF, &ringbuf.Record{
		RawSample: rawMemoryPoolPayload(t, BpfJvmMemPoolGcEvent{
			Type:       ebpfcommon.EventTypeJVMMemoryPoolGC,
			Timestamp:  100,
			NsPid:      1234,
			PidNsId:    42,
			GcWhenType: uint32(jvmruntime.RawJVMGCWhenAfter),
			Used:       100,
			Committed:  200,
			MaxSize:    300,
			Pool:       rawJVMString("G1 Eden Space"),
		}),
	})

	require.NoError(t, err)
	assert.True(t, ignore)
	assert.Empty(t, span)

	batch := readJVMTestBatch(t, received)
	require.Len(t, batch, 4)
	for _, snapshot := range batch {
		assert.Equal(t, service, snapshot.Service)
		require.NotNil(t, snapshot.JVM)
	}
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsed, batch[0].JVM.Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryCommitted, batch[1].JVM.Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryLimit, batch[2].JVM.Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsedAfterLastGC, batch[3].JVM.Kind)
}

func TestJVMBPFMapsAreInternallyPinnedAndUseSharedEventsRingBuffer(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)

	require.NotContains(t, spec.Maps, "jvm_gc_heap_summary_events")
	require.NotContains(t, spec.Maps, "jvm_mem_pool_gc_events")
	require.NotContains(t, spec.Maps, "jvm_heap_summary_samples")

	for _, name := range []string{
		"jvm_mem_pool_samples",
		"obi_usdt_specs",
		"obi_usdt_ip_to_spec_id",
	} {
		require.Contains(t, spec.Maps, name)
		assert.Equal(t, ebpfconvenience.PinInternal, spec.Maps[name].Pinning)
	}
	assert.Equal(t, ebpf.LRUHash, spec.Maps["obi_usdt_ip_to_spec_id"].Type)
}

func TestPythonAsyncMapsScopePointersByProcess(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)

	const pythonAddrKeySize = uint32(unsafe.Sizeof(struct {
		PID  uint64
		Addr uint64
	}{}))

	for _, name := range []string{"python_context_task", "python_task_state"} {
		require.Contains(t, spec.Maps, name)
		assert.Equal(t, pythonAddrKeySize, spec.Maps[name].KeySize)
	}
}

func TestJVMRuntimeMetricsExposeHotSpotUSDTProbes(t *testing.T) {
	tracer := Tracer{cfg: &obi.Config{}}
	assert.Empty(t, tracer.USDTProbes())

	tracer.cfg.Metrics.Features = export.FeatureApplicationRuntime
	assert.NotContains(t, tracer.UProbes(), "libjvm.so")

	probes := tracer.USDTProbes()

	require.Contains(t, probes, "libjvm.so")
	require.Len(t, probes["libjvm.so"], 2)
	assert.Equal(t, "hotspot", probes["libjvm.so"][0].Provider)
	assert.Equal(t, "mem__pool__gc__begin", probes["libjvm.so"][0].Name)
	assert.Equal(t, "hotspot", probes["libjvm.so"][1].Provider)
	assert.Equal(t, "mem__pool__gc__end", probes["libjvm.so"][1].Name)
}

func TestJVMRuntimeMetricsConstantOverridesUseApplicationRuntimeAsFeatureGate(t *testing.T) {
	for _, tt := range []struct {
		name             string
		configure        func(*obi.Config)
		samplingInterval time.Duration
		expectedInterval uint64
	}{
		{name: "disabled", samplingInterval: time.Second},
		{
			name: "enabled globally",
			configure: func(cfg *obi.Config) {
				cfg.Metrics.Features = export.FeatureApplicationRuntime
			},
			samplingInterval: 250 * time.Millisecond,
			expectedInterval: uint64((250 * time.Millisecond).Nanoseconds()),
		},
		{
			name: "enabled for instrument selector",
			configure: func(cfg *obi.Config) {
				cfg.Discovery.Instrument = services.GlobDefinitionCriteria{
					{Metrics: perapp.SvcMetricsConfig{Features: export.FeatureApplicationRuntime}},
				}
			},
			samplingInterval: 500 * time.Millisecond,
			expectedInterval: uint64((500 * time.Millisecond).Nanoseconds()),
		},
		{
			name: "enabled for deprecated services selector",
			configure: func(cfg *obi.Config) {
				cfg.Discovery.Services = services.RegexDefinitionCriteria{
					{Metrics: perapp.SvcMetricsConfig{Features: export.FeatureApplicationRuntime}},
				}
			},
			samplingInterval: 750 * time.Millisecond,
			expectedInterval: uint64((750 * time.Millisecond).Nanoseconds()),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tracer := Tracer{cfg: &obi.Config{}}
			if tt.configure != nil {
				tt.configure(tracer.cfg)
			}
			tracer.cfg.JVMRuntimeMetrics.SamplingInterval = tt.samplingInterval

			overrides := tracer.constants()

			assert.Equal(t, tt.expectedInterval, overrides["jvm_sampling_interval_ns"])
		})
	}
}

func TestRawJVMEventLayoutsUseGeneratedBPFStructs(t *testing.T) {
	assert.Equal(t, 200, int(unsafe.Sizeof(BpfJvmMemPoolGcEvent{})))
	assert.Equal(t, 104, int(unsafe.Sizeof(BpfJvmRuntimeMetricsEvent{})))
	assert.Equal(t, 176, int(unsafe.Sizeof(BpfJvmGcDurationEvent{})))
}

func TestParseJVMGCDurationRecord(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders", Namespace: "prod"}}
	tracer := &Tracer{pidsFilter: fakeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{
		99: {55: service},
	}}}

	event, ignore, err := tracer.parseJVMGCDurationRecord(&ringbuf.Record{RawSample: rawPayload(
		BpfJvmGcDurationEvent{
			Timestamp:     12345,
			NsPid:         55,
			PidNsId:       99,
			DurationNs:    25_000_000,
			CollectorName: rawJVMString("G1 Young Generation"),
			Action:        rawJVMString("end of minor GC"),
		},
	)})

	require.NoError(t, err)
	assert.False(t, ignore)
	assert.Equal(t, service, event.Service)
	assert.Equal(t, app.PID(55), event.PID)
	assert.Equal(t, uint32(99), event.PIDNamespaceID)
	assert.Equal(t, jvmruntime.JVMMetricGCDuration, event.Kind)
	assert.Equal(t, "G1 Young Generation", event.GCName)
	assert.Equal(t, "end of minor GC", event.GCAction)
	assert.Equal(t, uint64(25_000_000), event.DurationNS)
	assert.False(t, event.Time.IsZero())
}

func TestParseJVMRuntimeRecordUsesGeneratedBPFStruct(t *testing.T) {
	service := svc.Attrs{
		UID:         svc.UID{Name: "orders", Namespace: "prod"},
		SDKLanguage: svc.InstrumentableJava,
	}
	tracer := &Tracer{pidsFilter: fakeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{
		99: {55: service},
	}}}
	tracer.jvmGenerations.Store(app.PID(101), uint64(17))

	event, ignore, err := tracer.parseJVMRuntimeRecord(&ringbuf.Record{RawSample: rawPayload(
		BpfJvmRuntimeMetricsEvent{
			Timestamp:                12345,
			GlobalPid:                101,
			NsPid:                    55,
			PidNsId:                  99,
			LoadedClassCount:         11,
			TotalLoadedClassCount:    12,
			UnloadedClassCount:       13,
			ThreadCount:              14,
			DaemonThreadCount:        15,
			AvailableProcessorCount:  16,
			ProcessCpuTimeNs:         ^uint64(0),
			RecentCpuUtilizationBits: math.Float64bits(0.25),
		},
	)})

	require.NoError(t, err)
	assert.False(t, ignore)
	assert.Equal(t, service, event.Service)
	assert.Equal(t, app.PID(55), event.PID)
	assert.Equal(t, uint32(99), event.PIDNamespaceID)
	assert.Equal(t, uint64(17), event.Generation)
	assert.Equal(t, jvmruntime.JVMRuntimeValues{
		LoadedClassCount:        11,
		TotalLoadedClassCount:   12,
		UnloadedClassCount:      13,
		ThreadCount:             14,
		DaemonThreadCount:       15,
		AvailableProcessorCount: 16,
		ProcessCPUTimeNS:        -1,
		RecentCPUUtilization:    0.25,
	}, event.Values)
	assert.False(t, event.Time.IsZero())
}

func TestEnsureJVMRuntimeMetricGeneration(t *testing.T) {
	file := exec.New(exec.Init{
		Pid:     101,
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava},
	})

	ensureJVMRuntimeMetricGeneration(file)
	first := file.RuntimeMetricGeneration(101)
	second := ensureJVMRuntimeMetricGeneration(file)

	assert.NotZero(t, first)
	assert.Equal(t, first, second)
}

// Ties the clang-compiled layout of struct nodejs_eventloop_event (via the
// bpf2go-generated type) to the size the hand-written mirror in
// pkg/ebpf/common assumes; TestNodejsEventLoopRawABI pins the same number on
// the Go side.
func TestRawNodejsEventLayoutUsesGeneratedBPFStruct(t *testing.T) {
	assert.Equal(t, 120, int(unsafe.Sizeof(BpfNodejsEventloopEvent{})))
}

func rawMemoryPoolPayload(t *testing.T, raw BpfJvmMemPoolGcEvent) []byte {
	t.Helper()

	return rawPayload(raw)
}

func rawPayload[T any](raw T) []byte {
	size := int(unsafe.Sizeof(raw))
	out := make([]byte, size)
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), size))
	return out
}

func rawJVMString(value string) [jvmruntime.JVMRawStringLen]byte {
	var raw [jvmruntime.JVMRawStringLen]byte
	copy(raw[:], []byte(value))
	return raw
}

func readJVMTestBatch(t *testing.T, events <-chan []runtimemetrics.RuntimeMetricSnapshot) []runtimemetrics.RuntimeMetricSnapshot {
	t.Helper()

	select {
	case batch := <-events:
		return batch
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for JVM runtime events")
		return nil
	}
}

// The libruby probes sit on symbols the Ruby runtime exercises as a whole, and
// they can only ever correlate on Puma below Ruby 4.0, so the library they are
// declared under must carry the version constraint that gates them.
func TestRubyUProbesAreVersionGated(t *testing.T) {
	tracer := &Tracer{}

	var rubyKeys []string
	for lib := range tracer.UProbes() {
		if strings.HasPrefix(lib, "libruby") {
			rubyKeys = append(rubyKeys, lib)
		}
	}

	require.Len(t, rubyKeys, 1, "exactly one libruby probe group")
	assert.Equal(t, "libruby[< 4.0]", rubyKeys[0])
}

type fakeServiceFilter struct {
	current          map[uint32]map[app.PID]svc.Attrs
	currentPIDsCalls *int
}

func (f fakeServiceFilter) AllowPID(app.PID, uint32, *exec.FileInfo, ebpfcommon.PIDType) {}
func (f fakeServiceFilter) BlockPID(app.PID, uint32)                                     {}
func (f fakeServiceFilter) ValidPID(app.PID, uint32, ebpfcommon.PIDType) bool            { return false }

func (f fakeServiceFilter) Filter(inputSpans []request.Span) []request.Span { return inputSpans }

func (f fakeServiceFilter) CurrentPIDs(ebpfcommon.PIDType) map[uint32]map[app.PID]svc.Attrs {
	if f.currentPIDsCalls != nil {
		(*f.currentPIDsCalls)++
	}
	return f.current
}

func newTestBPFMap(t *testing.T, spec *ebpf.MapSpec) *ebpf.Map {
	t.Helper()

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("removing memlock failed: %v", err)
	}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("ebpf map create failed: %v", err)
	}
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
		MaxEntries: 16,
	})
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

// pid_cache holds negative answers too (bpf/pid/pid.h), so every rebuild of the
// filter must drop the whole cache or a stale "not selected" would outlive the
// filter change that authorized the process.
func TestRebuildValidPidsClearsPidCache(t *testing.T) {
	validPids, pidCache := newTestValidPids(t), newTestPidCache(t)

	const ns, nsPid = uint32(4026532701), app.PID(7)
	tracer := &Tracer{
		log: slog.Default(),
		pidsFilter: fakeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{
			ns: {nsPid: {}},
		}},
	}
	tracer.bpfObjects.ValidPids = validPids
	tracer.bpfObjects.PidCache = pidCache

	// one positive and two negative entries, as the BPF side would leave them
	require.NoError(t, pidCache.Put(uint32(41007), uint32(41007)))
	require.NoError(t, pidCache.Put(uint32(5000), uint32(0)))
	require.NoError(t, pidCache.Put(uint32(6000), uint32(0)))
	require.Equal(t, 3, pidCacheLen(t, pidCache))

	require.NoError(t, tracer.rebuildValidPids())

	assert.Equal(t, 0, pidCacheLen(t, pidCache), "rebuild must clear every cached answer")

	segment, bit := pidSegmentBit((uint64(ns) << 32) | uint64(nsPid))
	var word uint64
	require.NoError(t, validPids.Lookup(segment, &word))
	assert.Equal(t, uint64(1)<<bit, word, "the selected (ns, pid) bit is set")
}

func TestClearPidCacheOnEmptyMap(t *testing.T) {
	pidCache := newTestPidCache(t)
	tracer := &Tracer{log: slog.Default()}
	tracer.bpfObjects.PidCache = pidCache

	require.NoError(t, tracer.clearPidCache())
	assert.Equal(t, 0, pidCacheLen(t, pidCache))
}

// A clear that cannot run (here: the map is gone) must not fail the rebuild:
// the filter bits are already written and AllowPID still has to put its
// positive entry.
func TestRebuildValidPidsSurvivesClearFailure(t *testing.T) {
	validPids, pidCache := newTestValidPids(t), newTestPidCache(t)

	const ns, nsPid = uint32(4026532701), app.PID(7)
	tracer := &Tracer{
		log: slog.Default(),
		pidsFilter: fakeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{
			ns: {nsPid: {}},
		}},
	}
	tracer.bpfObjects.ValidPids = validPids
	tracer.bpfObjects.PidCache = pidCache

	require.NoError(t, pidCache.Close())

	require.NoError(t, tracer.rebuildValidPids())

	segment, bit := pidSegmentBit((uint64(ns) << 32) | uint64(nsPid))
	var word uint64
	require.NoError(t, validPids.Lookup(segment, &word))
	assert.Equal(t, uint64(1)<<bit, word, "the filter is written even when the cache cannot be cleared")
}
