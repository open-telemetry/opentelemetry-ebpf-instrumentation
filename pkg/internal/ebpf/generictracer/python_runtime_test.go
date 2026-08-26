// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	discexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export"
	cpythonruntime "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
)

func TestPythonRuntimeBPFABI(t *testing.T) {
	assert.Equal(t, uintptr(12), unsafe.Sizeof(BpfPidInfo{}))
	assert.Equal(t, uintptr(48), unsafe.Sizeof(BpfPythonRuntimeMetricTarget{}))
}

func TestPythonRuntimeBPFObjects(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)

	program, ok := spec.Programs["obi_uprobe_python_gc_done"]
	require.True(t, ok)
	assert.Equal(t, ebpf.Kprobe, program.Type)
	assert.Equal(t, "uprobe/python_gc_done", program.SectionName)

	for _, name := range []string{"python_runtime_metric_targets", "python_runtime_metric_snapshots"} {
		metricMap, ok := spec.Maps[name]
		require.True(t, ok)
		assert.Equal(t, ebpf.Hash, metricMap.Type)
		assert.Equal(t, ebpfconvenience.PinInternal, metricMap.Pinning)
		assert.Positive(t, metricMap.MaxEntries)
	}
}

func TestPythonRuntimeProbeAttachmentOptions(t *testing.T) {
	usdt, returnProbe, err := pythonRuntimeUprobeOptions(123, cpythonruntime.GCCompletionProbe{
		Kind: cpythonruntime.GCCompletionProbeUSDT, FileOffset: 0x200, SemaphoreOffset: 0x300,
	})
	require.NoError(t, err)
	assert.False(t, returnProbe)
	assert.Equal(t, uint64(0x200), usdt.Address)
	assert.Equal(t, uint64(0x300), usdt.RefCtrOffset)
	assert.Equal(t, 123, usdt.PID)

	private, returnProbe, err := pythonRuntimeUprobeOptions(456, cpythonruntime.GCCompletionProbe{
		Kind: cpythonruntime.GCCompletionProbePrivateReturn, FileOffset: 0x400,
	})
	require.NoError(t, err)
	assert.True(t, returnProbe)
	assert.Equal(t, uint64(0x400), private.Address)
	assert.Zero(t, private.RefCtrOffset)
	assert.Equal(t, 456, private.PID)
}

func TestPythonRuntimeAllowIsIdempotent(t *testing.T) {
	controller, resolver, targets, _ := pythonRuntimeTestController()
	pid := app.PID(os.Getpid())
	lifecycle := pythonRuntimeTestFile(pid, 100)

	controller.allow(pid, 42, lifecycle, lifecycle)
	controller.allow(pid, 42, lifecycle, lifecycle)
	require.Eventually(t, func() bool { return resolver.calls.Load() == 1 && targets.hasEntries() }, time.Second, time.Millisecond)
	controller.close()
}

func TestPythonRuntimeResolutionFailureDoesNotRetry(t *testing.T) {
	controller, resolver, targets, snapshots := pythonRuntimeTestController()
	resolver.err = errors.New("resolve failed")
	lifecycle := pythonRuntimeTestFile(123, 100)

	controller.allow(123, 42, lifecycle, lifecycle)
	require.Eventually(t, func() bool {
		controller.mu.Lock()
		defer controller.mu.Unlock()
		return resolver.calls.Load() == 1 && len(controller.targets) == 0
	}, time.Second, time.Millisecond)
	assert.False(t, targets.hasEntries())
	assert.False(t, snapshots.hasEntries())
}

func TestPythonRuntimeAttachmentFailureRollsBackMapState(t *testing.T) {
	controller, _, targets, snapshots := pythonRuntimeTestController()
	controller.attach = func(*cpythonruntime.MetricTarget, *ebpf.Program, int) (io.Closer, error) {
		return nil, errors.New("attach failed")
	}
	lifecycle := pythonRuntimeTestFile(123, 100)

	controller.allow(123, 42, lifecycle, lifecycle)
	require.Eventually(t, func() bool {
		controller.mu.Lock()
		defer controller.mu.Unlock()
		return len(controller.targets) == 0
	}, time.Second, time.Millisecond)
	assert.False(t, targets.hasEntries())
	assert.False(t, snapshots.hasEntries())
}

func TestPythonRuntimeBlockRemovesExactLifecycle(t *testing.T) {
	controller, _, targets, snapshots := pythonRuntimeTestController()
	lifecycle := pythonRuntimeTestFile(123, 100)
	generation := uint64(77)
	lifecycle.SetRuntimeMetricGeneration(123, generation)
	key := BpfPidInfo{HostPid: 123, UserPid: 123, Ns: 42}
	closed := &testCloser{}
	cancelCtx, cancel := context.WithCancel(context.Background())
	_ = cancelCtx
	controller.targets[123] = &pythonRuntimeLifecycle{
		pid: 123, ns: 42, startTime: 100, generation: generation,
		lifecycle: lifecycle, serviceSource: lifecycle, key: key, link: closed, cancel: cancel,
	}
	require.NoError(t, targets.Put(key, BpfPythonRuntimeMetricTarget{Generation: generation}))
	raw := BpfPythonRuntimeMetricSnapshot{Generation: generation}
	raw.Generations[0].Collections = 12
	require.NoError(t, snapshots.Put(key, raw))
	controller.block(123, 42, lifecycle, lifecycle)

	assert.True(t, closed.closed.Load())
	assert.False(t, targets.hasEntries())
	assert.False(t, snapshots.hasEntries())
	final, ok := lifecycle.TakePythonRuntimeMetricFinal(123)
	require.True(t, ok)
	assert.True(t, final.HasValue)
	assert.Equal(t, uint64(12), final.Generations[0].Collections)
	assert.Equal(t, generation, final.Generation)
}

func TestPythonRuntimeBlockRejectsStaleLifecycle(t *testing.T) {
	controller, _, targets, snapshots := pythonRuntimeTestController()
	current := pythonRuntimeTestFile(123, 200)
	stale := pythonRuntimeTestFile(123, 100)
	current.SetRuntimeMetricGeneration(123, 8)
	key := BpfPidInfo{HostPid: 123, UserPid: 123, Ns: 42}
	_, cancel := context.WithCancel(context.Background())
	controller.targets[123] = &pythonRuntimeLifecycle{
		pid: 123, ns: 42, startTime: 200, generation: 8,
		lifecycle: current, serviceSource: current, key: key, cancel: cancel,
	}
	require.NoError(t, targets.Put(key, BpfPythonRuntimeMetricTarget{Generation: 8}))
	require.NoError(t, snapshots.Put(key, BpfPythonRuntimeMetricSnapshot{Generation: 8}))

	controller.block(123, 42, stale, stale)

	assert.True(t, targets.hasEntries())
	assert.True(t, snapshots.hasEntries())
	controller.close()
}

func TestPythonRuntimeChildCleanupDoesNotRemoveParent(t *testing.T) {
	controller, _, targets, snapshots := pythonRuntimeTestController()
	parent := pythonRuntimeTestFile(123, 100)
	child := pythonRuntimeTestFile(124, 101)
	parent.SetRuntimeMetricGeneration(123, 8)
	child.SetRuntimeMetricGeneration(124, 9)
	parentKey := BpfPidInfo{HostPid: 123, UserPid: 123, Ns: 42}
	childKey := BpfPidInfo{HostPid: 124, UserPid: 124, Ns: 42}
	_, parentCancel := context.WithCancel(context.Background())
	_, childCancel := context.WithCancel(context.Background())
	controller.targets[123] = &pythonRuntimeLifecycle{
		pid: 123, ns: 42, startTime: 100, generation: 8,
		lifecycle: parent, serviceSource: parent, key: parentKey, cancel: parentCancel,
	}
	controller.targets[124] = &pythonRuntimeLifecycle{
		pid: 124, ns: 42, startTime: 101, generation: 9,
		lifecycle: child, serviceSource: parent, key: childKey, cancel: childCancel,
	}
	require.NoError(t, targets.Put(parentKey, BpfPythonRuntimeMetricTarget{Generation: 8}))
	require.NoError(t, targets.Put(childKey, BpfPythonRuntimeMetricTarget{Generation: 9}))
	require.NoError(t, snapshots.Put(parentKey, BpfPythonRuntimeMetricSnapshot{Generation: 8}))
	require.NoError(t, snapshots.Put(childKey, BpfPythonRuntimeMetricSnapshot{Generation: 9}))

	controller.block(124, 42, child, child)

	assert.True(t, targets.hasKey(parentKey))
	assert.True(t, snapshots.hasKey(parentKey))
	assert.False(t, targets.hasKey(childKey))
	assert.False(t, snapshots.hasKey(childKey))
	assert.Contains(t, controller.targets, app.PID(123))
	assert.NotContains(t, controller.targets, app.PID(124))
	final, ok := parent.TakePythonRuntimeMetricFinal(124)
	require.True(t, ok)
	assert.Equal(t, uint64(9), final.Generation)
	_, ok = child.TakePythonRuntimeMetricFinal(124)
	assert.False(t, ok)
	controller.close()
}

func pythonRuntimeTestController() (
	*pythonRuntimeController,
	*testPythonResolver,
	*testPythonMap,
	*testPythonMap,
) {
	resolver := &testPythonResolver{target: &cpythonruntime.MetricTarget{
		PID: 123, StartTime: 100, RuntimeAddress: 0x1000,
		RuntimeFinalizing: 8, RuntimeInterpretersMain: 16,
		InterpreterGC: 24, GCGenerationStats: 32,
		PrimaryProbe: cpythonruntime.GCCompletionProbe{
			Kind: cpythonruntime.GCCompletionProbePrivateReturn, FileOffset: 0x200,
		},
	}}
	targets := newTestPythonMap()
	snapshots := newTestPythonMap()
	tracer := &Tracer{log: slog.Default()}
	tracer.bpfObjects.ObiUprobePythonGcDone = &ebpf.Program{}
	controller := &pythonRuntimeController{
		tracer: tracer, resolver: resolver,
		targetMap: targets, snapshotMap: snapshots,
		attach: func(*cpythonruntime.MetricTarget, *ebpf.Program, int) (io.Closer, error) {
			return &testCloser{}, nil
		},
		startTime: func(app.PID) (uint64, error) { return 100, nil },
		targets:   map[app.PID]*pythonRuntimeLifecycle{},
	}
	return controller, resolver, targets, snapshots
}

func pythonRuntimeTestFile(pid app.PID, startTime uint64) *discexec.FileInfo {
	return discexec.New(discexec.Init{
		Pid: pid, Ns: 42, StartTime: startTime,
		Service: svc.Attrs{
			UID:         svc.UID{Name: "python"},
			SDKLanguage: svc.InstrumentablePython,
			Features:    export.FeatureApplicationRuntime,
		},
	})
}

type testPythonResolver struct {
	target *cpythonruntime.MetricTarget
	err    error
	calls  atomic.Int32
}

func (r *testPythonResolver) Resolve(context.Context, app.PID, uint64) (*cpythonruntime.MetricTarget, error) {
	r.calls.Add(1)
	return r.target, r.err
}

type testPythonMap struct {
	mu      sync.Mutex
	entries map[BpfPidInfo]any
}

func newTestPythonMap() *testPythonMap {
	return &testPythonMap{entries: map[BpfPidInfo]any{}}
}

func (m *testPythonMap) Put(key, value any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[key.(BpfPidInfo)] = value
	return nil
}

func (m *testPythonMap) Lookup(key, valueOut any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.entries[key.(BpfPidInfo)]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	switch output := valueOut.(type) {
	case *BpfPythonRuntimeMetricSnapshot:
		*output = value.(BpfPythonRuntimeMetricSnapshot)
	case *BpfPythonRuntimeMetricTarget:
		*output = value.(BpfPythonRuntimeMetricTarget)
	default:
		return errors.New("unsupported test map value")
	}
	return nil
}

func (m *testPythonMap) Delete(key any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key.(BpfPidInfo))
	return nil
}

func (m *testPythonMap) hasEntries() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries) != 0
}

func (m *testPythonMap) hasKey(key BpfPidInfo) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.entries[key]
	return ok
}

type testCloser struct {
	closed atomic.Bool
}

func (c *testCloser) Close() error {
	c.closed.Store(true)
	return nil
}
