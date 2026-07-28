// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer

import (
	"bytes"
	"debug/elf"
	"errors"
	"io"
	"log/slog"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

func TestGoChannelLinkProbesRequireChannelOffsets(t *testing.T) {
	disableContextPropagationForTest(t)

	tracer := &Tracer{
		log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		goChannelOffsetsByIno: map[uint64]bool{},
	}

	assertNoGoChannelLinkProbes(t, tracer.GoProbes())

	tracer.recordGoChannelOffsetAvailability(
		exec.New(exec.Init{Ino: 1}),
		&goexec.Offsets{Field: goexec.FieldOffsets{
			goexec.HchanQcountPos:   uint64(0),
			goexec.HchanDataqsizPos: uint64(8),
			goexec.HchanSendxPos:    uint64(48),
		}},
	)
	assertNoGoChannelLinkProbes(t, tracer.GoProbes())

	tracer.recordGoChannelOffsetAvailability(exec.New(exec.Init{Ino: 2}), goChannelOffsets())
	probes := tracer.GoProbes()
	for _, symbol := range GoChannelLinkProbeSymbols() {
		require.Contains(t, probes, symbol)
	}
}

func TestMissingGoChannelOffsetsUseSentinel(t *testing.T) {
	var offTable BpfOffTableT

	initMissingGoChannelOffsets(&offTable)

	for _, field := range goChannelOffsetFields {
		assert.Equal(t, missingGoOffset, offTable.Table[field])
	}
	assert.Zero(t, offTable.Table[goexec.ConnFdPos])
}

func TestGoAutoSDKSpanContextOffsetsUseSentinelAndPreserveZero(t *testing.T) {
	var offTable BpfOffTableT

	initMissingGoAutoSDKSpanContextOffsets(&offTable)

	for _, field := range goAutoSDKSpanContextOffsetFields {
		assert.Equal(t, missingGoOffset, offTable.Table[field])
	}

	setGoAutoSDKSpanContextOffsets(&offTable, &goexec.Offsets{
		Field: goexec.FieldOffsets{
			goexec.SpanContextTraceIDPos: uint64(0),
		},
	})

	assert.Zero(t, offTable.Table[goexec.SpanContextTraceIDPos])
	assert.Equal(t, missingGoOffset, offTable.Table[goexec.SpanContextSpanIDPos])
	assert.Equal(t, missingGoOffset, offTable.Table[goexec.SpanContextTraceFlagsPos])
	assert.Equal(t, missingGoOffset, offTable.Table[goexec.AutoSDKSpanContextPos])
	assert.Equal(t, missingGoOffset, offTable.Table[goexec.AutoSDKActivationSupported])
}

func TestGoRuntimeMetricAvailability(t *testing.T) {
	baseOffsets := &goexec.Offsets{Field: goexec.FieldOffsets{
		goexec.RuntimeMemstatsNumGCPos:         uint64(0),
		goexec.RuntimeGCControllerGCPercentPos: uint64(8),
	}}

	mask := goRuntimeMetricMask(baseOffsets)
	assert.True(t, hasBaseGoRuntimeMetrics(mask))
	assert.NotZero(t, mask&goRuntimeMetricGCCyclesMask)
	assert.Zero(t, mask&goRuntimeMetricMemoryLimitMask)
	assert.NotZero(t, mask&goRuntimeMetricProcessorLimitMask)
	assert.NotZero(t, mask&goRuntimeMetricGOGCMask)
	assert.Zero(t, mask&goRuntimeMetricCPUTimeMask)
	assert.Zero(t, mask&goRuntimeMetricMemoryUsedMask)
	assert.Zero(t, mask&goRuntimeMetricMemoryAllocsMask)

	baseOffsets.Field[goexec.RuntimeGCControllerMemoryLimitPos] = uint64(16)
	assert.NotZero(t, goRuntimeMetricMask(baseOffsets)&goRuntimeMetricMemoryLimitMask)

	for _, field := range goRuntimeCPUTimeOffsetFields {
		baseOffsets.Field[field] = uint64(field)
	}
	assert.NotZero(t, goRuntimeMetricMask(baseOffsets)&goRuntimeMetricCPUTimeMask)

	delete(baseOffsets.Field, goRuntimeCPUTimeOffsetFields[0])
	assert.Zero(t, goRuntimeMetricMask(baseOffsets)&goRuntimeMetricCPUTimeMask)

	for _, field := range goRuntimeMemoryOffsetFields {
		baseOffsets.Field[field] = uint64(field)
	}
	memoryMask := goRuntimeMetricMask(baseOffsets)
	assert.NotZero(t, memoryMask&goRuntimeMetricMemoryUsedMask)
	assert.NotZero(t, memoryMask&goRuntimeMetricMemoryAllocsMask)

	delete(baseOffsets.Field, goRuntimeMemoryOffsetFields[0])
	memoryMask = goRuntimeMetricMask(baseOffsets)
	assert.Zero(t, memoryMask&goRuntimeMetricMemoryUsedMask)
	assert.Zero(t, memoryMask&goRuntimeMetricMemoryAllocsMask)

	delete(baseOffsets.Field, goexec.RuntimeMemstatsNumGCPos)
	assert.False(t, hasBaseGoRuntimeMetrics(goRuntimeMetricMask(baseOffsets)))
}

func TestGoRuntimeMetricMaskABI(t *testing.T) {
	assert.Equal(t, goRuntimeMetricGCCyclesMask, uint64(1<<0))
	assert.Equal(t, goRuntimeMetricMemoryLimitMask, uint64(1<<1))
	assert.Equal(t, goRuntimeMetricProcessorLimitMask, uint64(1<<2))
	assert.Equal(t, goRuntimeMetricGOGCMask, uint64(1<<3))
	assert.Equal(t, goRuntimeMetricCPUTimeMask, uint64(1<<4))
	assert.Equal(t, goRuntimeMetricMemoryUsedMask, uint64(1<<5))
	assert.Equal(t, goRuntimeMetricMemoryAllocsMask, uint64(1<<6))
}

func TestGoRuntimeMetricsUseHeapSnapshotProbe(t *testing.T) {
	disableContextPropagationForTest(t)

	tracer := &Tracer{
		currentBinaryIno: 1,
		goRuntimeMetricMaskByIno: map[uint64]uint64{
			1: goRuntimeMetricBaseMask,
			2: goRuntimeMetricBaseMask | goRuntimeMetricCPUTimeMask,
			3: goRuntimeMetricBaseMask | goRuntimeMetricMemoryUsedMask,
		},
	}

	probes := tracer.GoProbes()
	require.Contains(t, probes, "runtime.gcMarkDone")
	assert.NotContains(t, probes, "runtime.(*scavengeIndex).nextGen")

	tracer.currentBinaryIno = 2
	probes = tracer.GoProbes()
	require.Contains(t, probes, "runtime.gcMarkDone")
	assert.NotContains(t, probes, "runtime.(*scavengeIndex).nextGen")

	tracer.currentBinaryIno = 3
	probes = tracer.GoProbes()
	require.Contains(t, probes, "runtime.(*scavengeIndex).nextGen")
	assert.NotContains(t, probes, "runtime.gcMarkDone")
}

func TestGoRuntimeMetricsFallBackWhenHeapProbeIsMissing(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}
	disableContextPropagationForTest(t)

	var logs bytes.Buffer
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(&logs, nil))}
	fileInfo := exec.New(exec.Init{
		ELF:        currentExecutableELF(t),
		Ino:        1,
		Pid:        123,
		CmdExePath: "/test/server",
	})
	offsets := goRuntimeMetricOffsets()

	tracer.recordGoRuntimeMetricAvailability(fileInfo, offsets)
	tracer.ProcessBinary(fileInfo)

	mask := tracer.goRuntimeMetricMaskByIno[fileInfo.Ino()]
	assert.True(t, hasBaseGoRuntimeMetrics(mask))
	assert.NotZero(t, mask&goRuntimeMetricMemoryLimitMask)
	assert.NotZero(t, mask&goRuntimeMetricProcessorLimitMask)
	assert.NotZero(t, mask&goRuntimeMetricCPUTimeMask)
	assert.Zero(t, mask&goRuntimeMetricHeapSnapshotMask)

	probes := tracer.GoProbes()
	require.Contains(t, probes, goRuntimeMetricProbeSymbols[0])
	assert.NotContains(t, probes, goRuntimeMetricProbeSymbols[1])
	assert.Contains(t, logs.String(), "Go runtime heap metric symbol unresolved; using scalar fallback")
}

func TestGoRuntimeMetricsUseResolvedHeapProbe(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}
	disableContextPropagationForTest(t)

	tracer := &Tracer{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	fileInfo := exec.New(exec.Init{ELF: currentExecutableELF(t), Ino: 1})
	offsets := goRuntimeMetricOffsets()
	offsets.Funcs[goRuntimeMetricProbeSymbols[1]] = goexec.FuncOffsets{}

	tracer.recordGoRuntimeMetricAvailability(fileInfo, offsets)
	tracer.ProcessBinary(fileInfo)

	mask := tracer.goRuntimeMetricMaskByIno[fileInfo.Ino()]
	assert.NotZero(t, mask&goRuntimeMetricCPUTimeMask)
	assert.Equal(t, goRuntimeMetricHeapSnapshotMask, mask&goRuntimeMetricHeapSnapshotMask)

	probes := tracer.GoProbes()
	require.Contains(t, probes, goRuntimeMetricProbeSymbols[1])
	assert.NotContains(t, probes, goRuntimeMetricProbeSymbols[0])
}

func TestGoRuntimeMetricMaskRequiresSizeClassTableForAllocations(t *testing.T) {
	var logs bytes.Buffer
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(&logs, nil))}
	fileInfo := exec.New(exec.Init{Ino: 1, Pid: 123, CmdExePath: "/test/server"})
	mask := goRuntimeMetricBaseMask |
		goRuntimeMetricCPUTimeMask |
		goRuntimeMetricMemoryUsedMask |
		goRuntimeMetricMemoryAllocsMask

	got := tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, goexec.RuntimeMetricSymbols{})

	assert.Zero(t, got&goRuntimeMetricMemoryAllocsMask)
	assert.NotZero(t, got&goRuntimeMetricMemoryUsedMask)
	assert.NotZero(t, got&goRuntimeMetricCPUTimeMask)
	assert.True(t, hasBaseGoRuntimeMetrics(got))
	assert.Contains(t, logs.String(),
		"Go runtime size-class table symbol unresolved; disabling allocation metrics")
}

func TestGoRuntimeMetricMaskKeepsAllocationsWithSizeClassTable(t *testing.T) {
	var logs bytes.Buffer
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(&logs, nil))}
	fileInfo := exec.New(exec.Init{Ino: 1})
	mask := goRuntimeMetricBaseMask | goRuntimeMetricMemoryAllocsMask

	got := tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, goexec.RuntimeMetricSymbols{
		SizeClassToSizesAddr: 0x1234,
	})

	assert.Equal(t, mask, got)
	assert.Empty(t, logs.String())
}

func TestProcessBinarySelectsRecordedChannelOffsetState(t *testing.T) {
	tracer := &Tracer{
		goChannelOffsetsByIno: map[uint64]bool{
			1: true,
			2: false,
		},
	}

	tracer.ProcessBinary(exec.New(exec.Init{Ino: 1}))
	assert.True(t, tracer.goChannelLinkProbesEnabled())

	tracer.ProcessBinary(exec.New(exec.Init{Ino: 2}))
	assert.False(t, tracer.goChannelLinkProbesEnabled())

	tracer.ProcessBinary(nil)
	assert.False(t, tracer.goChannelLinkProbesEnabled())
}

func TestGoAutoSDKActivationProbeGroupRequiresSpanContextOffsets(t *testing.T) {
	setContextPropagationSupportForTest(t, true)

	tracer := &Tracer{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	fileInfo := exec.New(exec.Init{Ino: 1})
	tracer.recordGoAutoSDKActivationSupport(fileInfo, &goexec.Offsets{
		Field: goexec.FieldOffsets{
			goexec.SpanContextTraceIDPos:      uint64(0),
			goexec.SpanContextSpanIDPos:       uint64(16),
			goexec.AutoSDKSpanContextPos:      uint64(80),
			goexec.AutoSDKActivationSupported: uint64(1),
		},
	})
	tracer.ProcessBinary(fileInfo)

	assert.Empty(t, tracer.GoProbeGroups())

	tracer.recordGoAutoSDKActivationSupport(fileInfo, goAutoSDKSpanContextOffsets())
	groups := tracer.GoProbeGroups()
	require.Len(t, groups, 1)
	assert.Equal(t, goAutoSDKActivationPrerequisiteSymbols, groups[0].Prerequisites)
	expectedSymbols := []string{
		"go.opentelemetry.io/auto/sdk.(*tracer).start",
		"context.WithValue",
		"go.opentelemetry.io/auto/sdk.(*span).ended",
		"go.opentelemetry.io/otel/internal/global.(*tracer).newSpan",
	}
	assert.Equal(t, expectedSymbols, GoAutoSDKActivationProbeSymbols())
	require.Len(t, groups[0].Probes, len(expectedSymbols))
	for index, symbol := range expectedSymbols {
		assert.Equal(t, symbol, groups[0].Probes[index].Symbol)
	}
}

func TestGoAutoSDKActivationProbeGroupRequiresWriteUserSupport(t *testing.T) {
	setContextPropagationSupportForTest(t, false)

	tracer := &Tracer{
		log:                      slog.New(slog.NewTextHandler(io.Discard, nil)),
		currentBinaryIno:         1,
		goAutoSDKActivationByIno: map[uint64]bool{1: true},
	}

	assert.Empty(t, tracer.GoProbeGroups())
}

func TestResetGoAutoSDKActivationAttempts(t *testing.T) {
	var logs bytes.Buffer
	attempts := &recordingMapKeyDeleter{errors: map[uint8]error{
		0: ebpf.ErrKeyNotExist,
		1: errors.New("delete failed"),
	}}

	err := resetGoAutoSDKActivationAttempts(
		attempts,
		app.PID(123),
		456,
		slog.New(slog.NewTextHandler(&logs, nil)),
	)

	require.Error(t, err)
	assert.Equal(t, []BpfGoAutoActivationAttemptKeyT{
		{Generation: 456, Pid: 123, Attempt: 0},
		{Generation: 456, Pid: 123, Attempt: 1},
		{Generation: 456, Pid: 123, Attempt: 2},
	}, attempts.keys)
	assert.Contains(t, logs.String(), "delete failed")
	assert.Contains(t, logs.String(), "attempt=1")
	assert.NotContains(t, logs.String(), ebpf.ErrKeyNotExist.Error())
}

func TestGoAutoSDKTargetGenerationsAreStableUntilBlock(t *testing.T) {
	targets := newRecordingTargetMap()
	attempts := &recordingMapKeyDeleter{errors: map[uint8]error{}}
	active := map[app.PID]goAutoSDKTargetState{}
	var next uint64

	generation, err := activateGoAutoSDKTarget(targets, attempts, active, &next, 123, nil)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), generation)

	sameGeneration, err := activateGoAutoSDKTarget(targets, attempts, active, &next, 123, nil)
	require.NoError(t, err)
	assert.Equal(t, generation, sameGeneration)
	require.Len(t, targets.puts, 1)

	require.NoError(t, deactivateGoAutoSDKTarget(targets, attempts, active, 123, nil))
	assert.NotContains(t, active, app.PID(123))
	assert.Equal(t, []BpfGoAutoActivationAttemptKeyT{
		{Generation: generation, Pid: 123, Attempt: 0},
		{Generation: generation, Pid: 123, Attempt: 1},
		{Generation: generation, Pid: 123, Attempt: 2},
	}, attempts.keys)

	newGeneration, err := activateGoAutoSDKTarget(targets, attempts, active, &next, 123, nil)
	require.NoError(t, err)
	assert.NotEqual(t, generation, newGeneration)
}

func TestGoAutoSDKTargetEnablementFailureCanRetry(t *testing.T) {
	targets := newRecordingTargetMap()
	targets.putErrors = []error{errors.New("put failed"), nil}
	attempts := &recordingMapKeyDeleter{errors: map[uint8]error{}}
	active := map[app.PID]goAutoSDKTargetState{}
	var next uint64

	failedGeneration, err := activateGoAutoSDKTarget(targets, attempts, active, &next, 123, nil)
	require.Error(t, err)
	assert.Equal(t, uint64(1), failedGeneration)
	assert.NotContains(t, active, app.PID(123))

	generation, err := activateGoAutoSDKTarget(targets, attempts, active, &next, 123, nil)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), generation)
	assert.Equal(t, goAutoSDKTargetState{generation: generation}, active[123])
}

func TestGoAutoSDKTargetDeleteFailureFallsBackToZero(t *testing.T) {
	targets := newRecordingTargetMap()
	targets.entries[123] = 7
	targets.deleteErrors = []error{errors.New("delete failed")}
	attempts := &recordingMapKeyDeleter{errors: map[uint8]error{}}
	active := map[app.PID]goAutoSDKTargetState{123: {generation: 7}}

	require.NoError(t, deactivateGoAutoSDKTarget(targets, attempts, active, 123, nil))

	assert.Zero(t, targets.entries[123])
	assert.NotContains(t, active, app.PID(123))
	require.Len(t, attempts.keys, goAutoSDKActivationMaxAttempts)
	for _, key := range attempts.keys {
		assert.Equal(t, uint64(7), key.Generation)
	}
}

func TestGoAutoSDKTargetDisableFailureRequiresRotation(t *testing.T) {
	targets := newRecordingTargetMap()
	targets.entries[123] = 7
	targets.deleteErrors = []error{errors.New("delete failed")}
	targets.putErrors = []error{errors.New("put failed")}
	attempts := &recordingMapKeyDeleter{errors: map[uint8]error{}}
	active := map[app.PID]goAutoSDKTargetState{123: {generation: 7}}

	require.Error(t, deactivateGoAutoSDKTarget(targets, attempts, active, 123, nil))

	assert.Equal(t, goAutoSDKTargetState{generation: 7, needsRotation: true}, active[123])
	assert.Empty(t, attempts.keys)
}

func TestGoAutoSDKTargetRecoveryPublishesBeforeRetiredAttemptCleanup(t *testing.T) {
	var operations []string
	targets := newRecordingTargetMap()
	targets.entries[123] = 7
	targets.operations = &operations
	attempts := &recordingMapKeyDeleter{
		errors:     map[uint8]error{},
		operations: &operations,
	}
	active := map[app.PID]goAutoSDKTargetState{
		123: {generation: 7, needsRotation: true},
	}
	next := uint64(7)

	generation, err := activateGoAutoSDKTarget(targets, attempts, active, &next, 123, nil)
	require.NoError(t, err)

	assert.Equal(t, uint64(8), generation)
	assert.Equal(t, uint64(8), targets.entries[123])
	assert.Equal(t, goAutoSDKTargetState{generation: 8}, active[123])
	assert.Equal(t, []string{
		"target-put",
		"attempt-delete",
		"attempt-delete",
		"attempt-delete",
	}, operations)
	for _, key := range attempts.keys {
		assert.Equal(t, uint64(7), key.Generation)
	}
}

func TestGoAutoSDKTargetRecoveryRetriesFailedPublication(t *testing.T) {
	targets := newRecordingTargetMap()
	targets.entries[123] = 7
	targets.putErrors = []error{errors.New("put failed"), nil}
	attempts := &recordingMapKeyDeleter{errors: map[uint8]error{}}
	active := map[app.PID]goAutoSDKTargetState{
		123: {generation: 7, needsRotation: true},
	}
	next := uint64(7)

	failedGeneration, err := activateGoAutoSDKTarget(
		targets,
		attempts,
		active,
		&next,
		123,
		nil,
	)
	require.Error(t, err)
	assert.Equal(t, uint64(8), failedGeneration)
	assert.Equal(t, goAutoSDKTargetState{generation: 7, needsRotation: true}, active[123])
	assert.Empty(t, attempts.keys)

	generation, err := activateGoAutoSDKTarget(targets, attempts, active, &next, 123, nil)
	require.NoError(t, err)
	assert.Equal(t, uint64(9), generation)
	assert.Equal(t, goAutoSDKTargetState{generation: 9}, active[123])
	require.Len(t, attempts.keys, goAutoSDKActivationMaxAttempts)
}

func TestGoAutoSDKTargetRecoveryCleanupFailureRetainsCleanupDebt(t *testing.T) {
	targets := newRecordingTargetMap()
	targets.entries[123] = 7
	attempts := &recordingMapKeyDeleter{errors: map[uint8]error{
		1: errors.New("delete failed"),
	}}
	active := map[app.PID]goAutoSDKTargetState{
		123: {generation: 7, needsRotation: true},
	}
	next := uint64(7)

	generation, err := activateGoAutoSDKTarget(targets, attempts, active, &next, 123, nil)
	require.NoError(t, err)

	assert.Equal(t, uint64(8), generation)
	assert.Equal(t, goAutoSDKTargetState{
		generation:         8,
		cleanupGenerations: []uint64{7},
	}, active[123])
	require.Len(t, attempts.keys, goAutoSDKActivationMaxAttempts)
}

func TestGoAutoSDKTargetRecoveryRetriesCleanupDebt(t *testing.T) {
	targets := newRecordingTargetMap()
	targets.entries[123] = 7
	attempts := &recordingMapKeyDeleter{
		errorsByCall: map[int]error{1: errors.New("delete failed")},
	}
	active := map[app.PID]goAutoSDKTargetState{
		123: {generation: 7, needsRotation: true},
	}
	next := uint64(7)

	generation, err := activateGoAutoSDKTarget(targets, attempts, active, &next, 123, nil)
	require.NoError(t, err)
	assert.Equal(t, goAutoSDKTargetState{
		generation:         generation,
		cleanupGenerations: []uint64{7},
	}, active[123])

	sameGeneration, err := activateGoAutoSDKTarget(targets, attempts, active, &next, 123, nil)
	require.NoError(t, err)

	assert.Equal(t, generation, sameGeneration)
	assert.Equal(t, goAutoSDKTargetState{generation: generation}, active[123])
	require.Len(t, targets.puts, 1)
	require.Len(t, attempts.keys, 2*goAutoSDKActivationMaxAttempts)
}

func TestGoAutoSDKTargetDuplicateBlockRetriesCleanupDebt(t *testing.T) {
	targets := newRecordingTargetMap()
	targets.entries[123] = 7
	attempts := &recordingMapKeyDeleter{
		errorsByCall: map[int]error{1: errors.New("delete failed")},
	}
	active := map[app.PID]goAutoSDKTargetState{123: {generation: 7}}

	require.Error(t, deactivateGoAutoSDKTarget(targets, attempts, active, 123, nil))
	assert.Equal(t, goAutoSDKTargetState{
		cleanupGenerations: []uint64{7},
	}, active[123])

	require.NoError(t, deactivateGoAutoSDKTarget(targets, attempts, active, 123, nil))

	assert.NotContains(t, active, app.PID(123))
	require.Len(t, attempts.keys, 2*goAutoSDKActivationMaxAttempts)
}

func TestGoAutoSDKTargetDuplicateBlockRetriesDirtyDisable(t *testing.T) {
	targets := newRecordingTargetMap()
	targets.entries[123] = 7
	targets.deleteErrors = []error{errors.New("delete failed"), nil}
	targets.putErrors = []error{errors.New("put failed")}
	attempts := &recordingMapKeyDeleter{errors: map[uint8]error{}}
	active := map[app.PID]goAutoSDKTargetState{123: {generation: 7}}

	require.Error(t, deactivateGoAutoSDKTarget(targets, attempts, active, 123, nil))
	require.NoError(t, deactivateGoAutoSDKTarget(targets, attempts, active, 123, nil))

	assert.NotContains(t, active, app.PID(123))
	assert.NotContains(t, targets.entries, uint32(123))
	require.Len(t, attempts.keys, goAutoSDKActivationMaxAttempts)
}

func TestGoAutoSDKTargetGenerationWrapSkipsZero(t *testing.T) {
	targets := newRecordingTargetMap()
	attempts := &recordingMapKeyDeleter{errors: map[uint8]error{}}
	active := map[app.PID]goAutoSDKTargetState{}
	next := ^uint64(0)

	generation, err := activateGoAutoSDKTarget(targets, attempts, active, &next, 123, nil)
	require.NoError(t, err)

	assert.Equal(t, uint64(1), generation)
	assert.Equal(t, goAutoSDKTargetState{generation: 1}, active[123])
}

type recordingMapKeyDeleter struct {
	keys         []BpfGoAutoActivationAttemptKeyT
	errors       map[uint8]error
	errorsByCall map[int]error
	operations   *[]string
}

func (m *recordingMapKeyDeleter) Delete(key any) error {
	attemptKey, ok := key.(*BpfGoAutoActivationAttemptKeyT)
	if !ok {
		panic("unexpected activation attempt key")
	}

	call := len(m.keys)
	m.keys = append(m.keys, *attemptKey)
	if m.operations != nil {
		*m.operations = append(*m.operations, "attempt-delete")
	}
	if err := m.errorsByCall[call]; err != nil {
		return err
	}
	return m.errors[attemptKey.Attempt]
}

type targetMapPut struct {
	key   uint32
	value uint64
}

type recordingTargetMap struct {
	entries      map[uint32]uint64
	puts         []targetMapPut
	deletes      []uint32
	putErrors    []error
	deleteErrors []error
	operations   *[]string
}

func newRecordingTargetMap() *recordingTargetMap {
	return &recordingTargetMap{entries: map[uint32]uint64{}}
}

func (m *recordingTargetMap) Put(key, value any) error {
	targetKey := *key.(*uint32)
	targetValue := *value.(*uint64)
	m.puts = append(m.puts, targetMapPut{key: targetKey, value: targetValue})
	if m.operations != nil {
		*m.operations = append(*m.operations, "target-put")
	}
	index := len(m.puts) - 1
	if index < len(m.putErrors) && m.putErrors[index] != nil {
		return m.putErrors[index]
	}
	m.entries[targetKey] = targetValue
	return nil
}

func (m *recordingTargetMap) Delete(key any) error {
	targetKey := *key.(*uint32)
	m.deletes = append(m.deletes, targetKey)
	index := len(m.deletes) - 1
	if index < len(m.deleteErrors) && m.deleteErrors[index] != nil {
		return m.deleteErrors[index]
	}
	if _, ok := m.entries[targetKey]; !ok {
		return ebpf.ErrKeyNotExist
	}
	delete(m.entries, targetKey)
	return nil
}

func goChannelOffsets() *goexec.Offsets {
	return &goexec.Offsets{Field: goexec.FieldOffsets{
		goexec.HchanQcountPos:   uint64(0),
		goexec.HchanDataqsizPos: uint64(8),
		goexec.HchanSendxPos:    uint64(48),
		goexec.HchanRecvxPos:    uint64(56),
	}}
}

func goAutoSDKSpanContextOffsets() *goexec.Offsets {
	return &goexec.Offsets{Field: goexec.FieldOffsets{
		goexec.SpanContextTraceIDPos:      uint64(0),
		goexec.SpanContextSpanIDPos:       uint64(16),
		goexec.SpanContextTraceFlagsPos:   uint64(24),
		goexec.AutoSDKSpanContextPos:      uint64(80),
		goexec.AutoSDKActivationSupported: uint64(1),
	}}
}

func goRuntimeMetricOffsets() *goexec.Offsets {
	offsets := &goexec.Offsets{
		Funcs: map[string]goexec.FuncOffsets{
			goRuntimeMetricProbeSymbols[0]: {},
		},
		Field: goexec.FieldOffsets{},
	}
	for _, field := range goRuntimeMetricOffsetFields {
		offsets.Field[field] = uint64(field)
	}
	return offsets
}

func currentExecutableELF(t *testing.T) *elf.File {
	t.Helper()

	executable, err := os.Executable()
	require.NoError(t, err)

	elfFile, err := elf.Open(executable)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, elfFile.Close())
	})
	return elfFile
}

func assertNoGoChannelLinkProbes(t *testing.T, probes map[string][]*ebpfcommon.ProbeDesc) {
	t.Helper()

	for _, symbol := range GoChannelLinkProbeSymbols() {
		assert.NotContains(t, probes, symbol)
	}
}

func disableContextPropagationForTest(t *testing.T) {
	t.Helper()

	previous := ebpfcommon.IntegrityModeOverride
	ebpfcommon.IntegrityModeOverride = true
	t.Cleanup(func() {
		ebpfcommon.IntegrityModeOverride = previous
	})
}

func setContextPropagationSupportForTest(t *testing.T, supported bool) {
	t.Helper()

	previousOverride := ebpfcommon.IntegrityModeOverride
	previousProbe := supportsContextPropagationWithProbe
	ebpfcommon.IntegrityModeOverride = false
	supportsContextPropagationWithProbe = func(*slog.Logger) bool {
		return supported
	}
	t.Cleanup(func() {
		ebpfcommon.IntegrityModeOverride = previousOverride
		supportsContextPropagationWithProbe = previousProbe
	})
}
