// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

func TestGoOffsetsMapKey(t *testing.T) {
	const inode = uint64(123)

	testCases := []struct {
		name      string
		statDev   uint64
		kernelDev uint64
	}{
		{
			name:      "regular device",
			statDev:   0xfc01,
			kernelDev: 0xfc00001,
		},
		{
			name:      "large minor number",
			statDev:   0x1000ed,
			kernelDev: 0x1ed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fileInfo := exec.New(exec.Init{
				Dev: tc.statDev,
				Ino: inode,
			})

			assert.Equal(t, executableIdentity{
				Dev: tc.kernelDev,
				Ino: inode,
			}, goOffsetsMapKey(fileInfo))
		})
	}
}

func TestSetFramerPaddingOffsetUsesExactLayout(t *testing.T) {
	const symbol = "golang.org/x/net/http2.(*Framer).WriteHeaders"
	offTable := BpfOffTableT{}
	offsets := &goexec.Offsets{Funcs: map[string][]goexec.FuncOffsets{
		symbol: {
			{Symbol: "fork/vendor/" + symbol, PadStart: 0x20, PadOffset: 0x70},
			{Symbol: symbol, PadStart: 0x30, PadOffset: 0x80},
		},
	}}

	setFramerPaddingOffset(&offTable, offsets, symbol, goexec.FramerPadLengthStackPos)
	assert.Equal(t, uint64(0x80), offTable.Table[goexec.FramerPadLengthStackPos])

	offsets.Funcs[symbol] = offsets.Funcs[symbol][:1]
	offTable.Table[goexec.FramerPadLengthStackPos] = missingGoOffset
	setFramerPaddingOffset(&offTable, offsets, symbol, goexec.FramerPadLengthStackPos)
	assert.Equal(t, missingGoOffset, offTable.Table[goexec.FramerPadLengthStackPos])
}

func TestGoChannelLinkProbesRequireChannelOffsets(t *testing.T) {
	disableContextPropagationForTest(t)

	tracer := &Tracer{
		log:                          slog.New(slog.NewTextHandler(io.Discard, nil)),
		goChannelOffsetsByExecutable: map[executableIdentity]bool{},
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

func TestGoRuntimeHistogramAvailabilityRequiresSupportedLayout(t *testing.T) {
	offsets := &goexec.Offsets{Field: goexec.FieldOffsets{
		goexec.RuntimeTimeHistogramUnderflowPos: uint64(1280),
		goexec.RuntimeTimeHistogramOverflowPos:  uint64(1288),
	}}

	mask := goRuntimeMetricMask(offsets)
	assert.Zero(t, mask&goRuntimeMetricGCPauseHistogramMask)
	assert.Zero(t, mask&goRuntimeMetricScheduleDurationHistogramMask)

	offsets.Field[goexec.RuntimeSchedTimeToRunPos] = uint64(640)
	mask = goRuntimeMetricMask(offsets)
	assert.Zero(t, mask&goRuntimeMetricGCPauseHistogramMask)
	assert.NotZero(t, mask&goRuntimeMetricScheduleDurationHistogramMask)

	offsets.Field[goexec.RuntimeSchedSTWTotalTimeGCPos] = uint64(4520)
	mask = goRuntimeMetricMask(offsets)
	assert.NotZero(t, mask&goRuntimeMetricGCPauseHistogramMask)
	assert.NotZero(t, mask&goRuntimeMetricScheduleDurationHistogramMask)

	delete(offsets.Field, goexec.RuntimeTimeHistogramUnderflowPos)
	mask = goRuntimeMetricMask(offsets)
	assert.Zero(t, mask&goRuntimeMetricGCPauseHistogramMask)
	assert.Zero(t, mask&goRuntimeMetricScheduleDurationHistogramMask)
}

func TestGoRuntimeHistogramAvailabilityRejectsUnsupportedLayout(t *testing.T) {
	const supportedBucketCount = 160
	const bucketSize = uint64(8)

	offsets := &goexec.Offsets{Field: goexec.FieldOffsets{
		goexec.RuntimeMemstatsNumGCPos:          uint64(0),
		goexec.RuntimeGCControllerGCPercentPos:  uint64(8),
		goexec.RuntimeSchedTimeToRunPos:         uint64(320),
		goexec.RuntimeSchedSTWTotalTimeGCPos:    uint64(4224),
		goexec.RuntimeTimeHistogramUnderflowPos: uint64(supportedBucketCount-1) * bucketSize,
		goexec.RuntimeTimeHistogramOverflowPos:  uint64(supportedBucketCount) * bucketSize,
	}}

	mask := goRuntimeMetricMask(offsets)
	assert.True(t, hasBaseGoRuntimeMetrics(mask))
	assert.Zero(t, mask&goRuntimeMetricHistogramMask)

	offsets.Field[goexec.RuntimeTimeHistogramUnderflowPos] = uint64(supportedBucketCount) * bucketSize
	mask = goRuntimeMetricMask(offsets)
	assert.True(t, hasBaseGoRuntimeMetrics(mask))
	assert.Zero(t, mask&goRuntimeMetricHistogramMask)

	offsets.Field[goexec.RuntimeTimeHistogramOverflowPos] = uint64(supportedBucketCount+1) * bucketSize

	mask = goRuntimeMetricMask(offsets)
	assert.True(t, hasBaseGoRuntimeMetrics(mask))
	assert.Equal(t, goRuntimeMetricHistogramMask, mask&goRuntimeMetricHistogramMask)
}

func TestGoRuntimeMetricMaskABI(t *testing.T) {
	assert.Equal(t, goRuntimeMetricGCCyclesMask, uint64(1<<0))
	assert.Equal(t, goRuntimeMetricMemoryLimitMask, uint64(1<<1))
	assert.Equal(t, goRuntimeMetricProcessorLimitMask, uint64(1<<2))
	assert.Equal(t, goRuntimeMetricGOGCMask, uint64(1<<3))
	assert.Equal(t, goRuntimeMetricCPUTimeMask, uint64(1<<4))
	assert.Equal(t, goRuntimeMetricMemoryUsedMask, uint64(1<<5))
	assert.Equal(t, goRuntimeMetricMemoryAllocsMask, uint64(1<<6))
	assert.Equal(t, goRuntimeMetricGCPauseHistogramMask, uint64(1<<7))
	assert.Equal(t, goRuntimeMetricScheduleDurationHistogramMask, uint64(1<<8))
	assert.Equal(t, goRuntimeMetricGoroutineCountMask, uint64(1<<9))
	assert.Equal(t, goRuntimeMetricMemoryGCGoalMask, uint64(1<<10))
}

func TestGoRuntimeMetricTargetABIAppendsGoroutineMetadata(t *testing.T) {
	var target BpfGoRuntimeMetricTargetT

	assert.Equal(t, uintptr(104), unsafe.Sizeof(target))
	assert.Equal(t, uintptr(40), unsafe.Offsetof(target.SizeClassToSizesAddr))
	assert.Equal(t, uintptr(48), unsafe.Offsetof(target.SchedAddr))
	assert.Equal(t, uintptr(56), unsafe.Offsetof(target.AllglenAddr))
	assert.Equal(t, uintptr(64), unsafe.Offsetof(target.AllpAddr))
	assert.Equal(t, uintptr(72), unsafe.Offsetof(target.GoroutineCountIncludesSystem))
}

func TestGoRuntimeMetricTargetABIAppendsGCGoalCache(t *testing.T) {
	var target BpfGoRuntimeMetricTargetT

	assert.Equal(t, uintptr(104), unsafe.Sizeof(target))
	assert.Equal(t, uintptr(80), unsafe.Offsetof(target.GcGoalSource))
	assert.Equal(t, uintptr(88), unsafe.Offsetof(target.GcGoal))
	assert.Equal(t, uintptr(96), unsafe.Offsetof(target.Generation))
}

func TestGoExecutableKeyABI(t *testing.T) {
	var key BpfGoExecutableKeyT

	assert.Equal(t, uintptr(16), unsafe.Sizeof(key))
	assert.Equal(t, uintptr(0), unsafe.Offsetof(key.Dev))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(key.Ino))
}

func TestGoRuntimeGCGoalSourceSelection(t *testing.T) {
	tests := []struct {
		name                  string
		offsets               *goexec.Offsets
		goalArgumentSupported bool
		want                  goRuntimeGCGoalSource
	}{
		{name: "missing metadata", offsets: nil, want: goRuntimeGCGoalSourceNone},
		{name: "probe symbol with compatible signature", offsets: &goexec.Offsets{Funcs: map[string][]goexec.FuncOffsets{
			goRuntimeMetricGCGoalSymbol: {{}},
		}}, goalArgumentSupported: true, want: goRuntimeGCGoalSourcePaceScavengerArgument},
		{name: "probe symbol with incompatible signature", offsets: &goexec.Offsets{Funcs: map[string][]goexec.FuncOffsets{
			goRuntimeMetricGCGoalSymbol: {{}},
		}}, want: goRuntimeGCGoalSourceNone},
		{name: "heap goal field preferred when both sources are present", offsets: &goexec.Offsets{
			Funcs: map[string][]goexec.FuncOffsets{goRuntimeMetricGCGoalSymbol: {{}}},
			Field: goexec.FieldOffsets{goexec.RuntimeGCControllerHeapGoalPos: uint64(112)},
		}, want: goRuntimeGCGoalSourceHeapGoalField},
		{name: "sources missing", offsets: &goexec.Offsets{}, want: goRuntimeGCGoalSourceNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, selectGoRuntimeGCGoalSource(tt.offsets, tt.goalArgumentSupported))
		})
	}
}

func TestGoRuntimeGCGoalProbeAttachedOnlyForPaceScavengerSource(t *testing.T) {
	disableContextPropagationForTest(t)
	firstIdentity := executableIdentity{Ino: 1}
	tracer := &Tracer{
		currentBinary: firstIdentity,
		goRuntimeMetricMaskByExecutable: map[executableIdentity]uint64{
			firstIdentity: goRuntimeMetricBaseMask | goRuntimeMetricMemoryGCGoalMask,
		},
		goRuntimeGCGoalSourceByExecutable: map[executableIdentity]goRuntimeGCGoalSource{
			firstIdentity: goRuntimeGCGoalSourcePaceScavengerArgument,
			{Ino: 2}:      goRuntimeGCGoalSourceHeapGoalField,
			{Ino: 3}:      goRuntimeGCGoalSourceNone,
		},
	}
	tracer.bpfObjects.ObiUprobeGoRuntimeGcGoal = &ebpf.Program{}

	probes := tracer.GoProbes()
	require.Contains(t, probes, goRuntimeMetricGCGoalSymbol)
	require.NotNil(t, probes[goRuntimeMetricGCGoalSymbol][0].Start)
	assert.Contains(t, probes, goRuntimeMetricGCMarkDoneSymbol)

	for _, ino := range []uint64{2, 3} {
		tracer.currentBinary = executableIdentity{Ino: ino}
		probes = tracer.GoProbes()
		assert.NotContains(t, probes, goRuntimeMetricGCGoalSymbol)
		assert.Contains(t, probes, goRuntimeMetricGCMarkDoneSymbol)
	}
}

func TestGoRuntimeGoroutineCountAvailabilityRequiresAllOffsets(t *testing.T) {
	offsets := goRuntimeMetricOffsets()
	delete(offsets.Field, goexec.RuntimeGListSizePos)

	assert.False(t, hasGoRuntimeGoroutineCountOffsets(offsets, false, true))
	assert.False(t, hasGoRuntimeGoroutineCountOffsets(offsets, true, true))
}

func TestGoRuntimeGoroutineCountAvailabilityRequiresNgsysOnlyBeforeGo126(t *testing.T) {
	offsets := goRuntimeMetricOffsets()
	delete(offsets.Field, goexec.RuntimeSchedNgSysPos)

	assert.False(t, hasGoRuntimeGoroutineCountOffsets(offsets, false, false), "unknown mode must fail closed")
	assert.False(t, hasGoRuntimeGoroutineCountOffsets(offsets, false, true), "Go 1.25 requires sched.ngsys")
	assert.True(t, hasGoRuntimeGoroutineCountOffsets(offsets, true, true), "Go 1.26 does not read sched.ngsys")

	offsets.Field[goexec.RuntimeSchedNgSysPos] = uint64(0)
	assert.True(t, hasGoRuntimeGoroutineCountOffsets(offsets, false, true))
}

func TestGoRuntimeMetricsUseHeapSnapshotProbe(t *testing.T) {
	disableContextPropagationForTest(t)

	tracer := &Tracer{
		currentBinary: executableIdentity{Ino: 1},
		goRuntimeMetricMaskByExecutable: map[executableIdentity]uint64{
			{Ino: 1}: goRuntimeMetricBaseMask,
			{Ino: 2}: goRuntimeMetricBaseMask | goRuntimeMetricCPUTimeMask,
			{Ino: 3}: goRuntimeMetricBaseMask | goRuntimeMetricMemoryUsedMask,
		},
	}

	probes := tracer.GoProbes()
	require.Contains(t, probes, "runtime.gcMarkDone")
	assert.NotContains(t, probes, "runtime.(*scavengeIndex).nextGen")

	tracer.currentBinary = executableIdentity{Ino: 2}
	probes = tracer.GoProbes()
	require.Contains(t, probes, "runtime.gcMarkDone")
	assert.NotContains(t, probes, "runtime.(*scavengeIndex).nextGen")

	tracer.currentBinary = executableIdentity{Ino: 3}
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

	mask := tracer.goRuntimeMetricMaskByExecutable[executableIdentity{Ino: fileInfo.Ino()}]
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

	var logs bytes.Buffer
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(
		&logs,
		&slog.HandlerOptions{Level: slog.LevelDebug},
	))}
	fileInfo := exec.New(exec.Init{ELF: currentExecutableELF(t), Ino: 1})
	offsets := goRuntimeMetricOffsets()
	offsets.Funcs[goRuntimeMetricProbeSymbols[1]] = []goexec.FuncOffsets{{}}

	tracer.recordGoRuntimeMetricAvailability(fileInfo, offsets)
	tracer.ProcessBinary(fileInfo)

	mask := tracer.goRuntimeMetricMaskByExecutable[executableIdentity{Ino: fileInfo.Ino()}]
	assert.NotZero(t, mask&goRuntimeMetricCPUTimeMask)
	assert.Equal(t, goRuntimeMetricHeapSnapshotMask, mask&goRuntimeMetricHeapSnapshotMask)
	assert.NotZero(t, mask&goRuntimeMetricGoroutineCountMask)
	assert.NotZero(t, mask&goRuntimeMetricMemoryGCGoalMask)
	assert.Contains(t, logs.String(), "goroutine_count_available=true")

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

func TestGoRuntimeMetricMaskRequiresGoroutineSymbolsAndModeOnlyForCount(t *testing.T) {
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	fileInfo := exec.New(exec.Init{Ino: 1})
	mask := goRuntimeMetricBaseMask | goRuntimeMetricCPUTimeMask | goRuntimeMetricGoroutineCountMask
	symbols := goexec.RuntimeMetricSymbols{
		SchedAddr:               0x1000,
		AllgLenAddr:             0x2000,
		AllpAddr:                0x3000,
		GoroutineCountModeKnown: true,
	}

	assert.Equal(t, mask, tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, symbols))

	symbols.AllgLenAddr = 0
	got := tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, symbols)
	assert.Zero(t, got&goRuntimeMetricGoroutineCountMask)
	assert.NotZero(t, got&goRuntimeMetricCPUTimeMask)

	symbols.AllgLenAddr = 0x2000
	symbols.GoroutineCountModeKnown = false
	got = tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, symbols)
	assert.Zero(t, got&goRuntimeMetricGoroutineCountMask)
	assert.NotZero(t, got&goRuntimeMetricCPUTimeMask)
}

func TestGoRuntimeMetricMaskRequiresSchedulerSymbolForHistograms(t *testing.T) {
	var logs bytes.Buffer
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(&logs, nil))}
	fileInfo := exec.New(exec.Init{Ino: 1, Pid: 123, CmdExePath: "/test/server"})
	mask := goRuntimeMetricBaseMask |
		goRuntimeMetricCPUTimeMask |
		goRuntimeMetricGCPauseHistogramMask |
		goRuntimeMetricScheduleDurationHistogramMask

	got := tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, goexec.RuntimeMetricSymbols{})

	assert.Zero(t, got&goRuntimeMetricHistogramMask)
	assert.NotZero(t, got&goRuntimeMetricCPUTimeMask)
	assert.True(t, hasBaseGoRuntimeMetrics(got))
	assert.Contains(t, logs.String(),
		"Go runtime scheduler symbol unresolved; disabling histogram metrics")
}

func TestGoRuntimeMetricMaskKeepsHistogramsWithSchedulerSymbol(t *testing.T) {
	var logs bytes.Buffer
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(&logs, nil))}
	fileInfo := exec.New(exec.Init{Ino: 1})
	mask := goRuntimeMetricBaseMask | goRuntimeMetricHistogramMask

	got := tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, goexec.RuntimeMetricSymbols{
		SchedAddr: 0x1234,
	})

	assert.Equal(t, mask, got)
	assert.Empty(t, logs.String())
}

func TestProcessBinarySelectsRecordedChannelOffsetState(t *testing.T) {
	tracer := &Tracer{
		goChannelOffsetsByExecutable: map[executableIdentity]bool{
			{Ino: 1}: true,
			{Ino: 2}: false,
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
	tracer.recordGoChannelOffsetAvailability(fileInfo, &goexec.Offsets{})
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
	assert.False(t, groups[0].Probes[0].ProcessScoped)
	assert.False(t, groups[0].Probes[1].ProcessScoped)
	assert.False(t, groups[0].Probes[2].ProcessScoped)
	assert.True(t, groups[0].Probes[3].ProcessScoped)
}

func TestGoAutoSDKActivationAvailabilityUsesExecutableIdentity(t *testing.T) {
	setContextPropagationSupportForTest(t, true)

	tracer := &Tracer{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	supported := exec.New(exec.Init{Dev: 1, Ino: 1})
	unsupported := exec.New(exec.Init{Dev: 2, Ino: 1})

	tracer.recordGoAutoSDKActivationSupport(supported, goAutoSDKSpanContextOffsets())
	tracer.recordGoChannelOffsetAvailability(supported, &goexec.Offsets{})
	require.Len(t, tracer.GoProbeGroups(), 1)

	tracer.recordGoAutoSDKActivationSupport(unsupported, &goexec.Offsets{})
	tracer.recordGoChannelOffsetAvailability(unsupported, &goexec.Offsets{})
	assert.Empty(t, tracer.GoProbeGroups())

	tracer.ProcessBinary(supported)
	require.Len(t, tracer.GoProbeGroups(), 1)
	tracer.ProcessBinary(unsupported)
	assert.Empty(t, tracer.GoProbeGroups())
}

func TestGoAutoSDKActivationProbeGroupRequiresWriteUserSupport(t *testing.T) {
	setContextPropagationSupportForTest(t, false)

	identity := executableIdentity{Ino: 1}
	tracer := &Tracer{
		log:                             slog.New(slog.NewTextHandler(io.Discard, nil)),
		currentBinary:                   identity,
		goAutoSDKActivationByExecutable: map[executableIdentity]bool{identity: true},
	}

	assert.Empty(t, tracer.GoProbeGroups())
}

func TestHeaderPropagationRespectsModeAndWriteUserSupport(t *testing.T) {
	tests := []struct {
		name               string
		mode               config.ContextPropagationMode
		writeUser          bool
		wireEnabled        bool
		writeProbesEnabled bool
	}{
		{name: "disabled supported", mode: config.ContextPropagationDisabled, writeUser: true},
		{name: "tcp supported", mode: config.ContextPropagationTCP, writeUser: true},
		{name: "headers supported", mode: config.ContextPropagationHeaders, writeUser: true, wireEnabled: true, writeProbesEnabled: true},
		{name: "all supported", mode: config.ContextPropagationAll, writeUser: true, wireEnabled: true, writeProbesEnabled: true},
		{name: "disabled unsupported", mode: config.ContextPropagationDisabled},
		{name: "tcp unsupported", mode: config.ContextPropagationTCP},
		{name: "headers unsupported", mode: config.ContextPropagationHeaders, wireEnabled: true},
		{name: "all unsupported", mode: config.ContextPropagationAll, wireEnabled: true},
	}

	headerProbeSymbols := []string{
		"net/http.Header.writeSubset",
		"golang.org/x/net/http2.(*Framer).WriteHeaders",
		"net/http.(*http2Framer).WriteHeaders",
	}
	tracingProbeSymbols := []string{
		"net/http.(*Transport).roundTrip",
		"google.golang.org/grpc.(*ClientConn).Invoke",
		"google.golang.org/grpc.(*ClientConn).NewStream",
		"google.golang.org/grpc/internal/transport.(*http2Client).NewStream",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setContextPropagationSupportForTest(t, tt.writeUser)

			tracer := &Tracer{
				cfg: &config.EBPFTracer{ContextPropagation: tt.mode},
				log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			constants := tracer.constants()
			assert.Equal(t, tt.wireEnabled, constants["g_bpf_header_propagation"])
			assert.Equal(t, tt.writeUser, constants["g_bpf_probe_write_user_enabled"])

			probes := tracer.GoProbes()
			for _, symbol := range headerProbeSymbols {
				if tt.writeProbesEnabled {
					assert.Contains(t, probes, symbol)
				} else {
					assert.NotContains(t, probes, symbol)
				}
			}
			for _, symbol := range tracingProbeSymbols {
				assert.Contains(t, probes, symbol)
			}
		})
	}
}

func TestHTTP2PreflushProbeGroupsRespectPropagation(t *testing.T) {
	setContextPropagationSupportForTest(t, true)

	tracer := &Tracer{
		cfg: &config.EBPFTracer{ContextPropagation: config.ContextPropagationHeaders},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	groups := tracer.GoProbeGroups()
	require.Len(t, groups, 2)
	assert.Equal(t, "go_http2_xnet_preflush", groups[0].Name)
	assert.Equal(t, "go_http2_stdlib_preflush", groups[1].Name)
	for _, group := range groups {
		require.Len(t, group.Probes, 2)
		assert.True(t, group.Probes[0].Probe.UsePadStart)
		assert.False(t, group.Probes[1].Probe.UsePadStart)
	}

	tracer.cfg.ContextPropagation = config.ContextPropagationDisabled
	assert.Empty(t, tracer.GoProbeGroups())
}

func TestManualSpanProbesDoNotRequireWriteUserSupport(t *testing.T) {
	setContextPropagationSupportForTest(t, false)

	tracer := &Tracer{
		cfg: &config.EBPFTracer{},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	probes := tracer.GoProbes()
	assert.Contains(t, probes, "go.opentelemetry.io/otel/internal/global.(*tracer).Start")
	assert.Contains(t, probes, "go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).End")
}

func TestGoAutoSDKActivationProbeGroupIgnoresPropagationMode(t *testing.T) {
	setContextPropagationSupportForTest(t, true)

	identity := executableIdentity{Ino: 1}
	tracer := &Tracer{
		cfg:                             &config.EBPFTracer{ContextPropagation: config.ContextPropagationDisabled},
		log:                             slog.New(slog.NewTextHandler(io.Discard, nil)),
		currentBinary:                   identity,
		goAutoSDKActivationByExecutable: map[executableIdentity]bool{identity: true},
	}

	assert.Len(t, tracer.GoProbeGroups(), 1)
}

func TestGoAutoSDKActivationUprobeOptionsArePIDScoped(t *testing.T) {
	options := goAutoSDKActivationUprobeOptions(
		goAutoSDKActivationProbe{offset: 0x1234},
		app.PID(456),
	)

	assert.Equal(t, uint64(0x1234), options.Address)
	assert.Equal(t, 456, options.PID)
	assert.Zero(t, options.Cookie)
}

func TestDuplicateAllowPIDKeepsOneActivationLink(t *testing.T) {
	activationLink := &activationCountingCloser{}
	attachCalls := 0
	tracer := activationLifecycleTestTracer(func(app.PID) (uint64, error) {
		return 100, nil
	})
	tracer.attachGoAutoSDKProbe = func(
		goAutoSDKActivationProbe,
		app.PID,
		uint64,
		uint64,
		uint64,
	) (io.Closer, error) {
		attachCalls++
		return activationLink, nil
	}
	fileInfo := exec.New(exec.Init{Dev: 5, Ino: 10})

	tracer.AllowPID(123, 1, fileInfo)
	generation := tracer.goAutoSDKTargets[123].generation
	tracer.AllowPID(123, 1, fileInfo)

	assert.Equal(t, 1, attachCalls)
	assert.Len(t, tracer.goAutoSDKActivationLinks, 1)
	assert.Equal(t, uint64(1), generation)

	handled, err := tracer.handleGoAutoSDKActivationEvent(
		activationEventRecord(t, 123, generation),
	)
	require.NoError(t, err)
	assert.True(t, handled)
	assert.Equal(t, int32(1), activationLink.closes.Load())

	tracer.AllowPID(123, 1, fileInfo)
	assert.Equal(t, 1, attachCalls)
	assert.Empty(t, tracer.goAutoSDKActivationLinks)
}

func TestAllowPIDRetriesProcessIdentityBeforeAttaching(t *testing.T) {
	identityReads := 0
	tracer := activationLifecycleTestTracer(func(app.PID) (uint64, error) {
		identityReads++
		if identityReads == 1 {
			return 0, errors.New("process stat unavailable")
		}
		return 100, nil
	})
	attachCalls := 0
	tracer.attachGoAutoSDKProbe = func(
		goAutoSDKActivationProbe,
		app.PID,
		uint64,
		uint64,
		uint64,
	) (io.Closer, error) {
		attachCalls++
		return &activationCountingCloser{}, nil
	}
	fileInfo := exec.New(exec.Init{Dev: 5, Ino: 10})

	tracer.AllowPID(123, 1, fileInfo)
	generation := tracer.goAutoSDKTargets[123].generation
	assert.Empty(t, tracer.goAutoSDKActivationLinks)

	tracer.AllowPID(123, 1, fileInfo)

	assert.NotEqual(t, generation, tracer.goAutoSDKTargets[123].generation)
	assert.Equal(t, 1, attachCalls)
	assert.Len(t, tracer.goAutoSDKActivationLinks, 1)
}

func TestRegisterProcessScopedGoProbeAttachesPendingTarget(t *testing.T) {
	activationLink := &activationCountingCloser{}
	attachedOffset := uint64(0)
	tracer := activationLinkTestTracer(7)
	tracer.attachGoAutoSDKProbe = func(
		probe goAutoSDKActivationProbe,
		pid app.PID,
		dev uint64,
		ino uint64,
		startTime uint64,
	) (io.Closer, error) {
		assert.Equal(t, app.PID(123), pid)
		assert.Equal(t, uint64(5), dev)
		assert.Equal(t, uint64(10), ino)
		assert.Zero(t, startTime)
		attachedOffset = probe.offset
		return activationLink, nil
	}

	tracer.RegisterProcessScopedGoProbe(5, 10, ebpfcommon.GoProbe{
		ProcessScoped: true,
		Probe: &ebpfcommon.ProbeDesc{
			Start:       &ebpf.Program{},
			StartOffset: 0x1234,
		},
	})

	assert.Equal(t, uint64(0x1234), attachedOffset)
	assert.Contains(t, tracer.goAutoSDKActivationLinks,
		goAutoSDKActivationLinkKey{pid: 123, generation: 7})
}

func TestProcessScopedProbesSeparateSameInodeAcrossDevices(t *testing.T) {
	tracer := activationLinkTestTracer(7)
	tracer.goAutoSDKTargets[456] = goAutoSDKTargetState{
		generation: 8,
		dev:        6,
		ino:        10,
	}
	type attachedProbe struct {
		dev    uint64
		offset uint64
	}
	attached := map[app.PID]attachedProbe{}
	tracer.attachGoAutoSDKProbe = func(
		probe goAutoSDKActivationProbe,
		pid app.PID,
		dev uint64,
		_ uint64,
		_ uint64,
	) (io.Closer, error) {
		attached[pid] = attachedProbe{dev: dev, offset: probe.offset}
		return &activationCountingCloser{}, nil
	}

	tracer.RegisterProcessScopedGoProbe(5, 10, ebpfcommon.GoProbe{
		ProcessScoped: true,
		Probe: &ebpfcommon.ProbeDesc{
			Start:       &ebpf.Program{},
			StartOffset: 0x50,
		},
	})
	tracer.RegisterProcessScopedGoProbe(6, 10, ebpfcommon.GoProbe{
		ProcessScoped: true,
		Probe: &ebpfcommon.ProbeDesc{
			Start:       &ebpf.Program{},
			StartOffset: 0x60,
		},
	})

	assert.Equal(t, attachedProbe{dev: 5, offset: 0x50}, attached[123])
	assert.Equal(t, attachedProbe{dev: 6, offset: 0x60}, attached[456])
}

func TestUnregisterProcessScopedGoProbeClosesOnlyMatchingInode(t *testing.T) {
	firstLink := &activationCountingCloser{}
	secondLink := &activationCountingCloser{}
	tracer := activationLinkTestTracer(7)
	firstExecutable := goAutoSDKExecutableKey{dev: 5, ino: 10}
	secondExecutable := goAutoSDKExecutableKey{dev: 6, ino: 20}
	tracer.goAutoSDKActivationProbes[secondExecutable] = goAutoSDKActivationProbe{}
	tracer.goAutoSDKActivationLinks = map[goAutoSDKActivationLinkKey]goAutoSDKActivationLink{
		{pid: 123, generation: 7}: {
			executable: firstExecutable,
			link:       &onceCloser{closer: firstLink},
		},
		{pid: 456, generation: 8}: {
			executable: secondExecutable,
			link:       &onceCloser{closer: secondLink},
		},
	}

	tracer.UnregisterProcessScopedGoProbes(5, 10)

	assert.Equal(t, int32(1), firstLink.closes.Load())
	assert.Zero(t, secondLink.closes.Load())
	assert.NotContains(t, tracer.goAutoSDKActivationProbes, firstExecutable)
	assert.Contains(t, tracer.goAutoSDKActivationProbes, secondExecutable)
	assert.Contains(t, tracer.goAutoSDKActivationLinks,
		goAutoSDKActivationLinkKey{pid: 456, generation: 8})
}

func TestGoAutoSDKActivationIgnoresStaleGenerationEvent(t *testing.T) {
	staleLink := &activationCountingCloser{}
	currentLink := &activationCountingCloser{}
	tracer := activationLinkTestTracer(8)
	executable := goAutoSDKExecutableKey{dev: 5, ino: 10}
	tracer.goAutoSDKActivationLinks = map[goAutoSDKActivationLinkKey]goAutoSDKActivationLink{
		{pid: 123, generation: 7}: {
			executable: executable,
			link:       &onceCloser{closer: staleLink},
		},
		{pid: 123, generation: 8}: {
			executable: executable,
			link:       &onceCloser{closer: currentLink},
		},
	}

	handled, err := tracer.handleGoAutoSDKActivationEvent(
		activationEventRecord(t, 123, 7),
	)

	require.NoError(t, err)
	assert.True(t, handled)
	assert.Zero(t, staleLink.closes.Load())
	assert.Zero(t, currentLink.closes.Load())
	assert.Len(t, tracer.goAutoSDKActivationLinks, 2)
	assert.False(t, tracer.goAutoSDKTargets[123].activated)

	handled, err = tracer.handleGoAutoSDKActivationEvent(
		activationEventRecord(t, 123, 8),
	)
	require.NoError(t, err)
	assert.True(t, handled)
	assert.Zero(t, staleLink.closes.Load())
	assert.Equal(t, int32(1), currentLink.closes.Load())
}

func TestGoAutoSDKActivationHandlesPIDReuse(t *testing.T) {
	oldLink := &activationCountingCloser{}
	newLink := &activationCountingCloser{}
	startTime := uint64(100)
	tracer := activationLifecycleTestTracer(func(app.PID) (uint64, error) {
		return startTime, nil
	})
	links := []*activationCountingCloser{oldLink, newLink}
	tracer.attachGoAutoSDKProbe = func(
		goAutoSDKActivationProbe,
		app.PID,
		uint64,
		uint64,
		uint64,
	) (io.Closer, error) {
		link := links[0]
		links = links[1:]
		return link, nil
	}
	fileInfo := exec.New(exec.Init{Dev: 5, Ino: 10})

	tracer.AllowPID(123, 1, fileInfo)
	oldGeneration := tracer.goAutoSDKTargets[123].generation
	startTime = 200
	tracer.AllowPID(123, 1, fileInfo)
	newGeneration := tracer.goAutoSDKTargets[123].generation

	handled, err := tracer.handleGoAutoSDKActivationEvent(
		activationEventRecord(t, 123, oldGeneration),
	)
	require.NoError(t, err)
	assert.True(t, handled)
	assert.Equal(t, int32(1), oldLink.closes.Load())
	assert.Zero(t, newLink.closes.Load())
	assert.NotEqual(t, oldGeneration, newGeneration)
	assert.Contains(t, tracer.goAutoSDKActivationLinks,
		goAutoSDKActivationLinkKey{pid: 123, generation: newGeneration})
}

func TestGoAutoSDKActivationSupportsProcessesSharingInode(t *testing.T) {
	links := map[app.PID]*activationCountingCloser{
		123: {},
		456: {},
	}
	tracer := activationLifecycleTestTracer(func(pid app.PID) (uint64, error) {
		return uint64(pid), nil
	})
	tracer.attachGoAutoSDKProbe = func(
		_ goAutoSDKActivationProbe,
		pid app.PID,
		_ uint64,
		_ uint64,
		_ uint64,
	) (io.Closer, error) {
		return links[pid], nil
	}
	fileInfo := exec.New(exec.Init{Dev: 5, Ino: 10})
	tracer.AllowPID(123, 1, fileInfo)
	tracer.AllowPID(456, 1, fileInfo)
	firstGeneration := tracer.goAutoSDKTargets[123].generation
	secondGeneration := tracer.goAutoSDKTargets[456].generation

	handled, err := tracer.handleGoAutoSDKActivationEvent(
		activationEventRecord(t, 123, firstGeneration),
	)

	require.NoError(t, err)
	assert.True(t, handled)
	assert.Equal(t, int32(1), links[123].closes.Load())
	assert.Zero(t, links[456].closes.Load())
	assert.NotContains(t, tracer.goAutoSDKActivationLinks,
		goAutoSDKActivationLinkKey{pid: 123, generation: firstGeneration})
	assert.Contains(t, tracer.goAutoSDKActivationLinks,
		goAutoSDKActivationLinkKey{pid: 456, generation: secondGeneration})

	handled, err = tracer.handleGoAutoSDKActivationEvent(
		activationEventRecord(t, 456, secondGeneration),
	)
	require.NoError(t, err)
	assert.True(t, handled)
	assert.Equal(t, int32(1), links[456].closes.Load())
}

func TestGoAutoSDKActivationCleanupRaceClosesLinkOnce(t *testing.T) {
	for range 25 {
		activationLink := &activationCountingCloser{}
		tracer := activationLifecycleTestTracer(func(app.PID) (uint64, error) {
			return 100, nil
		})
		tracer.attachGoAutoSDKProbe = func(
			goAutoSDKActivationProbe,
			app.PID,
			uint64,
			uint64,
			uint64,
		) (io.Closer, error) {
			return activationLink, nil
		}
		tracer.AllowPID(123, 1, exec.New(exec.Init{Dev: 5, Ino: 10}))
		generation := tracer.goAutoSDKTargets[123].generation
		record := activationEventRecord(t, 123, generation)

		var wg sync.WaitGroup
		wg.Add(4)
		go func() {
			defer wg.Done()
			_, _ = tracer.handleGoAutoSDKActivationEvent(record)
		}()
		go func() {
			defer wg.Done()
			tracer.UnregisterProcessScopedGoProbes(5, 10)
		}()
		go func() {
			defer wg.Done()
			_ = tracer.closeAllGoAutoSDKActivationLinks()
		}()
		go func() {
			defer wg.Done()
			tracer.BlockPID(123, 1)
		}()
		wg.Wait()

		assert.Equal(t, int32(1), activationLink.closes.Load())
		assert.Empty(t, tracer.goAutoSDKActivationLinks)
	}
}

func TestBlockPIDClosesActivationLinkBeforePIDReuse(t *testing.T) {
	firstLink := &activationCountingCloser{}
	secondLink := &activationCountingCloser{}
	tracer := activationLifecycleTestTracer(func(pid app.PID) (uint64, error) {
		return uint64(pid), nil
	})
	links := []*activationCountingCloser{firstLink, secondLink}
	tracer.attachGoAutoSDKProbe = func(
		goAutoSDKActivationProbe,
		app.PID,
		uint64,
		uint64,
		uint64,
	) (io.Closer, error) {
		link := links[0]
		links = links[1:]
		return link, nil
	}
	fileInfo := exec.New(exec.Init{Dev: 5, Ino: 10})

	tracer.AllowPID(123, 1, fileInfo)
	firstGeneration := tracer.goAutoSDKTargets[123].generation
	tracer.BlockPID(123, 1)
	tracer.AllowPID(123, 1, fileInfo)
	secondGeneration := tracer.goAutoSDKTargets[123].generation

	assert.Equal(t, int32(1), firstLink.closes.Load())
	assert.Zero(t, secondLink.closes.Load())
	assert.NotEqual(t, firstGeneration, secondGeneration)
	assert.Contains(t, tracer.goAutoSDKActivationLinks,
		goAutoSDKActivationLinkKey{pid: 123, generation: secondGeneration})
}

func TestRunClosesActivationLinksWhenRingbufIsAlreadyForwarded(t *testing.T) {
	activationLink := &activationCountingCloser{}
	tracer := activationLinkTestTracer(7)
	tracer.cfg = &config.EBPFTracer{}
	tracer.pidsFilter = &ebpfcommon.IdentityPidsFilter{}
	tracer.goAutoSDKActivationLinks = map[goAutoSDKActivationLinkKey]goAutoSDKActivationLink{
		{pid: 123, generation: 7}: {
			executable: goAutoSDKExecutableKey{dev: 5, ino: 10},
			link:       &onceCloser{closer: activationLink},
		},
	}
	eventContext := ebpfcommon.NewEBPFEventContext()
	eventContext.SharedRingBuffer = blockingSharedForwarder{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tracer.Run(ctx, eventContext, nil)

	assert.Equal(t, int32(1), activationLink.closes.Load())
	assert.Empty(t, tracer.goAutoSDKActivationLinks)
}

func TestSetEventContextRegistersActivationHandlerBeforeRun(t *testing.T) {
	activationLink := &activationCountingCloser{}
	tracer := activationLinkTestTracer(7)
	tracer.goAutoSDKActivationLinks = map[goAutoSDKActivationLinkKey]goAutoSDKActivationLink{
		{pid: 123, generation: 7}: {
			executable: goAutoSDKExecutableKey{dev: 5, ino: 10},
			link:       &onceCloser{closer: activationLink},
		},
	}
	eventContext := ebpfcommon.NewEBPFEventContext()
	tracer.SetEventContext(eventContext)

	handled, err := eventContext.HandleInternalEvent(
		activationEventRecord(t, 123, 7),
	)

	require.NoError(t, err)
	assert.True(t, handled)
	assert.Equal(t, int32(1), activationLink.closes.Load())
}

type blockingSharedForwarder struct{}

func (blockingSharedForwarder) AlreadyForwarded(ctx context.Context) {
	<-ctx.Done()
}

func activationLinkTestTracer(generation uint64) *Tracer {
	return &Tracer{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		goAutoSDKTargets: map[app.PID]goAutoSDKTargetState{
			123: {generation: generation, dev: 5, ino: 10},
		},
		goAutoSDKActivationProbes: map[goAutoSDKExecutableKey]goAutoSDKActivationProbe{
			{dev: 5, ino: 10}: {},
		},
		goAutoSDKActivationLinks: map[goAutoSDKActivationLinkKey]goAutoSDKActivationLink{},
	}
}

func activationLifecycleTestTracer(
	startTime func(app.PID) (uint64, error),
) *Tracer {
	return &Tracer{
		log:              slog.New(slog.NewTextHandler(io.Discard, nil)),
		pidsFilter:       &ebpfcommon.IdentityPidsFilter{},
		goAutoSDKTargets: map[app.PID]goAutoSDKTargetState{},
		goAutoSDKActivationProbes: map[goAutoSDKExecutableKey]goAutoSDKActivationProbe{
			{dev: 5, ino: 10}: {},
		},
		goAutoSDKActivationLinks:  map[goAutoSDKActivationLinkKey]goAutoSDKActivationLink{},
		goAutoSDKTargetMap:        newRecordingTargetMap(),
		goAutoSDKAttemptMap:       &recordingMapKeyDeleter{errors: map[uint8]error{}},
		goAutoSDKProcessStartTime: startTime,
	}
}

func activationEventRecord(
	t *testing.T,
	pid app.PID,
	generation uint64,
) *ringbuf.Record {
	t.Helper()

	var raw bytes.Buffer
	require.NoError(t, binary.Write(&raw, binary.LittleEndian, goAutoSDKActivationEvent{
		Type:       ebpfcommon.EventTypeGoAutoActivated,
		Pid:        uint32(pid),
		Generation: generation,
	}))
	return &ringbuf.Record{RawSample: raw.Bytes()}
}

type activationCountingCloser struct {
	closes atomic.Int32
}

func (c *activationCountingCloser) Close() error {
	c.closes.Add(1)
	return nil
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
		Funcs: map[string][]goexec.FuncOffsets{
			goRuntimeMetricProbeSymbols[0]: {{}},
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
