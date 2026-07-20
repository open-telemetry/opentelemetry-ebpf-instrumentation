// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer

import (
	"bytes"
	"debug/elf"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func goChannelOffsets() *goexec.Offsets {
	return &goexec.Offsets{Field: goexec.FieldOffsets{
		goexec.HchanQcountPos:   uint64(0),
		goexec.HchanDataqsizPos: uint64(8),
		goexec.HchanSendxPos:    uint64(48),
		goexec.HchanRecvxPos:    uint64(56),
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
