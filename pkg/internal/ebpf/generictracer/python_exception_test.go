// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	discexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	cpythonruntime "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestPythonExceptionBPFObjects(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)

	program, ok := spec.Programs[BpfProgObiUprobePythonErrSetObject]
	require.True(t, ok)
	assert.Equal(t, "uprobe/python_err_set_object", program.SectionName)

	for name, kind := range map[string]ebpf.MapType{
		BpfMapPythonExceptionProcs:   ebpf.Hash,
		BpfMapPythonExceptionPending: ebpf.LRUHash,
	} {
		m, ok := spec.Maps[name]
		require.True(t, ok, name)
		assert.Equal(t, kind, m.Type, name)
		assert.Equal(t, ebpfconvenience.PinInternal, m.Pinning, name)
	}

	ebpfcommon.ShrinkPythonExceptionMaps(spec)
	assert.Equal(t, uint32(1), spec.Maps[BpfMapPythonExceptionProcs].MaxEntries)
	assert.Equal(t, uint32(1), spec.Maps[BpfMapPythonExceptionPending].MaxEntries)
}

func TestPythonExceptionControllerDisabled(t *testing.T) {
	cfg := obi.DefaultConfig
	tracer := &Tracer{cfg: &cfg, log: tlog()}
	controller := newPythonExceptionController(tracer)
	require.Nil(t, controller)

	service := discexec.New(discexec.Init{Service: svc.Attrs{
		SDKLanguage: svc.InstrumentablePython,
		Exceptions:  services.ExceptionsConfig{Enabled: true},
	}})
	controller.allow(1, service)
	controller.block(1)
	controller.close()
}

func TestPythonExceptionProc(t *testing.T) {
	proc := pythonExceptionProc(&cpythonruntime.ExceptionLayout{
		Minor: 12, MainInterpreter: 0x10, CodeType: 0x20, UnicodeType: 0x30, TupleType: 0x40,
		StopIteration: 0x50, StopAsyncIteration: 0x60, GeneratorExit: 0x70,
		TstateInterp: 16, TstateFrame: 56, CFrameCurrentFrame: 8, FrameIsCFrame: true,
		FrameCode: 1, FramePrevious: 2, FrameInstr: 3, FrameOwner: 4, FrameOwnerCStack: 5,
		CodeAdaptive: 192, CodeFilename: 112, CodeName: 128, CodeLinetable: 136, CodeFirstlineno: 68,
		TupleItems: 24, UnicodeASCIIData: 40, UnicodeCompactData: 56, ExceptionTraceback: 40,
		TstateExcInfo: 104, ErrItemValue: 6, ErrItemPrevious: 7,
	})

	assert.Equal(t, [7]uint64{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70}, [7]uint64{
		proc.MainInterp, proc.CodeType, proc.UnicodeType, proc.TupleType,
		proc.StopIteration, proc.StopAsyncIteration, proc.GeneratorExit,
	})
	assert.Equal(t, [14]uint8{16, 56, 8, 1, 1, 2, 3, 4, 5, 24, 40, 104, 6, 7}, [14]uint8{
		proc.TstateInterp, proc.TstateFrame, proc.CframeCurrentFrame, proc.FrameIsCframe,
		proc.FrameCode, proc.FramePrevious, proc.FrameInstr, proc.FrameOwner, proc.FrameOwnerCstack,
		proc.TupleItems, proc.ExceptionTraceback, proc.TstateExcInfo, proc.ErrItemValue, proc.ErrItemPrevious,
	})
	assert.Equal(t, uint16(192), proc.CodeAdaptive)
	assert.Equal(t, [7]uint8{12, 112, 128, 136, 68, 40, 56}, [7]uint8{
		proc.Layout.Minor, proc.Layout.CodeFilename, proc.Layout.CodeName, proc.Layout.CodeLinetable,
		proc.Layout.CodeFirstlineno, proc.Layout.UnicodeAsciiData, proc.Layout.UnicodeCompactData,
	})
}

func TestPythonExceptionControllerClosed(t *testing.T) {
	// A late discovery notification must not access maps after tracer shutdown.
	controller := &pythonExceptionController{}
	controller.close()
	service := discexec.New(discexec.Init{Service: svc.Attrs{
		SDKLanguage: svc.InstrumentablePython,
		Exceptions:  services.ExceptionsConfig{Enabled: true},
	}})
	require.NotPanics(t, func() { controller.allow(1, service) })
	assert.Empty(t, controller.processes)
}
