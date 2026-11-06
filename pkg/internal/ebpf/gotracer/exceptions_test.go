// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer

import (
	"io"
	"os"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/obi"
)

func exceptionsConfig(enabled bool) *obi.Config {
	cfg := &obi.Config{}
	cfg.Exceptions.Enabled = enabled
	cfg.Logs.Protocol = otelcfg.ProtocolDebug
	return cfg
}

func exceptionGroupSymbols(t *testing.T, tracer *Tracer) []string {
	t.Helper()
	var symbols []string
	for _, group := range tracer.GoProbeGroups() {
		for _, probe := range group.Probes {
			if isGoExceptionSymbol(probe.Symbol) {
				require.True(t, probe.ProcessScoped, "%s is attached per process", probe.Symbol)
				symbols = append(symbols, probe.Symbol)
			}
		}
	}
	return symbols
}

func TestGoExceptionProbesAreProcessScoped(t *testing.T) {
	disableContextPropagationForTest(t)

	disabled := New(nil, exceptionsConfig(false), nil)
	assert.Empty(t, exceptionGroupSymbols(t, disabled), "global capture is off")
	assert.Equal(t, false, disabled.constants(0)["g_exceptions_enabled"])

	tracer := New(nil, exceptionsConfig(true), nil)
	assert.Equal(t, true, tracer.constants(0)["g_exceptions_enabled"])
	assert.Equal(t, []string{
		goErrorfSymbol, goLegacyErrorfSymbol, goPanicSymbol, goCleanupSymbol,
	}, exceptionGroupSymbols(t, tracer), "fmt.errorf registers before fmt.Errorf")
	for _, symbol := range GoExceptionProbeSymbols() {
		assert.NotContains(t, tracer.GoProbes(), symbol, "not attached to the whole executable")
	}
}

func TestGoExceptionCleanupWithTraceContext(t *testing.T) {
	cfg := exceptionsConfig(true)
	cfg.EBPF.PopulateTraceContext = true
	tracer := New(nil, cfg, nil)

	assert.Contains(t, tracer.GoProbes(), goCleanupSymbol)
	assert.NotContains(t, exceptionGroupSymbols(t, tracer), goCleanupSymbol)
}

func TestGoExceptionCleanupFollowsCaptureSources(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags uint8
		want  int
	}{
		{"disabled", 0, 0},
		{"neither source", goExceptionPIDEnabled, 0},
		{"panics", goExceptionPIDEnabled | goExceptionPIDPanics, 1},
		{"errors", goExceptionPIDEnabled | goExceptionPIDFormattedErrors, 1},
		{"both", goExceptionPIDEnabled | goExceptionPIDPanics | goExceptionPIDFormattedErrors, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tracer := New(nil, exceptionsConfig(true), nil)
			links := &exceptionLinks{attached: map[app.PID][]uint64{}, open: map[app.PID]int{}}
			tracer.attachGoExceptionProbe = links.attach
			executable := executableIdentity{Dev: 7, Ino: 11}
			tracer.RegisterProcessScopedGoProbe(executable.Dev, executable.Ino, exceptionProbe(goCleanupSymbol, 40))
			tracer.trackExceptionProcess(1, executable, tc.flags)
			require.Equal(t, tc.want, links.open[1])

			tracer.trackExceptionProcess(1, executable, goExceptionPIDEnabled)
			require.Zero(t, links.open[1], "disabling both sources detaches cleanup")
		})
	}
}

// exceptionLinks records the probes attached per process, by offset.
type exceptionLinks struct {
	attached map[app.PID][]uint64
	open     map[app.PID]int
}

type exceptionLink struct {
	links *exceptionLinks
	pid   app.PID
}

func (l exceptionLink) Close() error {
	l.links.open[l.pid]--
	return nil
}

func (l *exceptionLinks) attach(pid app.PID, _ executableIdentity, probe *ebpfcommon.ProbeDesc) ([]io.Closer, error) {
	offset := probe.StartOffset
	if probe.End != nil {
		offset = probe.ReturnOffsets[0]
	}
	l.attached[pid] = append(l.attached[pid], offset)
	l.open[pid]++
	return []io.Closer{exceptionLink{links: l, pid: pid}}, nil
}

func exceptionProbe(symbol string, offset uint64) ebpfcommon.GoProbe {
	probe := &ebpfcommon.ProbeDesc{End: &ebpf.Program{}, ReturnOffsets: []uint64{offset}}
	if symbol == goPanicSymbol || symbol == goCleanupSymbol {
		probe = &ebpfcommon.ProbeDesc{Start: &ebpf.Program{}, StartOffset: offset}
	}
	return ebpfcommon.GoProbe{Symbol: symbol, Probe: probe, ProcessScoped: true}
}

func TestGoExceptionProbesFollowEachProcess(t *testing.T) {
	tracer := New(nil, exceptionsConfig(true), nil)
	links := &exceptionLinks{attached: map[app.PID][]uint64{}, open: map[app.PID]int{}}
	tracer.attachGoExceptionProbe = links.attach
	shared, other := executableIdentity{Dev: 7, Ino: 11}, executableIdentity{Dev: 7, Ino: 12}

	// a process can be selected before or after its executable is committed
	tracer.trackExceptionProcess(1, shared, goExceptionPIDEnabled|goExceptionPIDPanics|goExceptionPIDFormattedErrors)
	tracer.RegisterProcessScopedGoProbe(shared.Dev, shared.Ino, exceptionProbe(goErrorfSymbol, 10))
	tracer.RegisterProcessScopedGoProbe(shared.Dev, shared.Ino, exceptionProbe(goLegacyErrorfSymbol, 20))
	tracer.RegisterProcessScopedGoProbe(shared.Dev, shared.Ino, exceptionProbe(goPanicSymbol, 30))
	tracer.RegisterProcessScopedGoProbe(other.Dev, other.Ino, exceptionProbe(goPanicSymbol, 40))
	tracer.trackExceptionProcess(2, shared, goExceptionPIDEnabled|goExceptionPIDPanics|goExceptionPIDFormattedErrors)
	tracer.trackExceptionProcess(2, shared, goExceptionPIDEnabled|goExceptionPIDPanics|goExceptionPIDFormattedErrors)

	assert.Equal(t, map[app.PID][]uint64{1: {10, 30}, 2: {10, 30}}, links.attached,
		"fmt.Errorf is skipped next to fmt.errorf, and processes that do not capture get no probes")

	tracer.untrackExceptionProcess(1)
	assert.Zero(t, links.open[1])

	tracer.UnregisterProcessScopedGoProbes(shared.Dev, shared.Ino)
	assert.Zero(t, links.open[2])
	tracer.RegisterProcessScopedGoProbe(shared.Dev, shared.Ino, exceptionProbe(goPanicSymbol, 50))
	assert.Equal(t, []uint64{10, 30, 50}, links.attached[2], "a replaced executable attaches again")
	assert.Equal(t, 1, links.open[2])
}

func TestCloseReleasesActiveGoExceptionResources(t *testing.T) {
	previous := goSymbols
	goSymbols = ebpfcommon.NewGoSymbolRegistry()
	t.Cleanup(func() {
		_ = goSymbols.Close()
		goSymbols = previous
	})

	tracer := New(nil, exceptionsConfig(true), nil)
	links := &exceptionLinks{attached: map[app.PID][]uint64{}, open: map[app.PID]int{}}
	tracer.attachGoExceptionProbe = links.attach
	fileInfo := exceptionTestFileInfo(t)
	executable := executableIdentity{Dev: fileInfo.Dev(), Ino: fileInfo.Ino()}
	tracer.RegisterProcessScopedGoProbe(executable.Dev, executable.Ino, exceptionProbe(goPanicSymbol, 30))
	tracer.trackExceptionProcess(1, executable, goExceptionPIDEnabled|goExceptionPIDPanics)
	require.NoError(t, goSymbols.AddExecutable(fileInfo))
	goSymbols.BindPID(1, executable.Dev, executable.Ino, 0)
	unrelated := exceptionTestFileInfo(t)
	require.NoError(t, goSymbols.AddExecutable(unrelated))
	goSymbols.BindPID(2, unrelated.Dev(), unrelated.Ino(), 0)
	_, err := goSymbols.Frames(1, nil)
	require.NoError(t, err)
	require.Equal(t, 1, links.open[1])

	require.NoError(t, tracer.Close())

	assert.Zero(t, links.open[1], "close the active exception probe")
	assert.Empty(t, tracer.exceptionProcesses, "retire the tracer's process state")
	_, err = goSymbols.Frames(1, nil)
	require.ErrorContains(t, err, "go symbol binding not found", "remove the PID binding")
	require.NoError(t, tracer.Close())
	assert.Zero(t, links.open[1], "repeated shutdown must not close the probe twice")
	_, err = goSymbols.Frames(2, nil)
	assert.NoError(t, err, "preserve another tracer's symbols")
}

func exceptionTestFileInfo(t *testing.T) *exec.FileInfo {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "executable")
	require.NoError(t, err)
	info, err := file.Stat()
	require.NoError(t, err)
	require.NoError(t, file.Close())
	stat := info.Sys().(*syscall.Stat_t)
	return exec.New(exec.Init{ProExeLinkPath: file.Name(), Dev: normalizeDeviceID(stat.Dev), Ino: stat.Ino})
}

func TestPrivateExceptionEvents(t *testing.T) {
	spec := func() *ebpf.CollectionSpec {
		return &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
			BpfMapExceptionEvents: {Type: ebpf.RingBuf, MaxEntries: 1 << 18, Pinning: 100},
		}}
	}

	enabled := spec()
	New(nil, exceptionsConfig(true), nil).privateExceptionEvents(enabled)
	require.Equal(t, ebpf.PinNone, enabled.Maps[BpfMapExceptionEvents].Pinning)
	require.Equal(t, uint32(1<<18), enabled.Maps[BpfMapExceptionEvents].MaxEntries)

	disabled := spec()
	New(nil, exceptionsConfig(false), nil).privateExceptionEvents(disabled)
	require.Equal(t, ebpf.PinNone, disabled.Maps[BpfMapExceptionEvents].Pinning)
	require.Equal(t, uint32(os.Getpagesize()), disabled.Maps[BpfMapExceptionEvents].MaxEntries)
}

func TestGoExceptionProbeSelection(t *testing.T) {
	tracer := New(nil, exceptionsConfig(true), nil)
	links := &exceptionLinks{attached: map[app.PID][]uint64{}, open: map[app.PID]int{}}
	tracer.attachGoExceptionProbe = links.attach
	executable := executableIdentity{Dev: 7, Ino: 11}
	panicOnly := goExceptionPIDEnabled | goExceptionPIDPanics
	errorsOnly := goExceptionPIDEnabled | goExceptionPIDFormattedErrors
	tracer.trackExceptionProcess(1, executable, panicOnly)
	tracer.RegisterProcessScopedGoProbe(executable.Dev, executable.Ino, exceptionProbe(goErrorfSymbol, 10))
	tracer.RegisterProcessScopedGoProbe(executable.Dev, executable.Ino, exceptionProbe(goPanicSymbol, 30))
	tracer.trackExceptionProcess(2, executable, errorsOnly)
	require.Equal(t, []uint64{30}, links.attached[1])
	require.Equal(t, []uint64{10}, links.attached[2])
	tracer.trackExceptionProcess(1, executable, errorsOnly)
	require.Equal(t, 1, links.open[1])
	require.Equal(t, []uint64{30, 10}, links.attached[1])
	tracer.UnregisterProcessScopedGoProbes(executable.Dev, executable.Ino)
	require.Zero(t, links.open[1])
	require.Zero(t, links.open[2])
	tracer.RegisterProcessScopedGoProbe(executable.Dev, executable.Ino, exceptionProbe(goPanicSymbol, 50))
	require.Zero(t, links.open[1])
	require.Zero(t, links.open[2])
	tracer.RegisterProcessScopedGoProbe(executable.Dev, executable.Ino, exceptionProbe(goErrorfSymbol, 60))
	require.Equal(t, 1, links.open[1])
	require.Equal(t, 1, links.open[2])
	tracer.trackExceptionProcess(1, executable, goExceptionPIDEnabled)
	require.Zero(t, links.open[1])
}
