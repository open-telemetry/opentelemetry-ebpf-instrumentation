// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"debug/elf"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type probeDescMap map[string][]*ebpfcommon.ProbeDesc

type testCase struct {
	startOffset   uint64
	returnOffsets []uint64
}

func makeProbeDescMap(cases map[string]testCase) probeDescMap {
	m := make(probeDescMap)

	for probe := range cases {
		m[probe] = []*ebpfcommon.ProbeDesc{{}}
	}

	return m
}

func TestGatherOffsets(t *testing.T) {
	reader := bytes.NewReader(testData())
	assert.NotNil(t, reader)

	testCases := expectedValues()
	probes := makeProbeDescMap(testCases)

	elfFile, err := elf.NewFile(reader)
	require.NoError(t, err)
	defer elfFile.Close()

	err = gatherOffsetsImpl(elfFile, probes, "libbsd.so", slog.Default())
	require.NoError(t, err)

	for probeName, probeArr := range probes {
		assert.NotEmpty(t, probeArr)
		desc := probeArr[0]
		expected := testCases[probeName]

		assert.Equal(t, expected.startOffset, desc.StartOffset)
		assert.Equal(t, expected.returnOffsets, desc.ReturnOffsets)
	}
}

func TestGatherOffsetsResolvesSymbolSubstring(t *testing.T) {
	reader := bytes.NewReader(testData())
	assert.NotNil(t, reader)

	probes := probeDescMap{
		"setprog": {{
			SymbolMatcher: ebpfcommon.SymbolMatcherContains,
		}},
	}

	elfFile, err := elf.NewFile(reader)
	require.NoError(t, err)
	defer elfFile.Close()

	err = gatherOffsetsImpl(elfFile, probes, "libbsd.so", slog.Default())
	require.NoError(t, err)

	desc := probes["setprog"][0]
	expected := expectedValues()["setprogname"]
	assert.Equal(t, expected.startOffset, desc.StartOffset)
	assert.Equal(t, expected.returnOffsets, desc.ReturnOffsets)
	assert.False(t, desc.Skip)
}

func TestApplyResolvedSymbolOffsetsKeepsStartOffsetWhenReturnScanFails(t *testing.T) {
	probe := &ebpfcommon.ProbeDesc{}
	sym := procs.Sym{Name: "jvm", Off: 0x1234}

	applyResolvedSymbolOffsets(probe, sym, nil, errors.New("decode failed"), "jvm", "libjvm.so", slog.Default())

	assert.Equal(t, uint64(0x1234), probe.StartOffset)
	assert.Empty(t, probe.ReturnOffsets)
}

func TestHandleSymbolDataReadFailureSkipsOptionalReturnProbe(t *testing.T) {
	probe := &ebpfcommon.ProbeDesc{
		StartOffset: 0x1234,
		End:         &ebpf.Program{},
	}

	err := handleSymbolDataReadFailure(probe, "jvm", "libjvm.so", slog.Default())
	require.NoError(t, err)

	assert.True(t, probe.Skip)
	assert.Equal(t, uint64(0x1234), probe.StartOffset)
	assert.Empty(t, probe.ReturnOffsets)
}

func TestHandleSymbolDataReadFailureFailsRequiredReturnProbe(t *testing.T) {
	probe := &ebpfcommon.ProbeDesc{
		Required:    true,
		StartOffset: 0x1234,
		End:         &ebpf.Program{},
	}

	err := handleSymbolDataReadFailure(probe, "jvm", "libjvm.so", slog.Default())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required symbol jvm needs return offsets")

	assert.False(t, probe.Skip)
	assert.Equal(t, uint64(0x1234), probe.StartOffset)
	assert.Empty(t, probe.ReturnOffsets)
}

func TestHandleSymbolDataReadFailureKeepsStartOnlyProbeResolved(t *testing.T) {
	probe := &ebpfcommon.ProbeDesc{
		StartOffset: 0x1234,
	}

	err := handleSymbolDataReadFailure(probe, "jvm", "libjvm.so", slog.Default())
	require.NoError(t, err)

	assert.False(t, probe.Skip)
	assert.Equal(t, uint64(0x1234), probe.StartOffset)
	assert.Empty(t, probe.ReturnOffsets)
}

func TestGatherOffsetsSkipsMissingOptionalSymbol(t *testing.T) {
	reader := bytes.NewReader(testData())
	assert.NotNil(t, reader)

	probes := probeDescMap{
		"missing_optional_symbol": {{
			Required:      false,
			SymbolMatcher: ebpfcommon.SymbolMatcherContains,
		}},
	}

	elfFile, err := elf.NewFile(reader)
	require.NoError(t, err)
	defer elfFile.Close()

	err = gatherOffsetsImpl(elfFile, probes, "libbsd.so", slog.Default())
	require.NoError(t, err)

	desc := probes["missing_optional_symbol"][0]
	assert.True(t, desc.Skip)
	assert.Zero(t, desc.StartOffset)
	assert.Empty(t, desc.ReturnOffsets)
}

func TestGatherOffsetsFailsMissingRequiredSymbol(t *testing.T) {
	reader := bytes.NewReader(testData())
	assert.NotNil(t, reader)

	probes := probeDescMap{
		"missing_required_symbol": {{
			Required: true,
		}},
	}

	elfFile, err := elf.NewFile(reader)
	require.NoError(t, err)
	defer elfFile.Close()

	err = gatherOffsetsImpl(elfFile, probes, "libbsd.so", slog.Default())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required symbol missing_required_symbol not found")

	desc := probes["missing_required_symbol"][0]
	assert.True(t, desc.Skip)
	assert.Zero(t, desc.StartOffset)
	assert.Empty(t, desc.ReturnOffsets)
}

func TestGatherGoOffsetsMarksMissingSymbolAsSkip(t *testing.T) {
	// Regression for the retention bug fixed alongside this test: when
	// gatherGoOffsets does not find an offset for a probe symbol it must
	// mark the probe as Skip. Otherwise instrumentProbes attaches with
	// probe.StartOffset == 0, which reaches cilium/ebpf as
	// UprobeOptions{Address: 0} and forces a full ELF symbol table parse
	// retained on Executable.cachedSymbols for the tracer's lifetime.
	// The skip path must also emit an InstrumentationError with the
	// symbol_not_found label so operators can observe when expected Go
	// probe symbols are missing from a binary.
	reporter := &countingReporter{}
	i := &instrumenter{
		offsets: &goexec.Offsets{
			Funcs: map[string]goexec.FuncOffsets{},
		},
		metrics:     reporter,
		processName: "testproc",
	}
	probes := probeDescMap{
		"net/rpc/jsonrpc.(*serverCodec).ReadRequestHeader": {{}},
	}

	i.gatherGoOffsets(probes)

	desc := probes["net/rpc/jsonrpc.(*serverCodec).ReadRequestHeader"][0]
	assert.True(t, desc.Skip)
	assert.Zero(t, desc.StartOffset)
	assert.Empty(t, desc.ReturnOffsets)
	assert.Equal(t, 1, reporter.errors[imetrics.InstrumentationErrorSymbolNotFound])
}

func TestGatherGoOffsetsAppliesResolvedOffsetsAndClearsSkip(t *testing.T) {
	reporter := &countingReporter{}
	i := &instrumenter{
		offsets: &goexec.Offsets{
			Funcs: map[string]goexec.FuncOffsets{
				"net/http.serverHandler.ServeHTTP": {
					Start:   0x1234,
					Returns: []uint64{0x1250, 0x1260},
				},
			},
		},
		metrics:     reporter,
		processName: "testproc",
	}
	// Seed Skip = true to ensure the resolved branch clears stale state on reuse.
	probes := probeDescMap{
		"net/http.serverHandler.ServeHTTP": {{Skip: true}},
	}

	i.gatherGoOffsets(probes)

	desc := probes["net/http.serverHandler.ServeHTTP"][0]
	assert.False(t, desc.Skip)
	assert.Equal(t, uint64(0x1234), desc.StartOffset)
	assert.Equal(t, []uint64{0x1250, 0x1260}, desc.ReturnOffsets)
	assert.Empty(t, reporter.errors, "no InstrumentationError should be emitted when the symbol resolves")
}

func TestInstrumentProbesSkipsMarkedOptionalProbe(t *testing.T) {
	i := &instrumenter{}
	probes := probeDescMap{
		"skipped_optional_symbol": {{
			Skip:  true,
			Start: &ebpf.Program{},
		}},
	}

	closers, err := i.instrumentProbes(nil, probes)
	require.NoError(t, err)
	assert.Empty(t, closers)
}

func TestMatchVersionedUprobeLibrary(t *testing.T) {
	maps := makeProcMaps(
		"/usr/local/lib/python3.11/lib-dynload/_asyncio.cpython-311-x86_64-linux-gnu.so",
		"/usr/lib/libpython3.14.so.1.0",
	)

	for _, tc := range []struct {
		name     string
		lib      string
		selected bool
		baseLib  string
		wantErr  string
	}{
		{
			name:     "unannotated library",
			lib:      "_asyncio",
			selected: true,
			baseLib:  "_asyncio",
		},
		{
			name:     "matching asyncio constraint",
			lib:      "_asyncio[< 3.12]",
			selected: true,
			baseLib:  "_asyncio",
		},
		{
			name:     "mismatching asyncio constraint",
			lib:      "_asyncio[>= 3.12]",
			selected: false,
			baseLib:  "_asyncio",
		},
		{
			name:     "matching libpython constraint",
			lib:      "libpython3.[>= 3.14]",
			selected: true,
			baseLib:  "libpython3.",
		},
		{
			name:    "invalid constraint",
			lib:     "_asyncio[>= version]",
			wantErr: "malformed constraint",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseLib, selected, err := matchVersionedUprobeLibrary(tc.lib, maps)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.baseLib, baseLib)
			assert.Equal(t, tc.selected, selected)
		})
	}
}

func TestUprobeModulesRespectsVersionedLibraryAnnotations(t *testing.T) {
	i := &instrumenter{}
	maps := makeProcMaps("/usr/local/lib/python3.11/lib-dynload/_asyncio.cpython-311-x86_64-linux-gnu.so")
	tracer := stubTracer{
		uprobes: map[string]map[string][]*ebpfcommon.ProbeDesc{
			"_asyncio": {
				"_asyncio_Task___init__": {{}},
			},
			"_asyncio[< 3.12]": {
				"task_step_legacy": {{}},
			},
			"_asyncio[>= 3.12]": {
				"task_step": {{}},
			},
		},
	}

	modules := i.uprobeModules(&tracer, 123, maps, "/proc/123/exe", 42, slog.Default())

	require.Len(t, modules, 1)
	module := modules[42]
	require.NotNil(t, module)
	require.Len(t, module.probes, 2)

	selectedSymbols := map[string]struct{}{}
	for _, probeMap := range module.probes {
		for symbol := range probeMap {
			selectedSymbols[symbol] = struct{}{}
		}
	}

	assert.Contains(t, selectedSymbols, "_asyncio_Task___init__")
	assert.Contains(t, selectedSymbols, "task_step_legacy")
	assert.NotContains(t, selectedSymbols, "task_step")
}

func TestResolveInstrPathFallsBackToExecutableWhenLibraryMissing(t *testing.T) {
	instrPath, ino, mappedPath, found := resolveInstrPath(123, "libmissing.so", nil, "/proc/123/exe", 42)

	assert.False(t, found)
	assert.Equal(t, "/proc/123/exe", instrPath)
	assert.Equal(t, uint64(42), ino)
	assert.Empty(t, mappedPath)
}

func TestResolveInstrPathUsesMappedPathWhenLibraryIsMapped(t *testing.T) {
	instrPath, ino, mappedPath, found := resolveInstrPath(123, "libjvm.so", makeProcMaps("/usr/lib/libjvm.so"), "/proc/123/exe", 42)

	assert.True(t, found)
	assert.Equal(t, "/usr/lib/libjvm.so", instrPath)
	assert.Equal(t, uint64(42), ino)
	assert.Equal(t, "/usr/lib/libjvm.so", mappedPath)
}

func TestUSDTIPMapPIDsIncludesNamespacedAliases(t *testing.T) {
	original := findNamespacedPids
	defer func() { findNamespacedPids = original }()

	findNamespacedPids = func(pid app.PID) ([]app.PID, error) {
		assert.Equal(t, app.PID(123), pid)
		return []app.PID{123, 1, 17}, nil
	}

	assert.Equal(t, []app.PID{123, 1, 17}, usdtIPMapPIDs(123))
}

func TestUSDTIPMapPIDsFallsBackToHostPID(t *testing.T) {
	original := findNamespacedPids
	defer func() { findNamespacedPids = original }()

	findNamespacedPids = func(pid app.PID) ([]app.PID, error) {
		assert.Equal(t, app.PID(123), pid)
		return nil, errors.New("can't read status")
	}

	assert.Equal(t, []app.PID{123}, usdtIPMapPIDs(123))
}

func TestUSDTLinkCloserDeletesIPMapEntriesAfterClosingLink(t *testing.T) {
	var calls []string
	linkCloser := closerFunc(func() error {
		calls = append(calls, "close-link")
		return nil
	})
	ipMap := &recordingUSDTIPMap{calls: &calls}
	keys := []obiUSDTIPKey{
		{PID: 123, IP: 0xabc},
		{PID: 1, IP: 0xabc},
	}

	closer := &usdtLinkCloser{
		link: linkCloser,
		cleanup: usdtIPMapCleanup{
			ipMap: ipMap,
			keys:  keys,
		},
	}

	require.NoError(t, closer.Close())
	require.NoError(t, closer.Close())

	assert.Equal(t, []string{"close-link", "delete-ip", "delete-ip"}, calls)
	assert.Equal(t, keys, ipMap.deleted)
}

func TestUSDTLinkCloserCloseIsConcurrentSafe(t *testing.T) {
	linkCloser := &countingCloser{}
	ipMap := &countingUSDTIPMap{}
	keys := []obiUSDTIPKey{
		{PID: 123, IP: 0xabc},
		{PID: 1, IP: 0xabc},
	}
	closer := &usdtLinkCloser{
		link: linkCloser,
		cleanup: usdtIPMapCleanup{
			ipMap: ipMap,
			keys:  keys,
		},
	}

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range cap(errs) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- closer.Close()
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), linkCloser.closes.Load())
	assert.Equal(t, int32(len(keys)), ipMap.deletes.Load())
}

type closerFunc func() error

func (f closerFunc) Close() error {
	return f()
}

type recordingUSDTIPMap struct {
	calls   *[]string
	deleted []obiUSDTIPKey
}

func (m *recordingUSDTIPMap) Delete(key any) error {
	ipKey, ok := key.(obiUSDTIPKey)
	if !ok {
		panic("unexpected USDT IP key type")
	}
	*m.calls = append(*m.calls, "delete-ip")
	m.deleted = append(m.deleted, ipKey)
	return nil
}

type countingCloser struct {
	closes atomic.Int32
}

func (c *countingCloser) Close() error {
	c.closes.Add(1)
	return nil
}

type countingUSDTIPMap struct {
	deletes atomic.Int32
}

func (m *countingUSDTIPMap) Delete(any) error {
	m.deletes.Add(1)
	return nil
}

func TestVersionFromPath(t *testing.T) {
	for _, tc := range []struct {
		path    string
		version string
		found   bool
	}{
		{
			path:    "/usr/local/lib/python3.11/lib-dynload/_asyncio.cpython-311-x86_64-linux-gnu.so",
			version: "3.11.0",
			found:   true,
		},
		{
			path:    "/usr/lib/libpython3.14.so.1.0",
			version: "3.14.0",
			found:   true,
		},
		{
			path:    "/usr/lib64/libssl.so.3",
			version: "3.0.0",
			found:   true,
		},
		{
			path:    "/usr/lib/libssl.so.3",
			version: "3.0.0",
			found:   true,
		},
		{
			path:  "/opt/runtime/current/module.so",
			found: false,
		},
	} {
		t.Run(tc.path, func(t *testing.T) {
			v, found := versionFromPath(tc.path)
			assert.Equal(t, tc.found, found)
			if tc.found {
				require.NotNil(t, v)
				assert.Equal(t, tc.version, v.String())
			}
		})
	}
}

func makeProcMaps(paths ...string) []*procfs.ProcMap {
	maps := make([]*procfs.ProcMap, 0, len(paths))
	for _, path := range paths {
		maps = append(maps, &procfs.ProcMap{
			Pathname: path,
			Perms:    &procfs.ProcMapPermissions{Execute: true},
		})
	}

	return maps
}

// countingReporter is a minimal imetrics.Reporter test double that only
// records InstrumentationError calls, sufficient for gatherGoOffsets tests.
// It embeds imetrics.NoopReporter so the rest of the Reporter surface stays a no-op.
type countingReporter struct {
	imetrics.NoopReporter
	errors map[string]int
}

func (r *countingReporter) InstrumentationError(_ string, errorType string) {
	if r.errors == nil {
		r.errors = map[string]int{}
	}
	r.errors[errorType]++
}

type stubTracer struct {
	uprobes map[string]map[string][]*ebpfcommon.ProbeDesc
}

func (s *stubTracer) AllowPID(app.PID, uint32, *exec.FileInfo)               {}
func (s *stubTracer) BlockPID(app.PID, uint32)                               {}
func (s *stubTracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error)           { return nil, nil }
func (s *stubTracer) AddCloser(...io.Closer)                                 {}
func (s *stubTracer) SetupTailCalls()                                        {}
func (s *stubTracer) KProbes() map[string]ebpfcommon.ProbeDesc               { return nil }
func (s *stubTracer) Tracepoints() map[string]ebpfcommon.ProbeDesc           { return nil }
func (s *stubTracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc           { return nil }
func (s *stubTracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc { return s.uprobes }
func (s *stubTracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc     { return nil }
func (s *stubTracer) SocketFilters() []*ebpf.Program                         { return nil }
func (s *stubTracer) SockMsgs() []ebpfcommon.SockMsg                         { return nil }
func (s *stubTracer) SockOps() []ebpfcommon.SockOps                          { return nil }
func (s *stubTracer) Iters() []*ebpfcommon.Iter                              { return nil }
func (s *stubTracer) Tracing() []*ebpfcommon.Tracing                         { return nil }
func (s *stubTracer) RecordInstrumentedLib(uint64, []io.Closer)              {}
func (s *stubTracer) AddInstrumentedLibRef(uint64)                           {}
func (s *stubTracer) AlreadyInstrumentedLib(uint64) bool                     { return false }
func (s *stubTracer) UnlinkInstrumentedLib(uint64)                           {}
func (s *stubTracer) RegisterOffsets(*exec.FileInfo, *goexec.Offsets)        {}
func (s *stubTracer) ProcessBinary(*exec.FileInfo)                           {}
func (s *stubTracer) Required() bool                                         { return false }
func (s *stubTracer) SetEventContext(*ebpfcommon.EBPFEventContext)           {}
func (s *stubTracer) Capabilities() ebpfcommon.TracerCapability              { return 0 }
func (s *stubTracer) Run(context.Context, *ebpfcommon.EBPFEventContext, *msg.Queue[[]request.Span]) {
}
