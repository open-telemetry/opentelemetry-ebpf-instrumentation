// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"debug/elf"
	"io"
	"log/slog"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
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

type stubTracer struct {
	uprobes map[string]map[string][]*ebpfcommon.ProbeDesc
}

func (s *stubTracer) AllowPID(app.PID, uint32, *svc.Attrs)                   {}
func (s *stubTracer) BlockPID(app.PID, uint32)                               {}
func (s *stubTracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error)           { return nil, nil }
func (s *stubTracer) AddCloser(...io.Closer)                                 {}
func (s *stubTracer) SetupTailCalls()                                        {}
func (s *stubTracer) KProbes() map[string]ebpfcommon.ProbeDesc               { return nil }
func (s *stubTracer) Tracepoints() map[string]ebpfcommon.ProbeDesc           { return nil }
func (s *stubTracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc           { return nil }
func (s *stubTracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc { return s.uprobes }
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
