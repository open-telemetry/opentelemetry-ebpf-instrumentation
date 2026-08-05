// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"debug/elf"
	"io"
	"log/slog"
	"os"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	execpkg "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	helpermaps "go.opentelemetry.io/obi/pkg/internal/helpers/maps"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type blockedPID struct {
	pid app.PID
	ns  uint32
}

type recordingTracer struct {
	allowed          []blockedPID
	allowedFileInfos map[app.PID]*execpkg.FileInfo
	blocked          []blockedPID
	blockedStartTime []uint64
	blockedFileInfos []*execpkg.FileInfo
}

type admissionRecordingTracer struct {
	recordingTracer
	admitted              map[app.PID]bool
	pending               map[*execpkg.FileInfo]bool
	claimRootOnAdmission  bool
	claimedAdmissionRoots []*os.File
}

type unlinkRecordingTracer struct {
	recordingTracer
	unlinkReady  bool
	unlinkChecks int
}

func (r *unlinkRecordingTracer) ExecutableUnlinkReady(*execpkg.FileInfo) bool {
	r.unlinkChecks++
	return r.unlinkReady
}

func readinessOnlyUnlink(
	tracer *ebpf.ProcessTracer,
	fileInfo *execpkg.FileInfo,
	_ uint64,
) bool {
	for _, program := range tracer.Programs {
		if readiness, ok := program.(ebpf.ExecutableUnlinkReadiness); ok &&
			!readiness.ExecutableUnlinkReady(fileInfo) {
			return false
		}
	}
	return true
}

func (r *admissionRecordingTracer) AllowPIDForProcess(
	pid app.PID,
	ns uint32,
	fi *execpkg.FileInfo,
) bool {
	r.AllowPID(pid, ns, fi)
	admitted := r.admitted[pid]
	if admitted && r.claimRootOnAdmission {
		if root := fi.TakeProcessRoot(); root != nil {
			r.claimedAdmissionRoots = append(r.claimedAdmissionRoots, root)
		}
	}
	return admitted
}

func (r *admissionRecordingTracer) PIDAdmissionRetryPending(
	_ app.PID,
	_ uint32,
	fi *execpkg.FileInfo,
) bool {
	return r.pending[fi]
}

func (r *admissionRecordingTracer) CancelPIDAdmissionRetry(
	_ app.PID,
	_ uint32,
	fi *execpkg.FileInfo,
) {
	delete(r.pending, fi)
}

type recordingMetrics struct {
	imetrics.NoopReporter
	instrumented   []string
	uninstrumented []string
}

func (r *recordingMetrics) InstrumentProcess(name string) {
	r.instrumented = append(r.instrumented, name)
}

func (r *recordingMetrics) UninstrumentProcess(name string) {
	r.uninstrumented = append(r.uninstrumented, name)
}

func (r *recordingTracer) AllowPID(pid app.PID, ns uint32, fi *execpkg.FileInfo) {
	r.allowed = append(r.allowed, blockedPID{pid: pid, ns: ns})
	if r.allowedFileInfos == nil {
		r.allowedFileInfos = make(map[app.PID]*execpkg.FileInfo)
	}
	r.allowedFileInfos[pid] = fi
}

func (r *recordingTracer) BlockPID(pid app.PID, ns uint32) {
	r.blocked = append(r.blocked, blockedPID{pid: pid, ns: ns})
}

func (r *recordingTracer) BlockPIDForProcess(
	pid app.PID,
	ns uint32,
	fileInfo *execpkg.FileInfo,
) {
	r.blocked = append(r.blocked, blockedPID{pid: pid, ns: ns})
	r.blockedFileInfos = append(r.blockedFileInfos, fileInfo)
	if fileInfo != nil {
		r.blockedStartTime = append(r.blockedStartTime, fileInfo.StartTime())
	}
}

type legacyPIDAccounter struct {
	blocked []blockedPID
}

func TestCloseInstrumentableProcessRootsClosesUnclaimedRoots(t *testing.T) {
	primaryRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	childRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	primary := execpkg.New(execpkg.Init{ProcessRoot: primaryRoot})
	child := execpkg.New(execpkg.Init{ProcessRoot: childRoot})
	instrumentable := &ebpf.Instrumentable{
		FileInfo:       primary,
		ChildFileInfos: map[app.PID]*execpkg.FileInfo{2: child},
	}

	closeInstrumentableProcessRoots(instrumentable)
	closeInstrumentableProcessRoots(instrumentable)

	_, err = primaryRoot.Stat()
	require.Error(t, err)
	_, err = childRoot.Stat()
	require.Error(t, err)
}

func TestCloseInstrumentableProcessRootsClosesEveryELF(t *testing.T) {
	primaryELF, err := elf.Open("/proc/self/exe")
	require.NoError(t, err)
	childELF, err := elf.Open("/proc/self/exe")
	require.NoError(t, err)
	primaryText := primaryELF.Section(".text")
	childText := childELF.Section(".text")
	require.NotNil(t, primaryText)
	require.NotNil(t, childText)
	primary := execpkg.New(execpkg.Init{ELF: primaryELF})
	child := execpkg.New(execpkg.Init{ELF: childELF})

	closeInstrumentableProcessRoots(&ebpf.Instrumentable{
		FileInfo: primary,
		ChildFileInfos: map[app.PID]*execpkg.FileInfo{
			2: child,
		},
	})

	_, err = primaryText.Data()
	require.Error(t, err)
	_, err = childText.Data()
	require.Error(t, err)
}

func TestClaimInstrumentableProcessRootsLeavesTracerRoot(t *testing.T) {
	root, err := os.Open(t.TempDir())
	require.NoError(t, err)
	fileInfo := execpkg.New(execpkg.Init{ProcessRoot: root})

	claimed := claimInstrumentableProcessRoots(
		&ebpf.Instrumentable{FileInfo: fileInfo},
	)[fileInfo]
	require.NotNil(t, claimed)
	assert.NotSame(t, root, claimed)
	tracerRoot := fileInfo.TakeProcessRoot()
	assert.Same(t, root, tracerRoot)
	assert.NoError(t, claimed.Close())
	assert.NoError(t, tracerRoot.Close())
}

func TestCloseInstrumentableProcessRootsLeavesClaimedRootOpen(t *testing.T) {
	root, err := os.Open(t.TempDir())
	require.NoError(t, err)
	fileInfo := execpkg.New(execpkg.Init{ProcessRoot: root})
	claimed := fileInfo.TakeProcessRoot()
	require.Same(t, root, claimed)
	t.Cleanup(func() {
		require.NoError(t, claimed.Close())
	})

	closeInstrumentableProcessRoots(&ebpf.Instrumentable{FileInfo: fileInfo})

	_, err = claimed.Stat()
	require.NoError(t, err)
}

func TestCloseQueuedInstrumentableProcessRootsDrainsCreatedBacklog(t *testing.T) {
	primaryRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	childRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	input := make(chan []Event[ebpf.Instrumentable], 1)
	input <- []Event[ebpf.Instrumentable]{{
		Type: EventCreated,
		Obj: ebpf.Instrumentable{
			FileInfo: execpkg.New(execpkg.Init{
				ProcessRoot: primaryRoot,
			}),
			ChildFileInfos: map[app.PID]*execpkg.FileInfo{
				2: execpkg.New(execpkg.Init{ProcessRoot: childRoot}),
			},
		},
	}}
	close(input)

	closeQueuedInstrumentableProcessRoots(input)

	_, err = primaryRoot.Stat()
	require.Error(t, err)
	_, err = childRoot.Stat()
	require.Error(t, err)
}

func (*legacyPIDAccounter) AllowPID(app.PID, uint32, *execpkg.FileInfo) {}

func (l *legacyPIDAccounter) BlockPID(pid app.PID, ns uint32) {
	l.blocked = append(l.blocked, blockedPID{pid: pid, ns: ns})
}

func (r *recordingTracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error)           { return nil, nil }
func (r *recordingTracer) AddCloser(...io.Closer)                                 {}
func (r *recordingTracer) SetupTailCalls()                                        {}
func (r *recordingTracer) KProbes() map[string]ebpfcommon.ProbeDesc               { return nil }
func (r *recordingTracer) Tracepoints() map[string]ebpfcommon.ProbeDesc           { return nil }
func (r *recordingTracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc           { return nil }
func (r *recordingTracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc { return nil }
func (r *recordingTracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc     { return nil }
func (r *recordingTracer) SocketFilters() []*cebpf.Program                        { return nil }
func (r *recordingTracer) SockMsgs() []ebpfcommon.SockMsg                         { return nil }
func (r *recordingTracer) SockOps() []ebpfcommon.SockOps                          { return nil }
func (r *recordingTracer) Iters() []*ebpfcommon.Iter                              { return nil }
func (r *recordingTracer) Tracing() []*ebpfcommon.Tracing                         { return nil }
func (r *recordingTracer) RecordInstrumentedLib(uint64, []io.Closer)              {}
func (r *recordingTracer) AddInstrumentedLibRef(uint64)                           {}
func (r *recordingTracer) AlreadyInstrumentedLib(uint64) bool                     { return false }
func (r *recordingTracer) UnlinkInstrumentedLib(uint64)                           {}
func (r *recordingTracer) RegisterOffsets(*execpkg.FileInfo, *goexec.Offsets)     {}
func (r *recordingTracer) ProcessBinary(*execpkg.FileInfo)                        {}
func (r *recordingTracer) Required() bool                                         { return false }
func (r *recordingTracer) SetEventContext(*ebpfcommon.EBPFEventContext)           {}
func (r *recordingTracer) Capabilities() ebpfcommon.TracerCapability              { return 0 }
func (r *recordingTracer) Run(context.Context, *ebpfcommon.EBPFEventContext, *msg.Queue[[]request.Span]) {
}

func TestExecutableKeySeparatesFilesystems(t *testing.T) {
	first := execpkg.New(execpkg.Init{Dev: 1, Ino: 42})
	second := execpkg.New(execpkg.Init{Dev: 2, Ino: 42})
	firstKey := executableKey(first)
	secondKey := executableKey(second)

	assert.NotEqual(t, firstKey, secondKey)

	tracers := map[ebpf.ExecutableKey]executableTracer{
		firstKey:  {tracer: &ebpf.ProcessTracer{Type: ebpf.Go}},
		secondKey: {tracer: &ebpf.ProcessTracer{Type: ebpf.Generic}},
	}
	require.Len(t, tracers, 2)
	assert.Equal(t, ebpf.Go, tracers[firstKey].tracer.Type)
	assert.Equal(t, ebpf.Generic, tracers[secondKey].tracer.Type)
}

func TestMonitorPIDsStopsAfterPrimaryAdmissionRejection(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	processStartTimeFunc = func(app.PID) uint64 { return 100 }

	fileInfo := execpkg.New(execpkg.Init{
		Pid:       42,
		Ns:        17,
		StartTime: 100,
	})
	primary := &admissionRecordingTracer{admitted: map[app.PID]bool{42: false}}
	inProcessCommon := &recordingTracer{}
	externalCommon := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{
		Programs: []ebpf.Tracer{primary, inProcessCommon},
	}
	ta := &traceAttacher{commonTracers: []ebpf.Tracer{externalCommon}}

	assert.False(t, ta.monitorPIDs(tracer, &ebpf.Instrumentable{FileInfo: fileInfo}))
	assert.Equal(t, []blockedPID{{pid: 42, ns: 17}}, primary.allowed)
	assert.Empty(t, inProcessCommon.allowed)
	assert.Empty(t, externalCommon.allowed)
	assert.NotContains(t, ta.activePIDs, app.PID(42))
}

func TestInitialAdmissionValidatesOwnedRootBeforeAndAfterAllow(t *testing.T) {
	tests := []struct {
		name        string
		identity    func(int) bool
		wantAllowed int
		wantBlocked int
		wantChecks  int
	}{
		{
			name:       "stale before allow",
			identity:   func(int) bool { return false },
			wantChecks: 1,
		},
		{
			name:        "replaced during allow",
			identity:    func(check int) bool { return check == 1 },
			wantAllowed: 1,
			wantBlocked: 1,
			wantChecks:  2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root, err := os.Open(t.TempDir())
			require.NoError(t, err)
			fileInfo := execpkg.New(execpkg.Init{
				Pid: 42, Ns: 17, StartTime: 100, Dev: 7, Ino: 1234, ProcessRoot: root,
			})
			program := &admissionRecordingTracer{
				admitted: map[app.PID]bool{fileInfo.Pid(): true},
			}
			tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
			checks := 0
			ta := &traceAttacher{
				activePIDs: map[app.PID]*execpkg.FileInfo{},
				initialIdentityCheck: func(got *execpkg.FileInfo, ownedRoot *os.File) bool {
					assert.Same(t, fileInfo, got)
					assert.NotSame(t, root, ownedRoot)
					_, statErr := ownedRoot.Stat()
					require.NoError(t, statErr)
					checks++
					return tc.identity(checks)
				},
			}
			ta.currentProcessRoots = claimInstrumentableProcessRoots(
				&ebpf.Instrumentable{FileInfo: fileInfo},
			)
			require.NoError(t, fileInfo.CloseProcessRoot())

			admitted := ta.monitorPIDs(tracer, &ebpf.Instrumentable{FileInfo: fileInfo})
			closeAdmissionProcessRoots(ta.currentProcessRoots)

			assert.False(t, admitted)
			assert.Equal(t, tc.wantChecks, checks)
			assert.Len(t, program.allowed, tc.wantAllowed)
			assert.Len(t, program.blocked, tc.wantBlocked)
			assert.Empty(t, ta.activePIDs)
			_, err = root.Stat()
			require.Error(t, err)
		})
	}
}

func TestProbeIdentityFailureLeavesCollapsedActiveParentUntouched(t *testing.T) {
	parent := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test", Pid: 42, Ns: 17, StartTime: 100, Ino: 1234,
	})
	child := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test", Pid: 43, Ns: 18, StartTime: 200, Ino: 1234,
	})
	childRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	program := &admissionRecordingTracer{
		admitted: map[app.PID]bool{child.Pid(): true},
	}
	cfg := &obi.Config{}
	tracer := ebpf.NewProcessTracer(
		ebpf.Generic,
		[]ebpf.Tracer{program},
		cfg,
		imetrics.NoopReporter{},
	)
	ie := &ebpf.Instrumentable{
		Type:           svc.InstrumentableGeneric,
		FileInfo:       parent,
		ChildPids:      []app.PID{child.Pid()},
		ChildFileInfos: map[app.PID]*execpkg.FileInfo{child.Pid(): child},
	}
	identityChecks := 0
	probeRollbacks := 0
	ta := &traceAttacher{
		log:     slog.Default(),
		Cfg:     cfg,
		Metrics: imetrics.NoopReporter{},
		existingTracers: map[ebpf.ExecutableKey]executableTracer{
			executableKey(parent): {tracer: tracer},
		},
		activePIDs: map[app.PID]*execpkg.FileInfo{parent.Pid(): parent},
		currentProcessRoots: map[*execpkg.FileInfo]*os.File{
			child: childRoot,
		},
		initialIdentityCheck: func(fileInfo *execpkg.FileInfo, root *os.File) bool {
			require.Same(t, child, fileInfo)
			require.Same(t, childRoot, root)
			identityChecks++
			return identityChecks < 3
		},
		probeUpdate: func(gotTracer *ebpf.ProcessTracer, target *ebpf.Instrumentable) (func(), bool) {
			assert.Same(t, tracer, gotTracer)
			assert.Same(t, child, target.FileInfo)
			return func() { probeRollbacks++ }, true
		},
		routeHarvester: harvest.NewRouteHarvester(
			&cfg.Discovery.RouteHarvestConfig,
			cfg.Discovery.DisabledRouteHarvesters,
			testTimeout,
		),
	}

	assert.False(t, ta.getTracer(ie))

	assert.Same(t, parent, ta.activePIDs[parent.Pid()])
	assert.NotContains(t, ta.activePIDs, child.Pid())
	assert.Empty(t, program.allowed)
	assert.Equal(t, 1, probeRollbacks)
	pending, ok := ta.pendingAdmissions[processAdmissionKey(child)]
	require.True(t, ok)
	assert.True(t, pending.updateTracerProbes)
	ta.cancelAllProcessAdmissionRetries()
	require.NoError(t, childRoot.Close())
}

func TestPendingAdmissionRetryCompletesAttacherBookkeeping(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	processStartTimeFunc = func(pid app.PID) uint64 {
		require.Equal(t, app.PID(42), pid)
		return 100
	}

	processRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	fileInfo := execpkg.New(execpkg.Init{
		CmdExePath:  "/bin/test",
		Pid:         42,
		Ns:          17,
		StartTime:   100,
		Ino:         1234,
		ProcessRoot: processRoot,
	})
	instrumentable := &ebpf.Instrumentable{
		Type:     svc.InstrumentableGeneric,
		FileInfo: fileInfo,
	}
	program := &admissionRecordingTracer{
		admitted:             map[app.PID]bool{fileInfo.Pid(): false},
		pending:              map[*execpkg.FileInfo]bool{fileInfo: true},
		claimRootOnAdmission: true,
	}
	commonProgram := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{
		Type:     ebpf.Generic,
		Programs: []ebpf.Tracer{program},
	}
	metrics := &recordingMetrics{}
	dynamicSelector := NewDynamicPIDSelector()
	signals := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
	signalCh := signals.Subscribe()
	events := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(1))
	eventCh := events.Subscribe()
	ta := &traceAttacher{
		log:                 slog.Default(),
		Metrics:             metrics,
		existingTracers:     map[ebpf.ExecutableKey]executableTracer{},
		processInstances:    helpermaps.MultiCounter[ebpf.ExecutableKey]{},
		activePIDs:          map[app.PID]*execpkg.FileInfo{},
		commonTracers:       []ebpf.Tracer{commonProgram},
		DynamicPIDSelector:  dynamicSelector,
		SpanSignalsShortcut: signals,
		OutputTracerEvents:  events,
	}

	require.False(t, ta.monitorPIDs(tracer, instrumentable))
	ta.queueProcessAdmissionRetry(tracer, instrumentable, false)
	require.Len(t, ta.pendingAdmissions, 1)
	retainedRoot := ta.pendingAdmissions[processAdmissionKey(fileInfo)].processRoots[fileInfo]
	require.NotNil(t, retainedRoot)
	assert.Empty(t, ta.activePIDs)
	assert.Empty(t, metrics.instrumented)

	program.admitted[fileInfo.Pid()] = true
	ta.retryPendingProcessAdmissions()

	assert.Empty(t, ta.pendingAdmissions)
	assert.Same(t, fileInfo, ta.activePIDs[fileInfo.Pid()])
	assert.Same(t, tracer, ta.existingTracers[executableKey(fileInfo)].tracer)
	require.NotNil(t, ta.processInstances[executableKey(fileInfo)])
	assert.Equal(t, 1, *ta.processInstances[executableKey(fileInfo)])
	assert.Equal(t, []string{fileInfo.ExecutableName()}, metrics.instrumented)
	assert.Same(t, fileInfo, dynamicSelector.fileInfoByPID[fileInfo.Pid()])
	assert.Equal(t, []blockedPID{{pid: 42, ns: 17}}, commonProgram.allowed)
	alive := testutil.ReadChannel(t, signalCh, testTimeout)
	require.Len(t, alive, 1)
	assert.Equal(t, request.EventTypeProcessAlive, alive[0].Type)
	created := testutil.ReadChannel(t, eventCh, testTimeout)
	assert.Equal(t, EventCreated, created.Type)
	assert.Same(t, tracer, created.Obj.Tracer)
	require.Len(t, program.claimedAdmissionRoots, 1)
	claimedRoot := program.claimedAdmissionRoots[0]
	assert.NotSame(t, retainedRoot, claimedRoot)
	_, err = claimedRoot.Stat()
	require.NoError(t, err)
	require.NoError(t, claimedRoot.Close())
	assert.Nil(t, fileInfo.TakeProcessRoot())
	_, err = retainedRoot.Stat()
	require.Error(t, err)
	_, err = processRoot.Stat()
	require.Error(t, err)
}

func TestPendingAdmissionRetryCancelsOnDeletionAndPIDReuse(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	currentStartTime := uint64(100)
	processStartTimeFunc = func(app.PID) uint64 { return currentStartTime }

	fileInfo := execpkg.New(execpkg.Init{
		Pid: 42, Ns: 17, StartTime: 100, Ino: 1234,
	})
	program := &admissionRecordingTracer{
		admitted: map[app.PID]bool{fileInfo.Pid(): false},
		pending:  map[*execpkg.FileInfo]bool{fileInfo: true},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	instrumentable := &ebpf.Instrumentable{FileInfo: fileInfo}
	ta := &traceAttacher{
		log:              slog.Default(),
		Metrics:          imetrics.NoopReporter{},
		activePIDs:       map[app.PID]*execpkg.FileInfo{},
		processInstances: helpermaps.MultiCounter[ebpf.ExecutableKey]{},
	}

	ta.queueProcessAdmissionRetry(tracer, instrumentable, false)
	require.Len(t, ta.pendingAdmissions, 1)
	ta.notifyProcessDeletion(instrumentable)
	assert.Empty(t, ta.pendingAdmissions)

	program.pending[fileInfo] = true
	ta.queueProcessAdmissionRetry(tracer, instrumentable, false)
	require.Len(t, ta.pendingAdmissions, 1)
	currentStartTime = 200
	program.admitted[fileInfo.Pid()] = true
	program.pending[fileInfo] = false
	ta.retryPendingProcessAdmissions()
	assert.Empty(t, ta.pendingAdmissions)
	assert.Empty(t, ta.activePIDs)
	assert.Empty(t, ta.processInstances)
}

func TestNormalAdmissionCancelsQueuedRetryBeforeTicker(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	processStartTimeFunc = func(app.PID) uint64 { return 100 }

	fileInfo := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test",
		Pid:        42,
		Ns:         17,
		StartTime:  100,
		Ino:        1234,
	})
	instrumentable := &ebpf.Instrumentable{
		Type:     svc.InstrumentableGolang,
		FileInfo: fileInfo,
	}
	program := &admissionRecordingTracer{
		admitted: map[app.PID]bool{fileInfo.Pid(): false},
		pending:  map[*execpkg.FileInfo]bool{fileInfo: true},
	}
	tracer := &ebpf.ProcessTracer{
		Type:     ebpf.Go,
		Programs: []ebpf.Tracer{program},
	}
	cfg := &obi.Config{}
	metrics := &recordingMetrics{}
	events := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(2))
	eventCh := events.Subscribe()
	ta := &traceAttacher{
		log:     slog.Default(),
		Cfg:     cfg,
		Metrics: metrics,
		existingTracers: map[ebpf.ExecutableKey]executableTracer{
			executableKey(fileInfo): {tracer: tracer},
		},
		processInstances:   helpermaps.MultiCounter[ebpf.ExecutableKey]{},
		activePIDs:         map[app.PID]*execpkg.FileInfo{},
		OutputTracerEvents: events,
		routeHarvester: harvest.NewRouteHarvester(
			&cfg.Discovery.RouteHarvestConfig,
			cfg.Discovery.DisabledRouteHarvesters,
			testTimeout,
		),
	}

	require.False(t, ta.monitorPIDs(tracer, instrumentable))
	ta.queueProcessAdmissionRetry(tracer, instrumentable, false)
	require.Len(t, ta.pendingAdmissions, 1)

	program.admitted[fileInfo.Pid()] = true
	require.True(t, ta.getTracer(instrumentable))
	ta.processInstances.Inc(executableKey(fileInfo))
	ta.OutputTracerEvents.Send(Event[*ebpf.Instrumentable]{
		Type: EventCreated,
		Obj:  instrumentable,
	})

	assert.Empty(t, ta.pendingAdmissions)
	ta.retryPendingProcessAdmissions()
	assert.Equal(t, []string{fileInfo.ExecutableName()}, metrics.instrumented)
	require.NotNil(t, ta.processInstances[executableKey(fileInfo)])
	assert.Equal(t, 1, *ta.processInstances[executableKey(fileInfo)])
	created := testutil.ReadChannel(t, eventCh, testTimeout)
	assert.Equal(t, EventCreated, created.Type)
	select {
	case duplicate := <-eventCh:
		t.Fatalf("unexpected duplicate event: %v", duplicate.Type)
	default:
	}
}

func TestSuccessfulAdmissionCancelsOverlappingCollapsedRetry(t *testing.T) {
	parent := execpkg.New(execpkg.Init{
		Pid: 42, Ns: 17, StartTime: 100, Ino: 1234,
	})
	child := execpkg.New(execpkg.Init{
		Pid: 43, Ns: 18, StartTime: 200, Ino: 1234,
	})
	program := &admissionRecordingTracer{
		admitted: map[app.PID]bool{parent.Pid(): true, child.Pid(): false},
		pending:  map[*execpkg.FileInfo]bool{child: true},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	collapsed := &ebpf.Instrumentable{
		FileInfo:       parent,
		ChildPids:      []app.PID{child.Pid()},
		ChildFileInfos: map[app.PID]*execpkg.FileInfo{child.Pid(): child},
	}
	ta := &traceAttacher{}
	ta.queueProcessAdmissionRetry(tracer, collapsed, false)
	require.Len(t, ta.pendingAdmissions, 1)

	ta.cancelInstrumentableAdmissionRetries(&ebpf.Instrumentable{FileInfo: child})

	assert.Empty(t, ta.pendingAdmissions)
	assert.False(t, program.pending[child])
}

func TestDistinctCollapsedRetriesKeepIndependentAccounting(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	startTimes := map[app.PID]uint64{42: 100, 43: 200, 44: 300}
	processStartTimeFunc = func(pid app.PID) uint64 { return startTimes[pid] }

	parentRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	oldChildRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	newChildRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	parent := execpkg.New(execpkg.Init{
		Pid: 42, Ns: 17, StartTime: 100, Ino: 1234, ProcessRoot: parentRoot,
	})
	oldChild := execpkg.New(execpkg.Init{
		Pid: 43, Ns: 18, StartTime: 200, Ino: 1234, ProcessRoot: oldChildRoot,
	})
	newChild := execpkg.New(execpkg.Init{
		Pid: 44, Ns: 19, StartTime: 300, Ino: 1234, ProcessRoot: newChildRoot,
	})
	program := &admissionRecordingTracer{
		admitted: map[app.PID]bool{
			parent.Pid():   true,
			oldChild.Pid(): true,
			newChild.Pid(): true,
		},
		pending: map[*execpkg.FileInfo]bool{
			oldChild: true,
			newChild: true,
		},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	group := func(child *execpkg.FileInfo) *ebpf.Instrumentable {
		return &ebpf.Instrumentable{
			FileInfo:       parent,
			ChildPids:      []app.PID{child.Pid()},
			ChildFileInfos: map[app.PID]*execpkg.FileInfo{child.Pid(): child},
		}
	}
	ta := &traceAttacher{
		Metrics:          imetrics.NoopReporter{},
		existingTracers:  map[ebpf.ExecutableKey]executableTracer{},
		processInstances: helpermaps.MultiCounter[ebpf.ExecutableKey]{},
		activePIDs:       map[app.PID]*execpkg.FileInfo{},
		pendingIdentityCheck: func(_ *execpkg.FileInfo, root *os.File) bool {
			return root != nil
		},
	}

	ta.queueProcessAdmissionRetry(tracer, group(oldChild), false)
	ta.queueProcessAdmissionRetry(tracer, group(newChild), false)
	require.Len(t, ta.pendingAdmissions, 2)

	ta.retryPendingProcessAdmissions()

	assert.Empty(t, ta.pendingAdmissions)
	assert.False(t, program.pending[oldChild])
	assert.False(t, program.pending[newChild])
	assert.Same(t, oldChild, ta.activePIDs[oldChild.Pid()])
	assert.Same(t, newChild, ta.activePIDs[newChild.Pid()])
	require.NotNil(t, ta.processInstances[executableKey(parent)])
	assert.Equal(t, 2, *ta.processInstances[executableKey(parent)])
	assert.Len(t, ta.activeEvents, 2)
	_, err = parentRoot.Stat()
	require.Error(t, err)
	_, err = oldChildRoot.Stat()
	require.Error(t, err)
	_, err = newChildRoot.Stat()
	require.Error(t, err)
}

func TestDistinctCollapsedRetriesShareFailedParentDebt(t *testing.T) {
	parentRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	firstChildRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	secondChildRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	parent := execpkg.New(execpkg.Init{
		Pid: 42, Ns: 17, StartTime: 100, Ino: 1234, ProcessRoot: parentRoot,
	})
	firstChild := execpkg.New(execpkg.Init{
		Pid: 43, Ns: 18, StartTime: 200, Ino: 1234, ProcessRoot: firstChildRoot,
	})
	secondChild := execpkg.New(execpkg.Init{
		Pid: 44, Ns: 19, StartTime: 300, Ino: 1234, ProcessRoot: secondChildRoot,
	})
	program := &admissionRecordingTracer{
		admitted: map[app.PID]bool{42: true, 43: true, 44: true},
		pending:  map[*execpkg.FileInfo]bool{parent: true},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	group := func(child *execpkg.FileInfo) *ebpf.Instrumentable {
		return &ebpf.Instrumentable{
			FileInfo:       parent,
			ChildPids:      []app.PID{child.Pid()},
			ChildFileInfos: map[app.PID]*execpkg.FileInfo{child.Pid(): child},
		}
	}
	ta := &traceAttacher{
		Metrics:          imetrics.NoopReporter{},
		existingTracers:  map[ebpf.ExecutableKey]executableTracer{},
		processInstances: helpermaps.MultiCounter[ebpf.ExecutableKey]{},
		activePIDs:       map[app.PID]*execpkg.FileInfo{},
		pendingIdentityCheck: func(_ *execpkg.FileInfo, root *os.File) bool {
			return root != nil
		},
	}
	ta.queueProcessAdmissionRetry(tracer, group(firstChild), false)
	ta.queueProcessAdmissionRetry(tracer, group(secondChild), false)
	require.Len(t, ta.pendingAdmissions, 2)

	ta.retryPendingProcessAdmissions()

	assert.Empty(t, ta.pendingAdmissions)
	require.NotNil(t, ta.processInstances[executableKey(parent)])
	assert.Equal(t, 2, *ta.processInstances[executableKey(parent)])
	assert.Len(t, ta.activeEvents, 2)
	allowed := map[app.PID]int{}
	for _, admission := range program.allowed {
		allowed[admission.pid]++
	}
	assert.Equal(t, map[app.PID]int{42: 1, 43: 1, 44: 1}, allowed)
}

func TestRetrySkipsAlreadyActiveParentWithoutOwnedRoot(t *testing.T) {
	triggerRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	parent := execpkg.New(execpkg.Init{Pid: 42, Ns: 17, StartTime: 100, Ino: 1234})
	trigger := execpkg.New(execpkg.Init{
		Pid: 43, Ns: 18, StartTime: 200, Ino: 1234, ProcessRoot: triggerRoot,
	})
	program := &admissionRecordingTracer{
		admitted: map[app.PID]bool{trigger.Pid(): true},
		pending:  map[*execpkg.FileInfo]bool{trigger: true},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	ta := &traceAttacher{
		Metrics:          imetrics.NoopReporter{},
		existingTracers:  map[ebpf.ExecutableKey]executableTracer{},
		processInstances: helpermaps.MultiCounter[ebpf.ExecutableKey]{},
		activePIDs:       map[app.PID]*execpkg.FileInfo{parent.Pid(): parent},
		pendingIdentityCheck: func(_ *execpkg.FileInfo, root *os.File) bool {
			return root != nil
		},
	}
	ie := &ebpf.Instrumentable{
		FileInfo:       parent,
		ChildPids:      []app.PID{trigger.Pid()},
		ChildFileInfos: map[app.PID]*execpkg.FileInfo{trigger.Pid(): trigger},
	}
	ta.queueProcessAdmissionRetry(tracer, ie, false)
	require.Len(t, ta.pendingAdmissions, 1)
	pending := ta.pendingAdmissions[processAdmissionKey(trigger)]
	assert.NotContains(t, pending.processRoots, parent)
	assert.NotSame(t, triggerRoot, pending.processRoots[trigger])

	ta.retryPendingProcessAdmissions()

	assert.Empty(t, ta.pendingAdmissions)
	assert.Same(t, parent, ta.activePIDs[parent.Pid()])
	assert.Same(t, trigger, ta.activePIDs[trigger.Pid()])
	assert.Equal(t, []blockedPID{{pid: trigger.Pid(), ns: trigger.Ns()}}, program.allowed)
	require.NotNil(t, ta.processInstances[executableKey(parent)])
	assert.Equal(t, 1, *ta.processInstances[executableKey(parent)])
	assert.Contains(t, ta.activeEvents, processAdmissionKey(trigger))
	_, err = triggerRoot.Stat()
	require.Error(t, err)
}

func TestDeletingNonOwnerPrimaryRebasesRetryToEventOwner(t *testing.T) {
	parentRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	ownerRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	parent := execpkg.New(execpkg.Init{
		Pid: 42, Ns: 17, StartTime: 100, Ino: 1234, ProcessRoot: parentRoot,
	})
	owner := execpkg.New(execpkg.Init{
		Pid: 43, Ns: 18, StartTime: 200, Ino: 1234, ProcessRoot: ownerRoot,
	})
	program := &admissionRecordingTracer{
		admitted: map[app.PID]bool{owner.Pid(): true},
		pending: map[*execpkg.FileInfo]bool{
			parent: true,
			owner:  true,
		},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	ta := &traceAttacher{
		log:              slog.Default(),
		Metrics:          imetrics.NoopReporter{},
		existingTracers:  map[ebpf.ExecutableKey]executableTracer{},
		processInstances: helpermaps.MultiCounter[ebpf.ExecutableKey]{},
		activePIDs:       map[app.PID]*execpkg.FileInfo{},
		pendingIdentityCheck: func(_ *execpkg.FileInfo, root *os.File) bool {
			return root != nil
		},
	}
	ie := &ebpf.Instrumentable{
		FileInfo:       parent,
		ChildPids:      []app.PID{owner.Pid()},
		ChildFileInfos: map[app.PID]*execpkg.FileInfo{owner.Pid(): owner},
	}
	ta.queueProcessAdmissionRetry(tracer, ie, false)

	ta.notifyProcessDeletion(&ebpf.Instrumentable{FileInfo: parent})

	pending, exists := ta.pendingAdmissions[processAdmissionKey(owner)]
	require.True(t, exists)
	assert.True(t, pending.accountCreation)
	assert.Same(t, owner, pending.eventOwner)
	assert.Same(t, owner, pending.instrumentable.FileInfo)
	assert.Empty(t, pending.instrumentable.ChildPids)
	assert.False(t, program.pending[parent])
	assert.True(t, program.pending[owner])
	_, err = parentRoot.Stat()
	require.Error(t, err)
	_, err = ownerRoot.Stat()
	require.Error(t, err)
	retainedOwnerRoot := pending.processRoots[owner]
	require.NotNil(t, retainedOwnerRoot)
	_, err = retainedOwnerRoot.Stat()
	require.NoError(t, err)

	ta.retryPendingProcessAdmissions()

	assert.Empty(t, ta.pendingAdmissions)
	assert.Same(t, owner, ta.activePIDs[owner.Pid()])
	assert.Contains(t, ta.activeEvents, processAdmissionKey(owner))
	require.NotNil(t, ta.processInstances[executableKey(owner)])
	assert.Equal(t, 1, *ta.processInstances[executableKey(owner)])
	_, err = retainedOwnerRoot.Stat()
	require.Error(t, err)
}

func TestDeletingEventOwnerPreservesOnlyMemberRetries(t *testing.T) {
	parentRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	ownerRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	siblingRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	parent := execpkg.New(execpkg.Init{
		Pid: 42, Ns: 17, StartTime: 100, Ino: 1234, ProcessRoot: parentRoot,
	})
	owner := execpkg.New(execpkg.Init{
		Pid: 43, Ns: 18, StartTime: 200, Ino: 1234, ProcessRoot: ownerRoot,
	})
	sibling := execpkg.New(execpkg.Init{
		Pid: 44, Ns: 19, StartTime: 300, Ino: 1234, ProcessRoot: siblingRoot,
	})
	program := &admissionRecordingTracer{
		admitted: map[app.PID]bool{parent.Pid(): true, sibling.Pid(): true},
		pending: map[*execpkg.FileInfo]bool{
			parent:  true,
			owner:   true,
			sibling: true,
		},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	ta := &traceAttacher{
		log:              slog.Default(),
		Metrics:          imetrics.NoopReporter{},
		existingTracers:  map[ebpf.ExecutableKey]executableTracer{},
		processInstances: helpermaps.MultiCounter[ebpf.ExecutableKey]{},
		activePIDs:       map[app.PID]*execpkg.FileInfo{},
		pendingIdentityCheck: func(_ *execpkg.FileInfo, root *os.File) bool {
			return root != nil
		},
	}
	ta.queueProcessAdmissionRetry(tracer, &ebpf.Instrumentable{
		FileInfo:  parent,
		ChildPids: []app.PID{owner.Pid(), sibling.Pid()},
		ChildFileInfos: map[app.PID]*execpkg.FileInfo{
			owner.Pid():   owner,
			sibling.Pid(): sibling,
		},
	}, false)

	ta.notifyProcessDeletion(&ebpf.Instrumentable{FileInfo: owner})

	assert.NotContains(t, ta.pendingAdmissions, processAdmissionKey(owner))
	require.Len(t, ta.pendingAdmissions, 2)
	retainedRoots := map[*execpkg.FileInfo]*os.File{}
	for _, fileInfo := range []*execpkg.FileInfo{parent, sibling} {
		pending, exists := ta.pendingAdmissions[processAdmissionKeyFor(fileInfo, pendingMemberAdmission)]
		require.True(t, exists)
		assert.False(t, pending.accountCreation)
		assert.Nil(t, pending.eventOwner)
		assert.Same(t, fileInfo, pending.instrumentable.FileInfo)
		retainedRoots[fileInfo] = pending.processRoots[fileInfo]
	}
	assert.False(t, program.pending[owner])
	_, err = ownerRoot.Stat()
	require.Error(t, err)
	_, err = parentRoot.Stat()
	require.Error(t, err)
	_, err = siblingRoot.Stat()
	require.Error(t, err)
	for _, retainedRoot := range retainedRoots {
		require.NotNil(t, retainedRoot)
		_, err = retainedRoot.Stat()
		require.NoError(t, err)
	}

	ta.retryPendingProcessAdmissions()

	assert.Empty(t, ta.pendingAdmissions)
	assert.Same(t, parent, ta.activePIDs[parent.Pid()])
	assert.Same(t, sibling, ta.activePIDs[sibling.Pid()])
	assert.Empty(t, ta.processInstances)
	assert.Empty(t, ta.activeEvents)
	for _, retainedRoot := range retainedRoots {
		_, err = retainedRoot.Stat()
		require.Error(t, err)
	}
}

func TestStaleCollapsedRetryDoesNotCancelDistinctLiveGroup(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	startTimes := map[app.PID]uint64{42: 101, 43: 200, 44: 300}
	processStartTimeFunc = func(pid app.PID) uint64 { return startTimes[pid] }

	stalePrimary := execpkg.New(execpkg.Init{
		Pid: 42, Ns: 17, StartTime: 100, Ino: 1234,
	})
	overlap := execpkg.New(execpkg.Init{
		Pid: 43, Ns: 18, StartTime: 200, Ino: 1234,
	})
	otherChild := execpkg.New(execpkg.Init{
		Pid: 44, Ns: 19, StartTime: 300, Ino: 1234,
	})
	program := &admissionRecordingTracer{
		admitted: map[app.PID]bool{},
		pending: map[*execpkg.FileInfo]bool{
			stalePrimary: true,
			overlap:      true,
			otherChild:   true,
		},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	ta := &traceAttacher{
		Metrics:          imetrics.NoopReporter{},
		processInstances: helpermaps.MultiCounter[ebpf.ExecutableKey]{},
		activePIDs:       map[app.PID]*execpkg.FileInfo{},
	}
	ta.queueProcessAdmissionRetry(tracer, &ebpf.Instrumentable{
		FileInfo:       stalePrimary,
		ChildPids:      []app.PID{overlap.Pid()},
		ChildFileInfos: map[app.PID]*execpkg.FileInfo{overlap.Pid(): overlap},
	}, false)
	ta.queueProcessAdmissionRetry(tracer, &ebpf.Instrumentable{
		FileInfo:       overlap,
		ChildPids:      []app.PID{otherChild.Pid()},
		ChildFileInfos: map[app.PID]*execpkg.FileInfo{otherChild.Pid(): otherChild},
	}, false)
	require.Len(t, ta.pendingAdmissions, 2)

	ta.retryPendingProcessAdmissions()

	require.Len(t, ta.pendingAdmissions, 2)
	assert.False(t, program.pending[stalePrimary])
	assert.True(t, program.pending[overlap])
	assert.True(t, program.pending[otherChild])
	rebased, exists := ta.pendingAdmissions[processAdmissionKey(overlap)]
	require.True(t, exists)
	assert.Same(t, overlap, rebased.eventOwner)
	assert.Same(t, overlap, rebased.instrumentable.FileInfo)
}

func TestClosedInputCancelsPendingAdmissionOwnership(t *testing.T) {
	processRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	fileInfo := execpkg.New(execpkg.Init{
		Pid: 42, Ns: 17, StartTime: 100, Ino: 1234, ProcessRoot: processRoot,
	})
	program := &admissionRecordingTracer{
		pending: map[*execpkg.FileInfo]bool{fileInfo: true},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	ta := &traceAttacher{log: slog.Default()}
	ta.queueProcessAdmissionRetry(
		tracer,
		&ebpf.Instrumentable{FileInfo: fileInfo},
		false,
	)
	require.Len(t, ta.pendingAdmissions, 1)
	input := make(chan []Event[ebpf.Instrumentable])
	close(input)

	ta.forEachInstrumentableInput(
		context.Background(),
		input,
		func([]Event[ebpf.Instrumentable]) {},
	)

	assert.Empty(t, ta.pendingAdmissions)
	assert.False(t, program.pending[fileInfo])
	_, err = processRoot.Stat()
	require.Error(t, err)
}

func TestPendingRetryRollsBackWhenIdentityChangesDuringAllow(t *testing.T) {
	fileInfo := execpkg.New(execpkg.Init{
		Pid: 42, Ns: 17, StartTime: 100, Dev: 7, Ino: 1234,
	})
	program := &admissionRecordingTracer{
		admitted: map[app.PID]bool{fileInfo.Pid(): true},
		pending:  map[*execpkg.FileInfo]bool{fileInfo: true},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	checks := 0
	ta := &traceAttacher{
		Metrics:          imetrics.NoopReporter{},
		activePIDs:       map[app.PID]*execpkg.FileInfo{},
		processInstances: helpermaps.MultiCounter[ebpf.ExecutableKey]{},
		pendingIdentityCheck: func(got *execpkg.FileInfo, _ *os.File) bool {
			assert.Same(t, fileInfo, got)
			checks++
			return checks < 3
		},
	}
	ta.queueProcessAdmissionRetry(
		tracer,
		&ebpf.Instrumentable{FileInfo: fileInfo},
		false,
	)

	ta.retryPendingProcessAdmissions()

	assert.GreaterOrEqual(t, checks, 4)
	assert.Empty(t, ta.pendingAdmissions)
	assert.Empty(t, ta.activePIDs)
	assert.Empty(t, ta.processInstances)
	assert.Equal(t, []blockedPID{{pid: 42, ns: 17}}, program.blocked)
}

func TestSameTickSameInodeFileInfosHaveDistinctOwnership(t *testing.T) {
	oldFileInfo := execpkg.New(execpkg.Init{
		Pid: 42, Ns: 17, StartTime: 100, Dev: 7, Ino: 1234,
	})
	currentFileInfo := execpkg.New(execpkg.Init{
		Pid: 42, Ns: 17, StartTime: 100, Dev: 7, Ino: 1234,
	})
	oldKey := processAdmissionKey(oldFileInfo)
	currentKey := processAdmissionKey(currentFileInfo)
	assert.NotSame(t, oldKey.fileInfo, currentKey.fileInfo)
	program := &admissionRecordingTracer{
		pending: map[*execpkg.FileInfo]bool{currentFileInfo: true},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	ta := &traceAttacher{
		log:        slog.Default(),
		Metrics:    imetrics.NoopReporter{},
		activePIDs: map[app.PID]*execpkg.FileInfo{},
		activeEvents: map[pendingProcessAdmissionKey]struct{}{
			currentKey: {},
		},
	}
	ta.queueProcessAdmissionRetry(
		tracer,
		&ebpf.Instrumentable{FileInfo: currentFileInfo},
		false,
	)

	ta.notifyProcessDeletion(&ebpf.Instrumentable{FileInfo: oldFileInfo})

	assert.Contains(t, ta.pendingAdmissions, currentKey)
	assert.Contains(t, ta.activeEvents, currentKey)
	assert.True(t, program.pending[currentFileInfo])
}

func TestDeletedChildIsPrunedWithoutCancelingLiveSiblingRetry(t *testing.T) {
	deletedRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	siblingRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	parent := execpkg.New(execpkg.Init{Pid: 42, Ns: 17, StartTime: 100, Ino: 1234})
	trigger := execpkg.New(execpkg.Init{Pid: 43, Ns: 18, StartTime: 200, Ino: 1234})
	deleted := execpkg.New(execpkg.Init{
		Pid: 44, Ns: 19, StartTime: 300, Ino: 1234, ProcessRoot: deletedRoot,
	})
	sibling := execpkg.New(execpkg.Init{
		Pid: 45, Ns: 20, StartTime: 400, Ino: 1234, ProcessRoot: siblingRoot,
	})
	program := &admissionRecordingTracer{pending: map[*execpkg.FileInfo]bool{
		trigger: true,
		deleted: true,
		sibling: true,
	}}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	group := func(extra *execpkg.FileInfo) *ebpf.Instrumentable {
		return &ebpf.Instrumentable{
			FileInfo:  parent,
			ChildPids: []app.PID{trigger.Pid(), extra.Pid()},
			ChildFileInfos: map[app.PID]*execpkg.FileInfo{
				trigger.Pid(): trigger,
				extra.Pid():   extra,
			},
		}
	}
	ta := &traceAttacher{log: slog.Default(), activePIDs: map[app.PID]*execpkg.FileInfo{}}
	ta.queueProcessAdmissionRetry(tracer, group(deleted), false)
	ta.queueProcessAdmissionRetry(tracer, group(sibling), false)
	require.Len(t, ta.pendingAdmissions, 1)

	ta.notifyProcessDeletion(&ebpf.Instrumentable{FileInfo: deleted})

	require.Len(t, ta.pendingAdmissions, 1)
	pending := ta.pendingAdmissions[processAdmissionKey(trigger)]
	assert.NotContains(t, pending.instrumentable.ChildPids, deleted.Pid())
	assert.Contains(t, pending.instrumentable.ChildPids, sibling.Pid())
	assert.False(t, program.pending[deleted])
	assert.True(t, program.pending[sibling])
	_, err = deletedRoot.Stat()
	require.Error(t, err)
	ta.cancelAllProcessAdmissionRetries()
	_, err = siblingRoot.Stat()
	require.Error(t, err)
}

func TestDuplicateRetryDoesNotPromoteProbeUpdate(t *testing.T) {
	fileInfo := execpkg.New(execpkg.Init{Pid: 42, Ns: 17, StartTime: 100, Ino: 1234})
	program := &admissionRecordingTracer{pending: map[*execpkg.FileInfo]bool{fileInfo: true}}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	ta := &traceAttacher{}
	ie := &ebpf.Instrumentable{FileInfo: fileInfo}

	ta.queueProcessAdmissionRetry(tracer, ie, false)
	ta.queueProcessAdmissionRetry(tracer, ie, true)

	assert.False(t, ta.pendingAdmissions[processAdmissionKey(fileInfo)].updateTracerProbes)
	assert.False(t, ta.pendingTracerProbeUpdate(tracer, ie, true))

	other := &traceAttacher{}
	other.queueProcessAdmissionRetry(tracer, ie, true)
	other.queueProcessAdmissionRetry(tracer, ie, false)
	assert.True(t, other.pendingTracerProbeUpdate(tracer, ie, false))
}

func TestRetryQueueReplacementTransfersOwnedProcessRoot(t *testing.T) {
	processRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	fileInfo := execpkg.New(execpkg.Init{
		Pid: 42, Ns: 17, StartTime: 100, Ino: 1234, ProcessRoot: processRoot,
	})
	firstProgram := &admissionRecordingTracer{
		pending: map[*execpkg.FileInfo]bool{fileInfo: true},
	}
	secondProgram := &admissionRecordingTracer{
		pending: map[*execpkg.FileInfo]bool{fileInfo: true},
	}
	firstTracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{firstProgram}}
	secondTracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{secondProgram}}
	ta := &traceAttacher{}
	ie := &ebpf.Instrumentable{FileInfo: fileInfo}

	ta.queueProcessAdmissionRetry(firstTracer, ie, false)
	ta.queueProcessAdmissionRetry(secondTracer, ie, false)

	pending := ta.pendingAdmissions[processAdmissionKey(fileInfo)]
	assert.Same(t, secondTracer, pending.tracer)
	replacementRoot := pending.processRoots[fileInfo]
	require.NotNil(t, replacementRoot)
	assert.NotSame(t, processRoot, replacementRoot)
	_, err = processRoot.Stat()
	require.Error(t, err)
	_, err = replacementRoot.Stat()
	require.NoError(t, err)
	assert.False(t, firstProgram.pending[fileInfo])
	ta.cancelAllProcessAdmissionRetries()
	_, err = replacementRoot.Stat()
	require.Error(t, err)
}

func TestPartialChildRejectionRetriesWithoutCreationAccounting(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	processStartTimeFunc = func(pid app.PID) uint64 {
		return map[app.PID]uint64{42: 100, 43: 200, 44: 300}[pid]
	}
	parent := execpkg.New(execpkg.Init{Pid: 42, Ns: 17, StartTime: 100, Ino: 1234})
	trigger := execpkg.New(execpkg.Init{Pid: 43, Ns: 18, StartTime: 200, Ino: 1234})
	rejected := execpkg.New(execpkg.Init{Pid: 44, Ns: 19, StartTime: 300, Ino: 1234})
	program := &admissionRecordingTracer{
		admitted: map[app.PID]bool{42: true, 43: true, 44: false},
		pending:  map[*execpkg.FileInfo]bool{rejected: true},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	ta := &traceAttacher{
		Metrics:          imetrics.NoopReporter{},
		activePIDs:       map[app.PID]*execpkg.FileInfo{},
		processInstances: helpermaps.MultiCounter[ebpf.ExecutableKey]{},
	}
	ie := &ebpf.Instrumentable{
		FileInfo:  parent,
		ChildPids: []app.PID{trigger.Pid(), rejected.Pid()},
		ChildFileInfos: map[app.PID]*execpkg.FileInfo{
			trigger.Pid():  trigger,
			rejected.Pid(): rejected,
		},
	}

	require.True(t, ta.monitorPIDs(tracer, ie))
	memberKey := processAdmissionKeyFor(rejected, pendingMemberAdmission)
	require.Contains(t, ta.pendingAdmissions, memberKey)
	assert.False(t, ta.pendingAdmissions[memberKey].accountCreation)
	program.admitted[rejected.Pid()] = true
	ta.retryPendingProcessAdmissions()

	assert.Empty(t, ta.pendingAdmissions)
	assert.Same(t, rejected, ta.activePIDs[rejected.Pid()])
	assert.Empty(t, ta.processInstances)
	assert.Empty(t, ta.activeEvents)
}

func TestMemberRetryDoesNotCancelMatchingCreationOwner(t *testing.T) {
	fileInfo := execpkg.New(execpkg.Init{
		Pid: 42, Ns: 17, StartTime: 100, Ino: 1234,
	})
	program := &admissionRecordingTracer{
		pending: map[*execpkg.FileInfo]bool{fileInfo: true},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	groupKey := processAdmissionKey(fileInfo)
	memberKey := processAdmissionKeyFor(fileInfo, pendingMemberAdmission)
	member := pendingProcessAdmission{
		tracer:         tracer,
		instrumentable: &ebpf.Instrumentable{FileInfo: fileInfo},
	}
	ta := &traceAttacher{pendingAdmissions: map[pendingProcessAdmissionKey]pendingProcessAdmission{
		groupKey: {
			tracer:          tracer,
			instrumentable:  &ebpf.Instrumentable{FileInfo: fileInfo},
			eventOwner:      fileInfo,
			accountCreation: true,
		},
		memberKey: member,
	}}

	retained := map[*execpkg.FileInfo]struct{}{}
	if ta.pendingCreationOwnsFileInfo(memberKey, tracer, fileInfo) {
		retained[fileInfo] = struct{}{}
	}
	cancelPendingProcessAdmissionExcept(member, retained)

	assert.True(t, program.pending[fileInfo])
	assert.Contains(t, ta.pendingAdmissions, groupKey)
}

func TestCreationAccountingUsesImmutableEventOwner(t *testing.T) {
	primary := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/primary", Pid: 42, StartTime: 100, Ino: 1234,
	})
	owner := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/owner", Pid: 43, StartTime: 200, Ino: 5678,
	})
	ie := &ebpf.Instrumentable{
		FileInfo:  primary,
		ChildPids: []app.PID{owner.Pid()},
		ChildFileInfos: map[app.PID]*execpkg.FileInfo{
			owner.Pid(): owner,
		},
	}
	events := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(2))
	eventCh := events.Subscribe()
	ta := &traceAttacher{OutputTracerEvents: events}

	require.True(t, ta.completeProcessCreationForOwner(ie, owner))
	created := testutil.ReadChannel(t, eventCh, testTimeout)

	assert.Same(t, owner, created.Obj.FileInfo)
	assert.NotContains(t, ta.processInstances, executableKey(primary))
	require.NotNil(t, ta.processInstances[executableKey(owner)])
	assert.Equal(t, 1, *ta.processInstances[executableKey(owner)])
}

func TestRetryPartialChildRejectionRetainsMemberAdmission(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	processStartTimeFunc = func(pid app.PID) uint64 {
		return map[app.PID]uint64{42: 100, 43: 200, 44: 300}[pid]
	}

	rejectedRoot, err := os.Open(t.TempDir())
	require.NoError(t, err)
	parent := execpkg.New(execpkg.Init{Pid: 42, Ns: 17, StartTime: 100, Ino: 1234})
	trigger := execpkg.New(execpkg.Init{Pid: 43, Ns: 18, StartTime: 200, Ino: 1234})
	rejected := execpkg.New(execpkg.Init{
		Pid: 44, Ns: 19, StartTime: 300, Ino: 1234, ProcessRoot: rejectedRoot,
	})
	program := &admissionRecordingTracer{
		admitted: map[app.PID]bool{42: true, 43: true, 44: false},
		pending: map[*execpkg.FileInfo]bool{
			trigger:  true,
			rejected: true,
		},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	ie := &ebpf.Instrumentable{
		FileInfo:  parent,
		ChildPids: []app.PID{trigger.Pid(), rejected.Pid()},
		ChildFileInfos: map[app.PID]*execpkg.FileInfo{
			trigger.Pid():  trigger,
			rejected.Pid(): rejected,
		},
	}
	ta := &traceAttacher{
		Metrics:          imetrics.NoopReporter{},
		existingTracers:  map[ebpf.ExecutableKey]executableTracer{},
		activePIDs:       map[app.PID]*execpkg.FileInfo{},
		processInstances: helpermaps.MultiCounter[ebpf.ExecutableKey]{},
	}
	ta.queueProcessAdmissionRetry(tracer, ie, false)

	ta.retryPendingProcessAdmissions()

	memberKey := processAdmissionKeyFor(rejected, pendingMemberAdmission)
	require.Len(t, ta.pendingAdmissions, 1)
	require.Contains(t, ta.pendingAdmissions, memberKey)
	assert.False(t, ta.pendingAdmissions[memberKey].accountCreation)
	assert.False(t, program.pending[trigger])
	assert.True(t, program.pending[rejected])
	retainedRejectedRoot := ta.pendingAdmissions[memberKey].processRoots[rejected]
	require.NotNil(t, retainedRejectedRoot)
	_, err = rejectedRoot.Stat()
	require.Error(t, err)
	_, err = retainedRejectedRoot.Stat()
	require.NoError(t, err)
	require.NotNil(t, ta.processInstances[executableKey(parent)])
	assert.Equal(t, 1, *ta.processInstances[executableKey(parent)])
	assert.Len(t, ta.activeEvents, 1)

	program.admitted[rejected.Pid()] = true
	ta.retryPendingProcessAdmissions()

	assert.Empty(t, ta.pendingAdmissions)
	assert.False(t, program.pending[rejected])
	assert.Same(t, rejected, ta.activePIDs[rejected.Pid()])
	assert.Equal(t, 1, *ta.processInstances[executableKey(parent)])
	assert.Len(t, ta.activeEvents, 1)
	_, err = retainedRejectedRoot.Stat()
	require.Error(t, err)
}

func TestExactDuplicateCreationIsAccountedOnce(t *testing.T) {
	fileInfo := execpkg.New(execpkg.Init{Pid: 42, Ns: 17, StartTime: 100, Ino: 1234})
	ie := &ebpf.Instrumentable{FileInfo: fileInfo}
	events := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(2))
	eventCh := events.Subscribe()
	ta := &traceAttacher{OutputTracerEvents: events}

	assert.True(t, ta.completeProcessCreation(ie))
	assert.False(t, ta.completeProcessCreation(ie))

	require.NotNil(t, ta.processInstances[executableKey(fileInfo)])
	assert.Equal(t, 1, *ta.processInstances[executableKey(fileInfo)])
	assert.Equal(t, EventCreated, testutil.ReadChannel(t, eventCh, testTimeout).Type)
	select {
	case duplicate := <-eventCh:
		t.Fatalf("unexpected duplicate event: %v", duplicate.Type)
	default:
	}
}

func TestGetTracerAdmitsExistingGoProcessOnce(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	processStartTimeFunc = func(app.PID) uint64 { return 100 }

	fileInfo := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test",
		Pid:        42,
		StartTime:  100,
		Ino:        1234,
		Ns:         17,
	})
	program := &admissionRecordingTracer{admitted: map[app.PID]bool{42: true}}
	tracer := &ebpf.ProcessTracer{
		Type:     ebpf.Go,
		Programs: []ebpf.Tracer{program},
	}
	cfg := &obi.Config{}
	ta := &traceAttacher{
		log:     slog.Default(),
		Cfg:     cfg,
		Metrics: imetrics.NoopReporter{},
		existingTracers: map[ebpf.ExecutableKey]executableTracer{
			executableKey(fileInfo): {tracer: tracer},
		},
		reusableGoTracer: tracer,
		routeHarvester: harvest.NewRouteHarvester(
			&cfg.Discovery.RouteHarvestConfig,
			cfg.Discovery.DisabledRouteHarvesters,
			testTimeout,
		),
	}

	assert.True(t, ta.getTracer(&ebpf.Instrumentable{
		Type:     svc.InstrumentableGolang,
		FileInfo: fileInfo,
	}))
	assert.Equal(t, []blockedPID{{pid: 42, ns: 17}}, program.allowed)
}

func TestInitializedTracerIsHandedOffBeforeProcessCreation(t *testing.T) {
	events := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(2))
	eventCh := events.Subscribe()
	tracer := &ebpf.ProcessTracer{Type: ebpf.Go}
	instrumentable := &ebpf.Instrumentable{
		FileInfo: execpkg.New(execpkg.Init{
			Pid:       42,
			StartTime: 100,
			Ino:       1234,
		}),
	}
	ta := &traceAttacher{OutputTracerEvents: events}

	ta.handoffInitializedTracer(tracer, instrumentable)
	events.Send(Event[*ebpf.Instrumentable]{
		Type: EventCreated,
		Obj:  instrumentable,
	})

	initialized := testutil.ReadChannel(t, eventCh, testTimeout)
	assert.Equal(t, EventTracerInitialized, initialized.Type)
	assert.Same(t, instrumentable, initialized.Obj)
	assert.Same(t, tracer, initialized.Obj.Tracer)
	created := testutil.ReadChannel(t, eventCh, testTimeout)
	assert.Equal(t, EventCreated, created.Type)
	assert.Same(t, tracer, ta.reusableGoTracer)
	assert.Nil(t, ta.reusableTracer)
}

func TestMonitorPIDsRollsBackRejectedCollapsedGroup(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	processStartTimeFunc = func(pid app.PID) uint64 {
		return map[app.PID]uint64{42: 100, 43: 200}[pid]
	}

	parent := execpkg.New(execpkg.Init{Pid: 42, Ns: 17, StartTime: 100})
	child := execpkg.New(execpkg.Init{Pid: 43, Ns: 18, StartTime: 200})
	instrumentable := &ebpf.Instrumentable{
		FileInfo:       parent,
		ChildPids:      []app.PID{43},
		ChildFileInfos: map[app.PID]*execpkg.FileInfo{43: child},
	}
	primary := &admissionRecordingTracer{
		admitted: map[app.PID]bool{42: true, 43: false},
	}
	inProcessCommon := &recordingTracer{}
	externalCommon := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{
		Programs: []ebpf.Tracer{primary, inProcessCommon},
	}
	ta := &traceAttacher{commonTracers: []ebpf.Tracer{externalCommon}}

	assert.False(t, ta.monitorPIDs(tracer, instrumentable))
	assert.Equal(
		t,
		[]blockedPID{{pid: 42, ns: 17}, {pid: 43, ns: 18}},
		primary.allowed,
	)
	assert.Equal(t, []blockedPID{{pid: 42, ns: 17}}, inProcessCommon.allowed)
	assert.Equal(t, []blockedPID{{pid: 42, ns: 17}, {pid: 43, ns: 18}}, primary.blocked)
	assert.Equal(t, []blockedPID{{pid: 42, ns: 17}, {pid: 43, ns: 18}}, inProcessCommon.blocked)
	assert.Empty(t, externalCommon.allowed)
	assert.Empty(t, externalCommon.blocked)
	assert.Empty(t, ta.activePIDs)
}

func TestRejectedNewCollapsedGroupCleanupSurvivesPIDReuse(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	startTimes := map[app.PID]uint64{42: 100, 43: 200}
	processStartTimeFunc = func(pid app.PID) uint64 {
		return startTimes[pid]
	}

	const ino = uint64(1234)
	parent := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test",
		Pid:        42,
		StartTime:  100,
		Ino:        ino,
		Ns:         17,
	})
	child := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test",
		Pid:        43,
		Ppid:       42,
		StartTime:  200,
		Ino:        ino,
		Ns:         18,
	})
	admission := &admissionRecordingTracer{
		admitted: map[app.PID]bool{parent.Pid(): true, child.Pid(): false},
	}
	unlink := &unlinkRecordingTracer{}
	tracer := &ebpf.ProcessTracer{
		Type:     ebpf.Go,
		Programs: []ebpf.Tracer{admission, unlink},
	}
	cfg := &obi.Config{}
	events := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(2))
	eventCh := events.Subscribe()
	ta := &traceAttacher{
		log:                slog.Default(),
		Cfg:                cfg,
		Metrics:            imetrics.NoopReporter{},
		existingTracers:    map[ebpf.ExecutableKey]executableTracer{},
		processInstances:   helpermaps.MultiCounter[ebpf.ExecutableKey]{},
		activePIDs:         map[app.PID]*execpkg.FileInfo{},
		unlinkExecutableFn: readinessOnlyUnlink,
		OutputTracerEvents: events,
		routeHarvester: harvest.NewRouteHarvester(
			&cfg.Discovery.RouteHarvestConfig,
			cfg.Discovery.DisabledRouteHarvesters,
			testTimeout,
		),
	}
	instrumentable := &ebpf.Instrumentable{
		FileInfo:       parent,
		ChildPids:      []app.PID{child.Pid()},
		ChildFileInfos: map[app.PID]*execpkg.FileInfo{child.Pid(): child},
	}

	require.False(t, ta.monitorPIDs(tracer, instrumentable))
	assert.Empty(t, ta.activePIDs)
	assert.NotContains(t, ta.processInstances, ebpf.ExecutableKey{Ino: ino})

	ta.unlinkRejectedExecutable(tracer, parent, 0)
	assert.Same(t, tracer, ta.existingTracers[ebpf.ExecutableKey{Ino: ino}].tracer)
	assert.Contains(t, ta.pendingUnlinks, ebpf.ExecutableKey{Ino: ino})
	assert.Equal(t, 1, unlink.unlinkChecks)

	ta.notifyProcessDeletion(&ebpf.Instrumentable{FileInfo: parent})
	ta.retryPendingExecutableUnlinks()
	select {
	case event := <-eventCh:
		t.Fatalf("unexpected event for rejected process: %v", event.Type)
	default:
	}
	assert.Empty(t, ta.activePIDs)
	assert.NotContains(t, ta.processInstances, ebpf.ExecutableKey{Ino: ino})
	assert.Same(t, tracer, ta.existingTracers[ebpf.ExecutableKey{Ino: ino}].tracer)
	assert.Contains(t, ta.pendingUnlinks, ebpf.ExecutableKey{Ino: ino})
	assert.Equal(t, 2, unlink.unlinkChecks)

	startTimes[parent.Pid()] = 300
	reused := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test",
		Pid:        parent.Pid(),
		StartTime:  300,
		Ino:        ino,
		Ns:         parent.Ns(),
	})
	admission.admitted[reused.Pid()] = true
	unlink.unlinkReady = true
	reusedInstrumentable := &ebpf.Instrumentable{
		Type:     svc.InstrumentableGolang,
		FileInfo: reused,
	}
	require.True(t, ta.getTracer(reusedInstrumentable))
	require.True(t, ta.completeProcessCreation(reusedInstrumentable))
	created := testutil.ReadChannel(t, eventCh, testTimeout)
	assert.Equal(t, EventCreated, created.Type)

	ta.retryPendingExecutableUnlinks()
	assert.Same(t, tracer, ta.existingTracers[ebpf.ExecutableKey{Ino: ino}].tracer)
	assert.Contains(t, ta.pendingUnlinks, ebpf.ExecutableKey{Ino: ino})
	assert.Equal(t, 2, unlink.unlinkChecks)

	ta.notifyProcessDeletion(&ebpf.Instrumentable{FileInfo: reused})
	deleted := testutil.ReadChannel(t, eventCh, testTimeout)
	assert.Equal(t, EventDeleted, deleted.Type)
	assert.NotContains(t, ta.processInstances, ebpf.ExecutableKey{Ino: ino})
	assert.NotContains(t, ta.existingTracers, ebpf.ExecutableKey{Ino: ino})
	assert.NotContains(t, ta.pendingUnlinks, ebpf.ExecutableKey{Ino: ino})
	assert.Equal(t, 3, unlink.unlinkChecks)

	ta.notifyProcessDeletion(&ebpf.Instrumentable{FileInfo: reused})
	assert.NotContains(t, ta.processInstances, ebpf.ExecutableKey{Ino: ino})
}

func TestMonitorPIDsPreservesChildServiceConfiguration(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	processStartTimeFunc = func(pid app.PID) uint64 {
		return map[app.PID]uint64{42: 100, 43: 200}[pid]
	}

	parentSampler := &services.CanonicalSampler{Type: services.SamplerTypeAlwaysOn}
	childSampler := &services.CanonicalSampler{Type: services.SamplerTypeAlwaysOff}
	parent := execpkg.New(execpkg.Init{
		Service: svc.Attrs{
			UID:           svc.UID{Name: "parent"},
			SamplerConfig: parentSampler,
		},
		CmdExePath: "/bin/test",
		Pid:        42,
		StartTime:  100,
		Ns:         17,
	})
	child := execpkg.New(execpkg.Init{
		Service: svc.Attrs{
			UID:           svc.UID{Name: "child"},
			SamplerConfig: childSampler,
		},
		CmdExePath: "/bin/test",
		Pid:        43,
		Ppid:       42,
		StartTime:  200,
		Ns:         18,
	})
	ie := &ebpf.Instrumentable{
		Type:           svc.InstrumentableGeneric,
		FileInfo:       parent,
		ChildPids:      []app.PID{child.Pid()},
		ChildFileInfos: map[app.PID]*execpkg.FileInfo{child.Pid(): child},
	}

	processProgram := &recordingTracer{}
	commonProgram := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{processProgram}}
	ta := &traceAttacher{commonTracers: []ebpf.Tracer{commonProgram}}

	assert.True(t, ta.monitorPIDs(tracer, ie))

	for _, program := range []*recordingTracer{processProgram, commonProgram} {
		assert.Equal(t, []blockedPID{{pid: 42, ns: 17}, {pid: 43, ns: 18}}, program.allowed)
		assert.Same(t, parent, program.allowedFileInfos[42])
		assert.Same(t, child, program.allowedFileInfos[43])
		assert.Same(t, parentSampler, program.allowedFileInfos[42].ServiceAttrs().SamplerConfig)
		assert.Same(t, childSampler, program.allowedFileInfos[43].ServiceAttrs().SamplerConfig)
	}
}

func TestBlockPIDForProcessFallsBackToLegacyAccounter(t *testing.T) {
	accounter := &legacyPIDAccounter{}
	fileInfo := execpkg.New(execpkg.Init{Pid: 42, Ns: 17, StartTime: 100})

	ebpf.BlockPIDForProcess(accounter, 42, 17, fileInfo)

	assert.Equal(t, []blockedPID{{pid: 42, ns: 17}}, accounter.blocked)
}

func TestAttacherDoesNotCountRejectedProcess(t *testing.T) {
	originalRemoveMemlock := removeMemlock
	t.Cleanup(func() { removeMemlock = originalRemoveMemlock })
	removeMemlock = func() error { return nil }

	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	processStartTimeFunc = func(pid app.PID) uint64 {
		require.Equal(t, app.PID(42), pid)
		return 100
	}

	instrumentables := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(1))
	tracerEvents := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(1))
	ta := &traceAttacher{
		Cfg:                  &obi.Config{},
		Metrics:              imetrics.NoopReporter{},
		InputInstrumentables: instrumentables,
		OutputTracerEvents:   tracerEvents,
		EbpfEventContext:     &ebpfcommon.EBPFEventContext{},
		unlinkExecutableFn:   readinessOnlyUnlink,
	}
	run, err := ta.attacherLoop(t.Context())
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		run(t.Context())
		close(done)
	}()

	instrumentables.Send([]Event[ebpf.Instrumentable]{{
		Type: EventCreated,
		Obj: ebpf.Instrumentable{
			Type: svc.InstrumentableUnknown,
			FileInfo: execpkg.New(execpkg.Init{
				CmdExePath: "/bin/unsupported",
				Pid:        42,
				StartTime:  100,
				Ino:        1234,
			}),
		},
	}})
	instrumentables.Close()
	testutil.ReadChannel(t, done, testTimeout)

	assert.NotContains(t, ta.processInstances, ebpf.ExecutableKey{Ino: 1234})
}

func TestAttacherRejectedGroupedChildDoesNotLeakParentTracer(t *testing.T) {
	originalRemoveMemlock := removeMemlock
	t.Cleanup(func() { removeMemlock = originalRemoveMemlock })
	removeMemlock = func() error { return nil }

	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	processStartTimeFunc = func(pid app.PID) uint64 {
		return map[app.PID]uint64{42: 100, 43: 200}[pid]
	}

	const ino = uint64(1234)
	parent := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test",
		Pid:        42,
		StartTime:  100,
		Ino:        ino,
		Ns:         17,
	})
	child := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test",
		Pid:        43,
		Ppid:       42,
		StartTime:  200,
		Ino:        ino,
		Ns:         18,
	})
	admission := &admissionRecordingTracer{
		admitted: map[app.PID]bool{parent.Pid(): true, child.Pid(): false},
	}
	unlink := &unlinkRecordingTracer{unlinkReady: true}
	tracer := &ebpf.ProcessTracer{
		Type:     ebpf.Go,
		Programs: []ebpf.Tracer{admission, unlink},
	}

	instrumentables := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(3))
	tracerEvents := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(3))
	eventCh := tracerEvents.Subscribe()
	ta := &traceAttacher{
		Cfg:                  &obi.Config{},
		Metrics:              imetrics.NoopReporter{},
		InputInstrumentables: instrumentables,
		OutputTracerEvents:   tracerEvents,
		EbpfEventContext:     &ebpfcommon.EBPFEventContext{},
		unlinkExecutableFn:   readinessOnlyUnlink,
	}
	run, err := ta.attacherLoop(t.Context())
	require.NoError(t, err)
	key := ebpf.ExecutableKey{Ino: ino}
	ta.existingTracers[key] = executableTracer{tracer: tracer}
	ta.processInstances.Inc(key)
	ta.activePIDs[parent.Pid()] = parent
	ta.activePIDTracers[parent] = tracer
	creationKey := processAdmissionKey(parent)
	ta.activeEvents[creationKey] = struct{}{}
	ta.activeExecutables[creationKey] = activeExecutable{key: key, tracer: tracer}

	done := make(chan struct{})
	go func() {
		run(t.Context())
		close(done)
	}()

	instrumentables.Send([]Event[ebpf.Instrumentable]{{
		Type: EventCreated,
		Obj: ebpf.Instrumentable{
			Type:           svc.InstrumentableGolang,
			FileInfo:       parent,
			ChildPids:      []app.PID{child.Pid()},
			ChildFileInfos: map[app.PID]*execpkg.FileInfo{child.Pid(): child},
		},
	}})
	require.NotNil(t, ta.processInstances[ebpf.ExecutableKey{Ino: ino}])
	assert.Equal(t, 1, *ta.processInstances[ebpf.ExecutableKey{Ino: ino}])
	assert.NotContains(t, ta.activePIDs, child.Pid())

	instrumentables.Send([]Event[ebpf.Instrumentable]{{
		Type: EventDeleted,
		Obj:  ebpf.Instrumentable{FileInfo: parent},
	}})

	deleted := testutil.ReadChannel(t, eventCh, testTimeout)
	require.Equal(t, EventDeleted, deleted.Type)
	assert.NotContains(t, ta.processInstances, ebpf.ExecutableKey{Ino: ino})
	assert.NotContains(t, ta.existingTracers, ebpf.ExecutableKey{Ino: ino})
	assert.Equal(t, 1, unlink.unlinkChecks)

	instrumentables.Close()
	testutil.ReadChannel(t, done, testTimeout)
	for event := range eventCh {
		assert.NotEqual(t, EventCreated, event.Type)
	}
}

func TestSyntheticDeletePath_TraceAttacherDeletesTracer(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	origRemoveMemlock := removeMemlock
	removeMemlock = func() error { return nil }
	defer func() { removeMemlock = origRemoveMemlock }()

	processMatches := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	instrumentables := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	tracerEventsQu := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	tracerEvents := tracerEventsQu.Subscribe()

	fileInfo := execpkg.New(execpkg.Init{
		Service:    svc.Attrs{UID: svc.UID{Name: "dyn-svc", Namespace: "ns"}},
		CmdExePath: "/bin/test",
		Pid:        42,
		StartTime:  100,
		Ino:        1234,
		Ns:         17,
	})
	startDeletedTyperPipeline(ctx, &typer{
		log:         slog.Default(),
		currentPids: map[app.PID]*execpkg.FileInfo{42: fileInfo},
	}, processMatches, instrumentables)

	ta := &traceAttacher{
		Cfg:                  &obi.Config{},
		Metrics:              imetrics.NoopReporter{},
		InputInstrumentables: instrumentables,
		OutputTracerEvents:   tracerEventsQu,
		EbpfEventContext:     &ebpfcommon.EBPFEventContext{},
	}
	run, err := ta.attacherLoop(ctx)
	require.NoError(t, err)

	prog := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{Type: ebpf.Generic, Programs: []ebpf.Tracer{prog}}
	key := executableKey(fileInfo)
	ta.existingTracers[key] = executableTracer{tracer: tracer, generation: 1}
	ta.processInstances.Inc(key)
	ta.activePIDs[fileInfo.Pid()] = fileInfo
	ta.activePIDTracers[fileInfo] = tracer
	creationKey := processAdmissionKey(fileInfo)
	ta.activeEvents[creationKey] = struct{}{}
	ta.activeExecutables[creationKey] = activeExecutable{
		key: key, tracer: tracer, generation: 1,
	}

	go run(ctx)

	processMatches.Send([]Event[ProcessMatch]{{
		Type: EventDeleted,
		Obj: ProcessMatch{
			Process: &services.ProcessInfo{Pid: 42, StartTime: 100},
		},
	}})

	ev := testutil.ReadChannel(t, tracerEvents, testTimeout)
	require.Equal(t, EventDeleted, ev.Type)
	require.NotNil(t, ev.Obj)
	assert.Equal(t, app.PID(42), ev.Obj.FileInfo.Pid())
	assert.Same(t, tracer, ev.Obj.Tracer)
	assert.Equal(t, uint64(1), ev.Obj.ExecutableGeneration)
	assert.Equal(t, []blockedPID{{pid: 42, ns: 17}}, prog.blocked)
	_, exists := ta.existingTracers[key]
	assert.False(t, exists)
}

func TestSyntheticDeletePath_TraceAttacherDeletesInstance(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	origRemoveMemlock := removeMemlock
	removeMemlock = func() error { return nil }
	defer func() { removeMemlock = origRemoveMemlock }()

	processMatches := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	instrumentables := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	tracerEventsQu := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	tracerEvents := tracerEventsQu.Subscribe()

	fileInfo := execpkg.New(execpkg.Init{
		Service:    svc.Attrs{UID: svc.UID{Name: "dyn-svc", Namespace: "ns"}},
		CmdExePath: "/bin/test",
		Pid:        42,
		StartTime:  100,
		Ino:        1234,
		Ns:         17,
	})
	startDeletedTyperPipeline(ctx, &typer{
		log:         slog.Default(),
		currentPids: map[app.PID]*execpkg.FileInfo{42: fileInfo},
	}, processMatches, instrumentables)

	ta := &traceAttacher{
		Cfg:                  &obi.Config{},
		Metrics:              imetrics.NoopReporter{},
		InputInstrumentables: instrumentables,
		OutputTracerEvents:   tracerEventsQu,
		EbpfEventContext:     &ebpfcommon.EBPFEventContext{},
	}
	run, err := ta.attacherLoop(ctx)
	require.NoError(t, err)

	prog := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{Type: ebpf.Generic, Programs: []ebpf.Tracer{prog}}
	key := executableKey(fileInfo)
	ta.existingTracers[key] = executableTracer{tracer: tracer, generation: 1}
	ta.processInstances.Inc(key)
	ta.processInstances.Inc(key)
	ta.activePIDs[fileInfo.Pid()] = fileInfo
	ta.activePIDTracers[fileInfo] = tracer
	creationKey := processAdmissionKey(fileInfo)
	ta.activeEvents[creationKey] = struct{}{}
	ta.activeExecutables[creationKey] = activeExecutable{
		key: key, tracer: tracer, generation: 1,
	}

	go run(ctx)

	processMatches.Send([]Event[ProcessMatch]{{
		Type: EventDeleted,
		Obj: ProcessMatch{
			Process: &services.ProcessInfo{Pid: 42, StartTime: 100},
		},
	}})

	ev := testutil.ReadChannel(t, tracerEvents, testTimeout)
	require.Equal(t, EventInstanceDeleted, ev.Type)
	require.NotNil(t, ev.Obj)
	assert.Equal(t, app.PID(42), ev.Obj.FileInfo.Pid())
	assert.Nil(t, ev.Obj.Tracer)
	assert.Equal(t, []blockedPID{{pid: 42, ns: 17}}, prog.blocked)
	require.Len(t, prog.blockedFileInfos, 1)
	assert.Same(t, fileInfo, prog.blockedFileInfos[0])
	assert.Same(t, tracer, ta.existingTracers[key].tracer)
}

func TestUnaccountedMemberDeletionDoesNotConsumeCreationOwnership(t *testing.T) {
	const ino = uint64(1234)
	trigger := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test", Pid: 42, StartTime: 100, Ino: ino, Ns: 17,
	})
	member := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test", Pid: 43, StartTime: 200, Ino: ino, Ns: 18,
	})
	program := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{Type: ebpf.Generic, Programs: []ebpf.Tracer{program}}
	instances := helpermaps.MultiCounter[ebpf.ExecutableKey]{}
	instances.Inc(ebpf.ExecutableKey{Ino: ino})
	metrics := &recordingMetrics{}
	events := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(1))
	eventCh := events.Subscribe()
	ta := &traceAttacher{
		log:     slog.Default(),
		Metrics: metrics,
		existingTracers: map[ebpf.ExecutableKey]executableTracer{
			{Ino: ino}: {tracer: tracer},
		},
		processInstances: instances,
		activePIDs: map[app.PID]*execpkg.FileInfo{
			trigger.Pid(): trigger,
			member.Pid():  member,
		},
		activeEvents: map[pendingProcessAdmissionKey]struct{}{
			processAdmissionKey(trigger): {},
		},
		OutputTracerEvents: events,
	}

	ta.notifyProcessDeletion(&ebpf.Instrumentable{FileInfo: member})

	assert.NotContains(t, ta.activePIDs, member.Pid())
	assert.Same(t, trigger, ta.activePIDs[trigger.Pid()])
	require.NotNil(t, ta.processInstances[ebpf.ExecutableKey{Ino: ino}])
	assert.Equal(t, 1, *ta.processInstances[ebpf.ExecutableKey{Ino: ino}])
	assert.Contains(t, ta.activeEvents, processAdmissionKey(trigger))
	assert.Same(t, tracer, ta.existingTracers[ebpf.ExecutableKey{Ino: ino}].tracer)
	assert.Empty(t, metrics.uninstrumented)
	assert.Equal(t, []blockedPID{{pid: member.Pid(), ns: member.Ns()}}, program.blocked)
	select {
	case event := <-eventCh:
		t.Fatalf("unexpected accounting event for member deletion: %v", event.Type)
	default:
	}
}

func TestDelayedOwnedDeletionAccountsAfterPIDReuse(t *testing.T) {
	const (
		oldIno = uint64(1234)
		newIno = uint64(5678)
	)
	oldFileInfo := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/old", Pid: 42, StartTime: 100, Ino: oldIno, Ns: 17,
	})
	newFileInfo := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/new", Pid: 42, StartTime: 200, Ino: newIno, Ns: 18,
	})
	oldProgram := &recordingTracer{}
	newProgram := &recordingTracer{}
	oldTracer := &ebpf.ProcessTracer{Type: ebpf.Generic, Programs: []ebpf.Tracer{oldProgram}}
	newTracer := &ebpf.ProcessTracer{Type: ebpf.Generic, Programs: []ebpf.Tracer{newProgram}}
	instances := helpermaps.MultiCounter[ebpf.ExecutableKey]{}
	instances.Inc(ebpf.ExecutableKey{Ino: oldIno})
	instances.Inc(ebpf.ExecutableKey{Ino: newIno})
	metrics := &recordingMetrics{}
	events := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(2))
	eventCh := events.Subscribe()
	ta := &traceAttacher{
		log:     slog.Default(),
		Metrics: metrics,
		existingTracers: map[ebpf.ExecutableKey]executableTracer{
			{Ino: oldIno}: {tracer: oldTracer},
			{Ino: newIno}: {tracer: newTracer},
		},
		processInstances: instances,
		activePIDs: map[app.PID]*execpkg.FileInfo{
			newFileInfo.Pid(): newFileInfo,
		},
		activeEvents: map[pendingProcessAdmissionKey]struct{}{
			processAdmissionKey(oldFileInfo): {},
			processAdmissionKey(newFileInfo): {},
		},
		OutputTracerEvents: events,
	}

	ta.notifyProcessDeletion(&ebpf.Instrumentable{FileInfo: oldFileInfo})

	deleted := testutil.ReadChannel(t, eventCh, testTimeout)
	assert.Equal(t, EventDeleted, deleted.Type)
	assert.Same(t, oldTracer, deleted.Obj.Tracer)
	assert.NotContains(t, ta.processInstances, ebpf.ExecutableKey{Ino: oldIno})
	assert.NotContains(t, ta.existingTracers, ebpf.ExecutableKey{Ino: oldIno})
	assert.NotContains(t, ta.activeEvents, processAdmissionKey(oldFileInfo))
	newKey := ebpf.ExecutableKey{Ino: newIno}
	require.NotNil(t, ta.processInstances[newKey])
	assert.Equal(t, 1, *ta.processInstances[newKey])
	assert.Same(t, newTracer, ta.existingTracers[newKey].tracer)
	assert.Contains(t, ta.activeEvents, processAdmissionKey(newFileInfo))
	assert.Same(t, newFileInfo, ta.activePIDs[newFileInfo.Pid()])
	assert.Equal(t, []string{oldFileInfo.ExecutableName()}, metrics.uninstrumented)
	assert.Empty(t, oldProgram.blocked)
	assert.Empty(t, newProgram.blocked)

	ta.notifyProcessDeletion(&ebpf.Instrumentable{FileInfo: oldFileInfo})

	require.NotNil(t, ta.processInstances[newKey])
	assert.Equal(t, 1, *ta.processInstances[newKey])
	assert.Equal(t, []string{oldFileInfo.ExecutableName()}, metrics.uninstrumented)
	select {
	case event := <-eventCh:
		t.Fatalf("unexpected duplicate deletion event: %v", event.Type)
	default:
	}
}

func TestProcessDeletionRetainsTracerUntilExecutableCleanupIsReady(t *testing.T) {
	const ino = uint64(1234)
	fileInfo := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test",
		Pid:        42,
		StartTime:  100,
		Ino:        ino,
		Ns:         17,
	})
	program := &unlinkRecordingTracer{}
	tracer := &ebpf.ProcessTracer{
		Type:     ebpf.Go,
		Programs: []ebpf.Tracer{program},
	}
	instances := helpermaps.MultiCounter[ebpf.ExecutableKey]{}
	instances.Inc(ebpf.ExecutableKey{Ino: ino})
	events := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(2))
	eventCh := events.Subscribe()
	ta := &traceAttacher{
		log:     slog.Default(),
		Metrics: imetrics.NoopReporter{},
		existingTracers: map[ebpf.ExecutableKey]executableTracer{
			{Ino: ino}: {tracer: tracer},
		},
		processInstances:   instances,
		activePIDs:         map[app.PID]*execpkg.FileInfo{fileInfo.Pid(): fileInfo},
		unlinkExecutableFn: readinessOnlyUnlink,
		activeEvents: map[pendingProcessAdmissionKey]struct{}{
			processAdmissionKey(fileInfo): {},
		},
		OutputTracerEvents: events,
	}

	ta.notifyProcessDeletion(&ebpf.Instrumentable{FileInfo: fileInfo})

	firstEvent := testutil.ReadChannel(t, eventCh, testTimeout)
	assert.Equal(t, EventInstanceDeleted, firstEvent.Type)
	assert.Same(t, tracer, ta.existingTracers[ebpf.ExecutableKey{Ino: ino}].tracer)
	assert.Contains(t, ta.pendingUnlinks, ebpf.ExecutableKey{Ino: ino})

	program.unlinkReady = true
	ta.processInstances.Inc(ebpf.ExecutableKey{Ino: ino})
	ta.retryPendingExecutableUnlinks()
	assert.Same(t, tracer, ta.existingTracers[ebpf.ExecutableKey{Ino: ino}].tracer)
	assert.Contains(t, ta.pendingUnlinks, ebpf.ExecutableKey{Ino: ino})
	assert.Equal(t, 1, program.unlinkChecks)

	assert.Zero(t, ta.processInstances.Dec(ebpf.ExecutableKey{Ino: ino}))
	ta.retryPendingExecutableUnlinks()
	assert.NotContains(t, ta.existingTracers, ebpf.ExecutableKey{Ino: ino})
	assert.NotContains(t, ta.pendingUnlinks, ebpf.ExecutableKey{Ino: ino})
	assert.Equal(t, 2, program.unlinkChecks)
	select {
	case event := <-eventCh:
		t.Fatalf("unexpected duplicate process event: %v", event.Type)
	default:
	}
}

func TestProcessDeletionIgnoresRejectedSameInodeProcess(t *testing.T) {
	const ino = uint64(1234)
	active := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test",
		Pid:        42,
		StartTime:  100,
		Ino:        ino,
		Ns:         17,
	})
	rejected := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test",
		Pid:        43,
		StartTime:  200,
		Ino:        ino,
		Ns:         18,
	})
	program := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{Type: ebpf.Generic, Programs: []ebpf.Tracer{program}}
	instances := helpermaps.MultiCounter[ebpf.ExecutableKey]{}
	instances.Inc(ebpf.ExecutableKey{Ino: ino})
	events := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(1))
	ta := &traceAttacher{
		log:     slog.Default(),
		Metrics: imetrics.NoopReporter{},
		existingTracers: map[ebpf.ExecutableKey]executableTracer{
			{Ino: ino}: {tracer: tracer},
		},
		processInstances:   instances,
		activePIDs:         map[app.PID]*execpkg.FileInfo{active.Pid(): active},
		OutputTracerEvents: events,
	}

	ta.notifyProcessDeletion(&ebpf.Instrumentable{FileInfo: rejected})

	require.NotNil(t, instances[ebpf.ExecutableKey{Ino: ino}])
	assert.Equal(t, 1, *instances[ebpf.ExecutableKey{Ino: ino}])
	assert.Same(t, tracer, ta.existingTracers[ebpf.ExecutableKey{Ino: ino}].tracer)
	assert.Contains(t, ta.activePIDs, active.Pid())
	assert.Empty(t, program.blocked)
}

func TestProcessDeletionRejectsStaleSamePIDIncarnations(t *testing.T) {
	const ino = uint64(1234)
	active := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/active",
		Pid:        42,
		StartTime:  100,
		Ino:        ino,
		Ns:         17,
	})
	tests := []struct {
		name    string
		deleted *execpkg.FileInfo
	}{
		{
			name: "start time changed",
			deleted: execpkg.New(execpkg.Init{
				CmdExePath: "/bin/active",
				Pid:        42,
				StartTime:  99,
				Ino:        ino,
				Ns:         17,
			}),
		},
		{
			name: "executable inode changed",
			deleted: execpkg.New(execpkg.Init{
				CmdExePath: "/bin/replaced",
				Pid:        42,
				StartTime:  100,
				Ino:        ino + 1,
				Ns:         17,
			}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			program := &recordingTracer{}
			tracer := &ebpf.ProcessTracer{
				Type:     ebpf.Generic,
				Programs: []ebpf.Tracer{program},
			}
			instances := helpermaps.MultiCounter[ebpf.ExecutableKey]{}
			instances.Inc(ebpf.ExecutableKey{Ino: ino})
			ta := &traceAttacher{
				log:     slog.Default(),
				Metrics: imetrics.NoopReporter{},
				existingTracers: map[ebpf.ExecutableKey]executableTracer{
					{Ino: ino}: {tracer: tracer},
				},
				processInstances: instances,
				activePIDs: map[app.PID]*execpkg.FileInfo{
					active.Pid(): active,
				},
			}

			ta.notifyProcessDeletion(&ebpf.Instrumentable{FileInfo: tc.deleted})

			require.NotNil(t, instances[ebpf.ExecutableKey{Ino: ino}])
			assert.Equal(t, 1, *instances[ebpf.ExecutableKey{Ino: ino}])
			assert.Same(t, tracer, ta.existingTracers[ebpf.ExecutableKey{Ino: ino}].tracer)
			assert.Same(t, active, ta.activePIDs[active.Pid()])
			assert.Empty(t, program.blocked)
		})
	}
}

func TestProcessDeletionRejectsAliasedSameTickIncarnation(t *testing.T) {
	const ino = uint64(1234)
	active := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/active",
		Pid:        42,
		StartTime:  100,
		Ino:        ino,
		Ns:         17,
	})
	deleted := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/stale-metadata",
		Pid:        42,
		StartTime:  100,
		Ino:        ino,
		Ns:         99,
	})
	program := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{
		Type:     ebpf.Generic,
		Programs: []ebpf.Tracer{program},
	}
	instances := helpermaps.MultiCounter[ebpf.ExecutableKey]{}
	instances.Inc(ebpf.ExecutableKey{Ino: ino})
	events := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(1))
	eventCh := events.Subscribe()
	ta := &traceAttacher{
		log:     slog.Default(),
		Metrics: imetrics.NoopReporter{},
		existingTracers: map[ebpf.ExecutableKey]executableTracer{
			{Ino: ino}: {tracer: tracer},
		},
		processInstances:   instances,
		activePIDs:         map[app.PID]*execpkg.FileInfo{active.Pid(): active},
		OutputTracerEvents: events,
	}

	ta.notifyProcessDeletion(&ebpf.Instrumentable{FileInfo: deleted})

	select {
	case event := <-eventCh:
		t.Fatalf("unexpected deletion event for aliased process: %v", event.Type)
	default:
	}
	assert.Empty(t, program.blocked)
	assert.Same(t, active, ta.activePIDs[active.Pid()])
}

func TestMonitorPIDsStopsSendingSignalsAfterCancellation(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	processStartTimeFunc = func(app.PID) uint64 {
		return 100
	}
	t.Cleanup(func() {
		processStartTimeFunc = originalProcessStartTimeFunc
	})

	signals := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
	signalCh := signals.Subscribe()
	signals.Send([]request.Span{{Type: request.EventTypeProcessAlive}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ta := &traceAttacher{
		log:                 slog.Default(),
		Metrics:             imetrics.NoopReporter{},
		runCtx:              ctx,
		activePIDs:          map[app.PID]*execpkg.FileInfo{},
		SpanSignalsShortcut: signals,
	}
	program := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{
		Type:     ebpf.Generic,
		Programs: []ebpf.Tracer{program},
	}
	instrumentable := &ebpf.Instrumentable{
		FileInfo: execpkg.New(execpkg.Init{
			Pid:       42,
			StartTime: 100,
			Ino:       1234,
		}),
	}
	done := make(chan bool, 1)
	go func() {
		done <- ta.monitorPIDs(tracer, instrumentable)
	}()

	assert.True(t, testutil.ReadChannel(t, done, testTimeout))
	_ = testutil.ReadChannel(t, signalCh, testTimeout)
}

func startDeletedTyperPipeline(
	ctx context.Context,
	tp *typer,
	input *msg.Queue[[]Event[ProcessMatch]],
	output *msg.Queue[[]Event[ebpf.Instrumentable]],
) {
	in := input.Subscribe(msg.SubscriberName("testExecTyper"))
	go func() {
		defer output.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case evs, ok := <-in:
				if !ok {
					return
				}
				if out := tp.FilterClassify(evs); len(out) > 0 {
					output.Send(out)
				}
			}
		}
	}()
}
