// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package discover

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	execpkg "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/helpers/maps"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type failingLoadTracer struct {
	recordingTracer
}

func (f *failingLoadTracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	return nil, errors.New("BPF load failure")
}

type failingExecutableTracer struct {
	recordingTracer
}

type initializedLifecycleTracer struct {
	recordingTracer
	started  chan struct{}
	finished chan struct{}
	resource io.Closer
}

func (t *initializedLifecycleTracer) Run(
	ctx context.Context,
	_ *ebpfcommon.EBPFEventContext,
	_ *msg.Queue[[]request.Span],
) {
	close(t.started)
	<-ctx.Done()
	_ = t.resource.Close()
	close(t.finished)
}

type lifecycleCountingCloser struct {
	closes atomic.Int32
}

func (c *lifecycleCountingCloser) Close() error {
	c.closes.Add(1)
	return nil
}

func (f *failingExecutableTracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return map[string][]*ebpfcommon.ProbeDesc{
		"missing-required-symbol": {{Required: true}},
	}
}

// After an optional common tracer fails during ProcessTracer.Init, it must be
// pruned from ta.commonTracers so that only successfully loaded common tracers
// receive AllowPID and BlockPID notifications.
func TestCommonTracersPrunedAfterLoadFailure(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	processStartTimeFunc = func(pid app.PID) uint64 {
		require.Equal(t, app.PID(42), pid)
		return 100
	}

	okTracer := &recordingTracer{}
	failedTracer := &failingLoadTracer{}

	cfg := &obi.Config{}
	cfg.EBPF.BPFFSPath = t.TempDir()
	tracer := ebpf.NewProcessTracer(ebpf.Generic, []ebpf.Tracer{okTracer, failedTracer}, cfg, imetrics.NoopReporter{})
	require.NoError(t, tracer.Init(&ebpfcommon.EBPFEventContext{}, cfg))
	require.Equal(t, []ebpf.Tracer{okTracer}, tracer.Programs)

	tracerEvents := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	ta := &traceAttacher{
		log:                slog.With("component", t.Name()),
		Metrics:            imetrics.NoopReporter{},
		commonTracers:      []ebpf.Tracer{okTracer, failedTracer},
		existingTracers:    map[ebpf.ExecutableKey]executableTracer{},
		processInstances:   maps.MultiCounter[ebpf.ExecutableKey]{},
		OutputTracerEvents: tracerEvents,
	}

	ta.dropUnloadedTracers(tracer.Programs)
	assert.Equal(t, []ebpf.Tracer{okTracer}, ta.commonTracers)

	fileInfo := execpkg.New(execpkg.Init{
		Service:    svc.Attrs{UID: svc.UID{Name: "svc", Namespace: "ns"}},
		CmdExePath: "/bin/test",
		Pid:        42,
		StartTime:  100,
		Ino:        1234,
		Ns:         17,
	})
	ie := &ebpf.Instrumentable{FileInfo: fileInfo}

	ta.monitorPIDs(tracer, ie)
	assert.NotEmpty(t, okTracer.allowed)
	assert.Empty(t, failedTracer.allowed)

	key := executableKey(fileInfo)
	ta.existingTracers[key] = executableTracer{tracer: tracer, generation: 1}
	ta.processInstances.Inc(key)

	ta.notifyProcessDeletion(ie)
	assert.NotEmpty(t, okTracer.blocked)
	assert.Empty(t, failedTracer.blocked)
}

func TestInitializedTracerIsHandedOffWhenOwnerDisappearsAfterInit(t *testing.T) {
	processRoot, err := os.Open("/proc/self")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, processRoot.Close()) })

	resource := &lifecycleCountingCloser{}
	program := &initializedLifecycleTracer{
		started:  make(chan struct{}),
		finished: make(chan struct{}),
		resource: resource,
	}
	cfg := &obi.Config{ShutdownTimeout: time.Second}
	cfg.EBPF.BPFFSPath = t.TempDir()
	eventContext := ebpfcommon.NewEBPFEventContext()
	events := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(1))
	eventCh := events.Subscribe()
	fileInfo := execpkg.New(execpkg.Init{
		CmdExePath:     "/proc/self/exe",
		ProExeLinkPath: "/proc/self/exe",
		Pid:            app.PID(os.Getpid()),
		StartTime:      100,
		Ino:            1234,
	})
	identityChecks := 0
	ta := &traceAttacher{
		log:                 slog.Default(),
		Cfg:                 cfg,
		Metrics:             imetrics.NoopReporter{},
		existingTracers:     map[ebpf.ExecutableKey]executableTracer{},
		activePIDs:          map[app.PID]*execpkg.FileInfo{},
		commonTracersLoaded: true,
		currentProcessRoots: map[*execpkg.FileInfo]*os.File{fileInfo: processRoot},
		initialIdentityCheck: func(got *execpkg.FileInfo, root *os.File) bool {
			require.Same(t, fileInfo, got)
			require.Same(t, processRoot, root)
			identityChecks++
			return identityChecks < 4
		},
		processTracerFactory: func(
			tracerType ebpf.ProcessTracerType,
			_ []ebpf.Tracer,
			factoryCfg *obi.Config,
			metrics imetrics.Reporter,
		) *ebpf.ProcessTracer {
			return ebpf.NewProcessTracer(
				tracerType,
				[]ebpf.Tracer{program},
				factoryCfg,
				metrics,
			)
		},
		OutputTracerEvents: events,
		EbpfEventContext:   eventContext,
		routeHarvester: harvest.NewRouteHarvester(
			&cfg.Discovery.RouteHarvestConfig,
			cfg.Discovery.DisabledRouteHarvesters,
			time.Second,
		),
	}
	ie := &ebpf.Instrumentable{
		Type:     svc.InstrumentableGeneric,
		FileInfo: fileInfo,
	}

	assert.False(t, ta.getTracer(ie))
	initialized := testutil.ReadChannel(t, eventCh, time.Second)
	require.Equal(t, EventTracerInitialized, initialized.Type)
	require.Same(t, ie, initialized.Obj)
	require.NotNil(t, initialized.Obj.Tracer)
	assert.Same(t, initialized.Obj.Tracer, ta.reusableTracer)
	select {
	case extra := <-eventCh:
		t.Fatalf("initialized tracer was handed off more than once: %v", extra.Type)
	default:
	}

	runCtx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() {
		initialized.Obj.Tracer.Run(runCtx, eventContext, nil)
		close(runDone)
	}()
	testutil.ReadChannel(t, program.started, time.Second)
	cancel()
	testutil.ReadChannel(t, program.finished, time.Second)
	testutil.ReadChannel(t, runDone, time.Second)
	assert.Equal(t, int32(1), resource.closes.Load())
}

func TestReuseTracerReturnsOnExecutableAttachmentFailure(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	processStartTimeFunc = func(app.PID) uint64 { return 100 }

	pid := app.PID(os.Getpid())
	fileInfo := execpkg.New(execpkg.Init{
		CmdExePath:     "/proc/self/exe",
		ProExeLinkPath: "/proc/self/exe",
		Pid:            pid,
		StartTime:      100,
		Ino:            1234,
	})
	ie := &ebpf.Instrumentable{
		FileInfo: fileInfo,
		Offsets:  &goexec.Offsets{Funcs: map[string]goexec.FuncOffsets{}},
	}
	tracer := ebpf.NewProcessTracer(
		ebpf.Generic,
		[]ebpf.Tracer{&failingExecutableTracer{}},
		&obi.Config{},
		imetrics.NoopReporter{},
	)
	ta := &traceAttacher{
		log:             slog.Default(),
		Metrics:         imetrics.NoopReporter{},
		existingTracers: map[ebpf.ExecutableKey]executableTracer{},
	}

	assert.False(t, ta.reuseTracer(tracer, ie))
	assert.NotContains(t, tracer.Instrumentables, executableKey(fileInfo))
	assert.NotContains(t, ta.existingTracers, executableKey(fileInfo))
	assert.Nil(t, ie.Tracer)
}

func TestPendingIdentityUsesOwnedProcessRoot(t *testing.T) {
	pid := app.PID(os.Getpid())
	root, err := os.Open(fmt.Sprintf("/proc/%d", pid))
	require.NoError(t, err)
	dev, ino, err := FindINodeForPID(pid)
	require.NoError(t, err)
	fileInfo := execpkg.New(execpkg.Init{
		Pid:       pid,
		StartTime: processStartTimeFunc(pid),
		Dev:       dev,
		Ino:       ino,
	})

	assert.True(t, livePendingProcessIdentityMatches(fileInfo, root))
	require.NoError(t, root.Close())
	assert.False(t, livePendingProcessIdentityMatches(fileInfo, root))
}

func TestPendingIdentityReadsStartTimeAndExecutableFromOwnedRoot(t *testing.T) {
	pid := app.PID(os.Getpid())
	root, err := os.Open(fmt.Sprintf("/proc/%d", pid))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })
	startTime, dev, ino, err := processRootIdentity(root)
	require.NoError(t, err)

	matching := execpkg.New(execpkg.Init{
		Pid: pid, StartTime: startTime, Dev: dev, Ino: ino,
	})
	wrongStartTime := execpkg.New(execpkg.Init{
		Pid: pid, StartTime: startTime + 1, Dev: dev, Ino: ino,
	})
	wrongExecutable := execpkg.New(execpkg.Init{
		Pid: pid, StartTime: startTime, Dev: dev, Ino: ino + 1,
	})

	assert.True(t, livePendingProcessIdentityMatches(matching, root))
	assert.False(t, livePendingProcessIdentityMatches(wrongStartTime, root))
	assert.False(t, livePendingProcessIdentityMatches(wrongExecutable, root))
}

func TestFilesystemRootPathUsesOwnedProcessRoot(t *testing.T) {
	root, err := os.Open("/proc/self")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, root.Close()) })

	path, err := filesystemRootPathThroughProcessRoot(root)
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("/proc/self/fd/%d/root", root.Fd()), path)
	_, err = os.Stat(path)
	require.NoError(t, err)
}

func TestIdentityStableProcessHandleSignalsBoundProcess(t *testing.T) {
	handle, err := openIdentityStableProcessHandle(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, handle.Signal(0))
	require.NoError(t, handle.Close())
	assert.Error(t, handle.Signal(0))
}

func TestReuseTracerRollsBackRejectedIncarnation(t *testing.T) {
	originalProcessStartTimeFunc := processStartTimeFunc
	t.Cleanup(func() { processStartTimeFunc = originalProcessStartTimeFunc })
	startTimeReads := 0
	processStartTimeFunc = func(app.PID) uint64 {
		startTimeReads++
		if startTimeReads <= 2 {
			return 100
		}
		return 200
	}

	pid := app.PID(os.Getpid())
	fileInfo := execpkg.New(execpkg.Init{
		CmdExePath:     "/proc/self/exe",
		ProExeLinkPath: "/proc/self/exe",
		Pid:            pid,
		StartTime:      100,
		Ino:            1234,
	})
	ie := &ebpf.Instrumentable{FileInfo: fileInfo}
	tracer := ebpf.NewProcessTracer(ebpf.Generic, nil, &obi.Config{}, imetrics.NoopReporter{})
	ta := &traceAttacher{
		log:             slog.Default(),
		Metrics:         imetrics.NoopReporter{},
		existingTracers: map[ebpf.ExecutableKey]executableTracer{},
	}

	assert.False(t, ta.reuseTracer(tracer, ie))
	assert.NotContains(t, tracer.Instrumentables, fileInfo.Ino())
	assert.NotContains(t, ta.existingTracers, executableKey(fileInfo))
	assert.Nil(t, ie.Tracer)
}
