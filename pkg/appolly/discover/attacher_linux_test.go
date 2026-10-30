// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package discover

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	osexec "os/exec"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	execpkg "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/helpers/maps"
	"go.opentelemetry.io/obi/pkg/internal/procs"
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

// After an optional common tracer fails during ProcessTracer.Init, it must be
// pruned from ta.commonTracers so that only successfully loaded common tracers
// receive AllowPID and BlockPID notifications.
func TestCommonTracersPrunedAfterLoadFailure(t *testing.T) {
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
		processInstances:   maps.Map2[ebpf.ExecutableKey, app.PID, struct{}]{},
		OutputTracerEvents: tracerEvents,
	}

	ta.dropUnloadedTracers(tracer.Programs)
	assert.Equal(t, []ebpf.Tracer{okTracer}, ta.commonTracers)

	fileInfo := execpkg.New(execpkg.Init{
		Service:    svc.Attrs{UID: svc.UID{Name: "svc", Namespace: "ns"}},
		CmdExePath: "/bin/test",
		Pid:        42,
		Ino:        1234,
		Ns:         17,
	})
	ie := &ebpf.Instrumentable{FileInfo: fileInfo}

	ta.monitorPIDs(t.Context(), tracer, ie)
	assert.NotEmpty(t, okTracer.allowed)
	assert.Empty(t, failedTracer.allowed)

	key := executableKey(fileInfo)
	ta.existingTracers[key] = executableTracer{tracer: tracer, generation: 1}
	ta.processInstances.Put(key, fileInfo.Pid(), struct{}{})

	ta.notifyProcessDeletion(t.Context(), ie)
	assert.NotEmpty(t, okTracer.blocked)
	assert.Empty(t, failedTracer.blocked)
}

// A process that exits before its attach completes must not pin the next binary reusing its inode number
func TestFailedAttachDoesNotHoldExecutableInstance(t *testing.T) {
	created := func(fi *execpkg.FileInfo) Event[ebpf.Instrumentable] {
		return Event[ebpf.Instrumentable]{Type: EventCreated, Obj: ebpf.Instrumentable{Type: svc.InstrumentableGeneric, FileInfo: fi}}
	}
	deleted := func(fi *execpkg.FileInfo) Event[ebpf.Instrumentable] {
		return Event[ebpf.Instrumentable]{Type: EventDeleted, Obj: ebpf.Instrumentable{FileInfo: fi}}
	}

	failures := []struct {
		name   string
		exited func(t *testing.T) *execpkg.FileInfo
	}{{
		name:   "executable gone",
		exited: func(t *testing.T) *execpkg.FileInfo { return sameInodeFileInfo(exitedProcessPID(t)) },
	}, {
		name: "process gone after its executable was opened",
		exited: func(t *testing.T) *execpkg.FileInfo {
			return sameInodeFileInfoWithExe(exitedProcessPID(t), "/proc/self/exe")
		},
	}}

	tests := []struct {
		name   string
		events func(exited, running *execpkg.FileInfo) []Event[ebpf.Instrumentable]
	}{{
		name: "exit of the failed process is reported before the inode is reused",
		events: func(exited, running *execpkg.FileInfo) []Event[ebpf.Instrumentable] {
			return []Event[ebpf.Instrumentable]{created(exited), deleted(exited), created(running), deleted(running)}
		},
	}, {
		name: "exit of the failed process is reported after another instance attached",
		events: func(exited, running *execpkg.FileInfo) []Event[ebpf.Instrumentable] {
			return []Event[ebpf.Instrumentable]{created(exited), created(running), deleted(exited), deleted(running)}
		},
	}, {
		name: "failed process is a new instance of an attached executable",
		events: func(exited, running *execpkg.FileInfo) []Event[ebpf.Instrumentable] {
			return []Event[ebpf.Instrumentable]{created(running), created(exited), deleted(exited), deleted(running)}
		},
	}}

	for _, failure := range failures {
		t.Run(failure.name, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					instrumentables, tracerEvents := startReusingGenericAttacher(t, nil)

					exited := failure.exited(t)
					running := sameInodeFileInfo(app.PID(os.Getpid()))
					instrumentables.Send(tc.events(exited, running))

					ev := testutil.ReadChannel(t, tracerEvents, testTimeout)
					require.Equal(t, EventCreated, ev.Type)
					assert.Same(t, running, ev.Obj.FileInfo)

					ev = testutil.ReadChannel(t, tracerEvents, testTimeout)
					require.Equal(t, EventDeleted, ev.Type)
					assert.Same(t, running, ev.Obj.FileInfo)
					assert.NotNil(t, ev.Obj.Tracer)
				})
			}
		})
	}
}

// The typer folds a child into its parent's Instrumentable, but reports the child's exit with its own FileInfo
func TestFoldedChildHoldsExecutableInstance(t *testing.T) {
	tests := []struct {
		name             string
		parentExitsFirst bool
	}{
		{name: "child exits first"},
		{name: "parent exits first", parentExitsFirst: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			instrumentables, tracerEvents := startReusingGenericAttacher(t, nil)

			parent := sameInodeFileInfo(app.PID(os.Getpid()))
			child := sameInodeFileInfo(exitedProcessPID(t))
			first, last := child, parent
			if tc.parentExitsFirst {
				first, last = parent, child
			}
			instrumentables.Send([]Event[ebpf.Instrumentable]{
				{Type: EventCreated, Obj: ebpf.Instrumentable{Type: svc.InstrumentableGeneric, FileInfo: parent, ChildPids: []app.PID{child.Pid()}}},
				{Type: EventCreated, Obj: ebpf.Instrumentable{Type: svc.InstrumentableGeneric, FileInfo: parent}},
				{Type: EventDeleted, Obj: ebpf.Instrumentable{FileInfo: first}},
				{Type: EventDeleted, Obj: ebpf.Instrumentable{FileInfo: last}},
			})

			for range 2 {
				ev := testutil.ReadChannel(t, tracerEvents, testTimeout)
				require.Equal(t, EventCreated, ev.Type)
			}

			ev := testutil.ReadChannel(t, tracerEvents, testTimeout)
			require.Equal(t, EventInstanceDeleted, ev.Type)
			assert.Same(t, first, ev.Obj.FileInfo)

			ev = testutil.ReadChannel(t, tracerEvents, testTimeout)
			require.Equal(t, EventDeleted, ev.Type)
			assert.Same(t, last, ev.Obj.FileInfo)
			assert.NotNil(t, ev.Obj.Tracer)
		})
	}
}

type blockingRouteHarvester struct {
	started chan struct{}
	release chan struct{}
}

func (h *blockingRouteHarvester) HarvestRoutes(*execpkg.FileInfo) (*harvest.RouteHarvesterResult, error) {
	if h.started != nil {
		h.started <- struct{}{}
	}
	<-h.release
	return &harvest.RouteHarvesterResult{Routes: []string{"/users/{id}"}, Kind: harvest.CompleteRoutes}, nil
}

func (h *blockingRouteHarvester) HarvestRoutesDelay(*execpkg.FileInfo) (bool, time.Duration) {
	return false, 0
}

// A harvest can run until its timeout; the processes waiting behind it would have their spans dropped meanwhile
func TestSlowRouteHarvestDoesNotBlockAttacher(t *testing.T) {
	harvester := &blockingRouteHarvester{started: make(chan struct{}, 2), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(harvester.release) })
	t.Cleanup(release)
	instrumentables, tracerEvents := startReusingGenericAttacher(t, harvester)

	self := app.PID(os.Getpid())
	first := runningFileInfo(t, self)
	second := runningFileInfo(t, self)
	instrumentables.Send([]Event[ebpf.Instrumentable]{
		{Type: EventCreated, Obj: ebpf.Instrumentable{Type: svc.InstrumentableGeneric, FileInfo: first}},
		{Type: EventCreated, Obj: ebpf.Instrumentable{Type: svc.InstrumentableGeneric, FileInfo: second}},
	})

	for _, fi := range []*execpkg.FileInfo{first, second} {
		ev := testutil.ReadChannel(t, tracerEvents, testTimeout)
		require.Equal(t, EventCreated, ev.Type)
		assert.Same(t, fi, ev.Obj.FileInfo)
	}

	testutil.ReadChannel(t, harvester.started, testTimeout)
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, harvester.started, "harvests must run one at a time")

	release()
	assert.Eventually(t, func() bool {
		return first.ServiceAttrs().HarvestedRouteMatcher != nil && second.ServiceAttrs().HarvestedRouteMatcher != nil
	}, testTimeout, 10*time.Millisecond)
}

func TestRouteHarvestSkipsGoneProcesses(t *testing.T) {
	self := app.PID(os.Getpid())
	tests := []struct {
		name      string
		fileInfo  *execpkg.FileInfo
		cancelled bool
		harvested bool
	}{
		{name: "running", fileInfo: runningFileInfo(t, self), harvested: true},
		{name: "executable renamed", fileInfo: runningFileInfo(t, self, func(i *execpkg.Init) { i.CmdExePath = "/renamed" }), harvested: true},
		{name: "PID reused by the same executable", fileInfo: runningFileInfo(t, self, func(i *execpkg.Init) { i.StartTime-- })},
		{name: "executable inode changed", fileInfo: runningFileInfo(t, self, func(i *execpkg.Init) { i.Ino++ })},
		{name: "executable device changed", fileInfo: runningFileInfo(t, self, func(i *execpkg.Init) { i.Dev++ })},
		{name: "shutting down", fileInfo: runningFileInfo(t, self), cancelled: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			harvester := &blockingRouteHarvester{release: make(chan struct{})}
			close(harvester.release)
			ta := &traceAttacher{
				log:            slog.With("component", t.Name()),
				routeHarvester: harvester,
				harvestSlot:    semaphore.NewWeighted(1),
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancelled {
				cancel()
			}

			ta.harvestRoutesProcessor(ctx, &ebpf.Instrumentable{FileInfo: tc.fileInfo}, false)
			assert.Equal(t, tc.harvested, tc.fileInfo.ServiceAttrs().HarvestedRouteMatcher != nil)
		})
	}
}

// The process is checked when its harvest gets the slot, not when the harvest is queued
func TestQueuedRouteHarvestSkipsExitedProcess(t *testing.T) {
	cmd := osexec.Command("sleep", "60")
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	fileInfo := runningFileInfo(t, app.PID(cmd.Process.Pid))

	harvester := &blockingRouteHarvester{release: make(chan struct{})}
	close(harvester.release)
	ta := &traceAttacher{
		log:            slog.With("component", t.Name()),
		routeHarvester: harvester,
		harvestSlot:    semaphore.NewWeighted(1),
	}
	require.NoError(t, ta.harvestSlot.Acquire(t.Context(), 1))
	done := make(chan struct{})
	go func() {
		defer close(done)
		ta.harvestRoutesProcessor(t.Context(), &ebpf.Instrumentable{FileInfo: fileInfo}, false)
	}()

	time.Sleep(100 * time.Millisecond)
	require.NoError(t, cmd.Process.Kill())
	_ = cmd.Wait()
	ta.harvestSlot.Release(1)

	testutil.ReadChannel(t, done, testTimeout)
	assert.Nil(t, fileInfo.ServiceAttrs().HarvestedRouteMatcher)
}

// A harvest can hold the slot until its extractor ends; the ones queued behind it must still stop on shutdown
func TestQueuedRouteHarvestStopsOnShutdown(t *testing.T) {
	harvester := &blockingRouteHarvester{started: make(chan struct{}, 1), release: make(chan struct{})}
	t.Cleanup(func() { close(harvester.release) })
	ta := &traceAttacher{
		log:            slog.With("component", t.Name()),
		routeHarvester: harvester,
		harvestSlot:    semaphore.NewWeighted(1),
	}
	ctx, cancel := context.WithCancel(t.Context())
	self := app.PID(os.Getpid())
	running, queued := runningFileInfo(t, self), runningFileInfo(t, self)
	go ta.harvestRoutesProcessor(ctx, &ebpf.Instrumentable{FileInfo: running}, false)
	testutil.ReadChannel(t, harvester.started, testTimeout)

	done := make(chan struct{})
	go func() {
		defer close(done)
		ta.harvestRoutesProcessor(ctx, &ebpf.Instrumentable{FileInfo: queued}, false)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()

	testutil.ReadChannel(t, done, testTimeout)
	assert.Empty(t, harvester.started)
	assert.Nil(t, queued.ServiceAttrs().HarvestedRouteMatcher)
}

func startReusingGenericAttacher(t *testing.T, harvester routesHarvester) (*msg.Queue[[]Event[ebpf.Instrumentable]], <-chan Event[*ebpf.Instrumentable]) {
	origRemoveMemlock := removeMemlock
	removeMemlock = func() error { return nil }
	t.Cleanup(func() { removeMemlock = origRemoveMemlock })

	instrumentables := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	tracerEventsQu := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	tracerEvents := tracerEventsQu.Subscribe()

	cfg := &obi.Config{}
	ta := &traceAttacher{
		Cfg:                  cfg,
		Metrics:              imetrics.NoopReporter{},
		InputInstrumentables: instrumentables,
		OutputTracerEvents:   tracerEventsQu,
		EbpfEventContext:     &ebpfcommon.EBPFEventContext{},
	}
	run, err := ta.attacherLoop(t.Context())
	require.NoError(t, err)
	if harvester != nil {
		ta.routeHarvester = harvester
	}
	ta.reusableTracer = ebpf.NewProcessTracer(ebpf.Generic, []ebpf.Tracer{&recordingTracer{}}, cfg, imetrics.NoopReporter{})

	go run(t.Context())
	return instrumentables, tracerEvents
}

func exitedProcessPID(t *testing.T) app.PID {
	cmd := osexec.Command("true")
	require.NoError(t, cmd.Run())
	return app.PID(cmd.Process.Pid)
}

func runningFileInfo(t *testing.T, pid app.PID, edits ...func(*execpkg.Init)) *execpkg.FileInfo {
	exeLink := fmt.Sprintf("/proc/%d/exe", pid)
	exe, err := os.Readlink(exeLink)
	require.NoError(t, err)
	startTime, err := procs.StartTime(pid)
	require.NoError(t, err)
	dev, ino, err := FindINodeForPID(pid)
	require.NoError(t, err)
	in := execpkg.Init{
		Service:        svc.Attrs{UID: svc.UID{Name: "svc", Namespace: "ns"}},
		CmdExePath:     exe,
		ProExeLinkPath: exeLink,
		Pid:            pid,
		StartTime:      startTime,
		Dev:            dev,
		Ino:            ino,
	}
	for _, edit := range edits {
		edit(&in)
	}
	return execpkg.New(in)
}

func sameInodeFileInfo(pid app.PID) *execpkg.FileInfo {
	return sameInodeFileInfoWithExe(pid, fmt.Sprintf("/proc/%d/exe", pid))
}

func sameInodeFileInfoWithExe(pid app.PID, exeLink string) *execpkg.FileInfo {
	return execpkg.New(execpkg.Init{
		Service:        svc.Attrs{UID: svc.UID{Name: "svc", Namespace: "ns"}},
		CmdExePath:     "/bin/test",
		ProExeLinkPath: exeLink,
		Pid:            pid,
		Ino:            1234,
	})
}
