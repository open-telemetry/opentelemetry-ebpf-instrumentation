// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package discover

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	osexec "os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	execpkg "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/helpers/maps"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
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
					instrumentables, tracerEvents := startReusingGenericAttacher(t)

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
			instrumentables, tracerEvents := startReusingGenericAttacher(t)

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

func startReusingGenericAttacher(t *testing.T) (*msg.Queue[[]Event[ebpf.Instrumentable]], <-chan Event[*ebpf.Instrumentable]) {
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
	ta.reusableTracer = ebpf.NewProcessTracer(ebpf.Generic, []ebpf.Tracer{&recordingTracer{}}, cfg, imetrics.NoopReporter{})

	go run(t.Context())
	return instrumentables, tracerEvents
}

func exitedProcessPID(t *testing.T) app.PID {
	cmd := osexec.Command("true")
	require.NoError(t, cmd.Run())
	return app.PID(cmd.Process.Pid)
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
