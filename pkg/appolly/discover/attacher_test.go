// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"io"
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
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type blockedPID struct {
	pid app.PID
	ns  uint32
}

type recordedPIDLifecycle struct {
	pid       app.PID
	ns        uint32
	lifecycle *execpkg.FileInfo
}

type recordingTracer struct {
	allowed           []blockedPID
	blocked           []blockedPID
	allowedFileInfos  []*execpkg.FileInfo
	blockedLifecycles []recordedPIDLifecycle
}

func (r *recordingTracer) AllowPID(pid app.PID, ns uint32, fileInfo *execpkg.FileInfo) {
	r.allowed = append(r.allowed, blockedPID{pid: pid, ns: ns})
	r.allowedFileInfos = append(r.allowedFileInfos, fileInfo)
}

func (r *recordingTracer) BlockPID(pid app.PID, ns uint32) {
	r.blocked = append(r.blocked, blockedPID{pid: pid, ns: ns})
}

func (r *recordingTracer) BlockPIDLifecycle(
	pid app.PID,
	ns uint32,
	lifecycle *execpkg.FileInfo,
) {
	r.BlockPID(pid, ns)
	r.blockedLifecycles = append(r.blockedLifecycles, recordedPIDLifecycle{
		pid: pid, ns: ns, lifecycle: lifecycle,
	})
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

func TestMonitorPIDsAllowsPythonWorkerOnce(t *testing.T) {
	parent := execpkg.New(execpkg.Init{Pid: 100})
	worker := execpkg.New(execpkg.Init{Pid: 101, Ppid: 100, Ns: 17})
	worker.SetRuntimeMetricServiceSource(parent)
	program := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}

	(&traceAttacher{}).monitorPIDs(tracer, &ebpf.Instrumentable{
		Type: svc.InstrumentablePython, FileInfo: worker,
	})

	assert.Equal(t, []blockedPID{{pid: 101, ns: 17}}, program.allowed)
	require.Len(t, program.allowedFileInfos, 1)
	assert.Same(t, worker, program.allowedFileInfos[0])
	assert.Equal(t, svc.InstrumentablePython, parent.SDKLanguage())
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
		Ino:        1234,
		Ns:         17,
	})
	serviceSource := execpkg.New(execpkg.Init{Pid: 41})
	fileInfo.SetRuntimeMetricServiceSource(serviceSource)
	startDeletedTyperPipeline(ctx, &typer{
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

	go run(ctx)

	processMatches.Send([]Event[ProcessMatch]{{
		Type: EventDeleted,
		Obj: ProcessMatch{
			Process: &services.ProcessInfo{Pid: 42},
		},
	}})

	ev := testutil.ReadChannel(t, tracerEvents, testTimeout)
	require.Equal(t, EventDeleted, ev.Type)
	require.NotNil(t, ev.Obj)
	assert.Equal(t, app.PID(42), ev.Obj.FileInfo.Pid())
	assert.Same(t, tracer, ev.Obj.Tracer)
	assert.Equal(t, uint64(1), ev.Obj.ExecutableGeneration)
	assert.Equal(t, []blockedPID{{pid: 42, ns: 17}}, prog.blocked)
	require.Len(t, prog.blockedLifecycles, 1)
	assert.Same(t, fileInfo, prog.blockedLifecycles[0].lifecycle)
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
		Ino:        1234,
		Ns:         17,
	})
	startDeletedTyperPipeline(ctx, &typer{
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

	go run(ctx)

	processMatches.Send([]Event[ProcessMatch]{{
		Type: EventDeleted,
		Obj: ProcessMatch{
			Process: &services.ProcessInfo{Pid: 42},
		},
	}})

	ev := testutil.ReadChannel(t, tracerEvents, testTimeout)
	require.Equal(t, EventInstanceDeleted, ev.Type)
	require.NotNil(t, ev.Obj)
	assert.Equal(t, app.PID(42), ev.Obj.FileInfo.Pid())
	assert.Nil(t, ev.Obj.Tracer)
	assert.Equal(t, []blockedPID{{pid: 42, ns: 17}}, prog.blocked)
	assert.Same(t, tracer, ta.existingTracers[key].tracer)
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

func TestSyncServiceMetadata_Precedence(t *testing.T) {
	t.Run("explicit src overrides auto dst", func(t *testing.T) {
		src := execpkg.New(execpkg.Init{
			Service: svc.Attrs{UID: svc.UID{Name: "explicit-svc"}},
		})
		dst := execpkg.New(execpkg.Init{})
		dst.SetAutoServiceName("auto-svc")

		syncServiceMetadata(dst, src)

		assert.Equal(t, "explicit-svc", dst.ServiceAttrs().UID.Name)
		assert.False(t, dst.AutoName())
	})

	t.Run("explicit dst overrides auto src", func(t *testing.T) {
		dst := execpkg.New(execpkg.Init{
			Service: svc.Attrs{UID: svc.UID{Name: "explicit-dst"}},
		})
		src := execpkg.New(execpkg.Init{})
		src.SetAutoServiceName("auto-src")

		syncServiceMetadata(dst, src)

		assert.Equal(t, "explicit-dst", src.ServiceAttrs().UID.Name)
		assert.False(t, src.AutoName())
	})

	t.Run("explicit src overrides empty dst", func(t *testing.T) {
		src := execpkg.New(execpkg.Init{
			Service: svc.Attrs{UID: svc.UID{Name: "explicit-src"}},
		})
		dst := execpkg.New(execpkg.Init{})

		syncServiceMetadata(dst, src)

		assert.Equal(t, "explicit-src", dst.ServiceAttrs().UID.Name)
		assert.False(t, dst.AutoName())
	})

	t.Run("auto src propagates to empty dst", func(t *testing.T) {
		src := execpkg.New(execpkg.Init{})
		src.SetAutoServiceName("auto-src")
		dst := execpkg.New(execpkg.Init{})

		syncServiceMetadata(dst, src)

		assert.Equal(t, "auto-src", dst.ServiceAttrs().UID.Name)
		assert.True(t, dst.AutoName())
	})

	t.Run("auto dst propagates to empty src", func(t *testing.T) {
		dst := execpkg.New(execpkg.Init{})
		dst.SetAutoServiceName("auto-dst")
		src := execpkg.New(execpkg.Init{})

		syncServiceMetadata(dst, src)

		assert.Equal(t, "auto-dst", src.ServiceAttrs().UID.Name)
		assert.True(t, src.AutoName())
	})

	t.Run("distinct auto names are preserved without overwrite", func(t *testing.T) {
		dst := execpkg.New(execpkg.Init{})
		dst.SetAutoServiceName("auto-dst")
		src := execpkg.New(execpkg.Init{})
		src.SetAutoServiceName("auto-src")

		syncServiceMetadata(dst, src)

		assert.Equal(t, "auto-dst", dst.ServiceAttrs().UID.Name)
		assert.Equal(t, "auto-src", src.ServiceAttrs().UID.Name)
	})

	t.Run("metadata map synchronization and isolation", func(t *testing.T) {
		src := execpkg.New(execpkg.Init{})
		src.SetMetadata(map[attr.Name]string{attr.Name("service.version"): "1.2.3"})
		dst := execpkg.New(execpkg.Init{})

		syncServiceMetadata(dst, src)

		assert.Equal(t, "1.2.3", dst.ServiceAttrs().Metadata[attr.Name("service.version")])

		// Mutating src should not mutate dst (deep copy)
		src.SetMetadata(map[attr.Name]string{attr.Name("service.version"): "9.9.9"})
		assert.Equal(t, "1.2.3", dst.ServiceAttrs().Metadata[attr.Name("service.version")])
	})

	t.Run("reverse metadata map synchronization", func(t *testing.T) {
		dst := execpkg.New(execpkg.Init{})
		dst.SetMetadata(map[attr.Name]string{attr.Name("service.version"): "2.0.0"})
		src := execpkg.New(execpkg.Init{})

		syncServiceMetadata(dst, src)

		assert.Equal(t, "2.0.0", src.ServiceAttrs().Metadata[attr.Name("service.version")])
	})

	t.Run("nil and self no-op safety", func(t *testing.T) {
		fi := execpkg.New(execpkg.Init{})
		fi.SetAutoServiceName("test")
		syncServiceMetadata(nil, fi)
		syncServiceMetadata(fi, nil)
		syncServiceMetadata(fi, fi)
		assert.Equal(t, "test", fi.ServiceAttrs().UID.Name)
	})
}

func TestMonitorPIDs_PropagatesNameToServiceSource(t *testing.T) {
	parent := execpkg.New(execpkg.Init{Pid: 100, CmdExePath: "/usr/bin/python3.14"})
	worker := execpkg.New(execpkg.Init{Pid: 101, Ppid: 100, Ns: 17, CmdExePath: "/usr/bin/python3.14"})
	worker.SetRuntimeMetricServiceSource(parent)
	worker.SetAutoServiceName("main_ssl")

	program := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}

	(&traceAttacher{}).monitorPIDs(tracer, &ebpf.Instrumentable{
		Type: svc.InstrumentablePython, FileInfo: worker,
	})

	// Parent should receive main_ssl from worker before applying defaults,
	// rather than falling back to python3.14.
	assert.Equal(t, "main_ssl", parent.ServiceAttrs().UID.Name)
	assert.Equal(t, "main_ssl", worker.ServiceAttrs().UID.Name)
	assert.Equal(t, svc.InstrumentablePython, parent.SDKLanguage())
}
