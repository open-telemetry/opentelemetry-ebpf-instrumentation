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

type recordedSamplerUpdate struct {
	pid      app.PID
	ns       uint32
	fileInfo *execpkg.FileInfo
	sampler  *services.SamplerConfig
}

type recordingTracer struct {
	allowed           []blockedPID
	blocked           []blockedPID
	allowedFileInfos  []*execpkg.FileInfo
	blockedLifecycles []recordedPIDLifecycle
	samplerUpdates    []recordedSamplerUpdate
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

func (r *recordingTracer) UpdatePIDSampler(pid app.PID, ns uint32, fileInfo *execpkg.FileInfo) {
	r.samplerUpdates = append(r.samplerUpdates, recordedSamplerUpdate{
		pid: pid, ns: ns, fileInfo: fileInfo, sampler: fileInfo.ServiceAttrs().SamplerConfig,
	})
}

func (r *recordingTracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error)           { return nil, nil }
func (r *recordingTracer) AddCloser(...io.Closer)                                 {}
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
func (r *recordingTracer) Close() error                                           { return nil }
func (r *recordingTracer) Run(context.Context, *ebpfcommon.EBPFEventContext, *msg.Queue[[]request.Span]) {
}

func TestMonitorPIDsAllowsPythonWorkerOnce(t *testing.T) {
	parent := execpkg.New(execpkg.Init{Pid: 100})
	worker := execpkg.New(execpkg.Init{Pid: 101, Ppid: 100, Ns: 17})
	worker.SetRuntimeMetricServiceSource(parent)
	program := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}

	(&traceAttacher{}).monitorPIDs(t.Context(), tracer, &ebpf.Instrumentable{
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
	ta.processInstances.Put(key, 42, fileInfo)

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
	ta.processInstances.Put(key, 42, fileInfo)
	ta.processInstances.Put(key, 43, fileInfo)

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

func TestTraceAttacherUpdatesSamplers(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	origRemoveMemlock := removeMemlock
	removeMemlock = func() error { return nil }
	defer func() { removeMemlock = origRemoveMemlock }()

	processMatches := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	instrumentables := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	tracerEventsQu := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	tracerEvents := tracerEventsQu.Subscribe()

	// A Python master and its worker share the generic tracer, which samples both
	// with the master's sampler. A Go process has a tracer of its own.
	master := execpkg.New(execpkg.Init{Pid: 100, Ino: 1, Ns: 17})
	worker := execpkg.New(execpkg.Init{Pid: 101, Ppid: 100, Ino: 1, Ns: 17})
	master.SetRuntimeMetricServiceSource(master)
	worker.SetRuntimeMetricServiceSource(master)
	// Each of these masters leaves in the same batch that updates its worker.
	masterA := execpkg.New(execpkg.Init{Pid: 200, Ino: 2, Ns: 17})
	workerA := execpkg.New(execpkg.Init{Pid: 201, Ppid: 200, Ino: 2, Ns: 17})
	masterA.SetRuntimeMetricServiceSource(masterA)
	workerA.SetRuntimeMetricServiceSource(masterA)
	masterB := execpkg.New(execpkg.Init{Pid: 400, Ino: 4, Ns: 17})
	workerB := execpkg.New(execpkg.Init{Pid: 401, Ppid: 400, Ino: 4, Ns: 17})
	masterB.SetRuntimeMetricServiceSource(masterB)
	workerB.SetRuntimeMetricServiceSource(masterB)
	golang := execpkg.New(execpkg.Init{Pid: 300, Ino: 3, Ns: 17})
	// Deleting one of these after each step waits until the attacher has handled the step.
	barriers := []*execpkg.FileInfo{
		execpkg.New(execpkg.Init{Pid: 900, Ino: 9}),
		execpkg.New(execpkg.Init{Pid: 901, Ino: 9}),
		execpkg.New(execpkg.Init{Pid: 902, Ino: 9}),
		execpkg.New(execpkg.Init{Pid: 903, Ino: 9}),
		execpkg.New(execpkg.Init{Pid: 904, Ino: 9}),
		execpkg.New(execpkg.Init{Pid: 905, Ino: 9}),
	}
	currentPids := map[app.PID]*execpkg.FileInfo{
		100: master, 101: worker, 200: masterA, 201: workerA, 400: masterB, 401: workerB, 300: golang,
	}
	for _, barrier := range barriers {
		currentPids[barrier.Pid()] = barrier
	}
	startDeletedTyperPipeline(ctx, &typer{currentPids: currentPids}, processMatches, instrumentables)

	ta := &traceAttacher{
		Cfg:                  &obi.Config{},
		Metrics:              imetrics.NoopReporter{},
		InputInstrumentables: instrumentables,
		OutputTracerEvents:   tracerEventsQu,
		EbpfEventContext:     &ebpfcommon.EBPFEventContext{},
	}
	run, err := ta.attacherLoop(ctx)
	require.NoError(t, err)

	generic := &recordingTracer{}
	goProgram := &recordingTracer{}
	ta.reusableTracer = &ebpf.ProcessTracer{Type: ebpf.Generic, Programs: []ebpf.Tracer{generic}}
	ta.reusableGoTracer = &ebpf.ProcessTracer{Type: ebpf.Go, Programs: []ebpf.Tracer{goProgram}}
	for _, fi := range append([]*execpkg.FileInfo{master, worker, masterA, workerA, masterB, workerB}, barriers...) {
		ta.processInstances.Put(executableKey(fi), fi.Pid(), fi)
		ta.existingTracers[executableKey(fi)] = executableTracer{tracer: ta.reusableTracer}
	}
	ta.processInstances.Put(executableKey(golang), golang.Pid(), golang)
	ta.existingTracers[executableKey(golang)] = executableTracer{tracer: ta.reusableGoTracer}

	go run(ctx)

	updated := func(pid app.PID, sampler services.SamplerName) Event[ProcessMatch] {
		return Event[ProcessMatch]{Type: EventUpdated, Obj: ProcessMatch{
			Process:       &services.ProcessInfo{Pid: pid},
			SamplerConfig: &services.SamplerConfig{Name: sampler},
		}}
	}
	deleted := func(pid app.PID) Event[ProcessMatch] {
		return Event[ProcessMatch]{Type: EventDeleted, Obj: ProcessMatch{Process: &services.ProcessInfo{Pid: pid}}}
	}
	apply := func(events ...Event[ProcessMatch]) {
		t.Helper()
		barrier := barriers[0]
		barriers = barriers[1:]
		processMatches.Send(events)
		// Updates are applied after the rest of their batch, so the barrier goes in a batch of its own.
		processMatches.Send([]Event[ProcessMatch]{deleted(barrier.Pid())})
		event := testutil.ReadChannel(t, tracerEvents, testTimeout)
		for event.Obj.FileInfo != barrier {
			event = testutil.ReadChannel(t, tracerEvents, testTimeout)
		}
	}
	samplerOf := func(fi *execpkg.FileInfo) services.SamplerName {
		if cfg := fi.ServiceAttrs().SamplerConfig; cfg != nil {
			return cfg.Name
		}
		return ""
	}

	t.Log("a worker's own update does not change the sampler its master applies to both")
	apply(updated(101, services.SamplerAlwaysOff))
	assert.Equal(t, services.SamplerAlwaysOff, samplerOf(worker))
	assert.Empty(t, samplerOf(master))
	assert.Empty(t, generic.samplerUpdates)
	assert.Empty(t, goProgram.samplerUpdates)

	t.Log("the master's update rewrites the samplers of both, once, through their tracer only")
	apply(updated(101, services.SamplerAlwaysOn), updated(100, services.SamplerAlwaysOn))
	assert.Equal(t, services.SamplerAlwaysOn, samplerOf(worker))
	assert.Equal(t, services.SamplerAlwaysOn, samplerOf(master))
	assert.ElementsMatch(t, []recordedSamplerUpdate{
		{pid: 100, ns: 17, fileInfo: master, sampler: &services.SamplerConfig{Name: services.SamplerAlwaysOn}},
		{pid: 101, ns: 17, fileInfo: master, sampler: &services.SamplerConfig{Name: services.SamplerAlwaysOn}},
	}, generic.samplerUpdates)
	assert.Empty(t, goProgram.samplerUpdates)

	generic.samplerUpdates = nil
	apply(updated(300, services.SamplerAlwaysOff))
	assert.Equal(t, []recordedSamplerUpdate{
		{pid: 300, ns: 17, fileInfo: golang, sampler: &services.SamplerConfig{Name: services.SamplerAlwaysOff}},
	}, goProgram.samplerUpdates)
	assert.Empty(t, generic.samplerUpdates)

	t.Log("once the master exits, its remaining worker follows its own update")
	processMatches.Send([]Event[ProcessMatch]{deleted(100)})
	require.Equal(t, EventInstanceDeleted, testutil.ReadChannel(t, tracerEvents, testTimeout).Type)
	apply(updated(101, services.SamplerParentBasedAlwaysOff))
	assert.Equal(t, services.SamplerParentBasedAlwaysOff, samplerOf(master))
	assert.Equal(t, []recordedSamplerUpdate{
		{pid: 101, ns: 17, fileInfo: master, sampler: &services.SamplerConfig{Name: services.SamplerParentBasedAlwaysOff}},
	}, generic.samplerUpdates)

	t.Log("a worker follows its own update when its master leaves in the same batch, in either order")
	generic.samplerUpdates = nil
	apply(updated(201, services.SamplerAlwaysOn), deleted(200))
	apply(deleted(400), updated(401, services.SamplerAlwaysOn))
	assert.Equal(t, []recordedSamplerUpdate{
		{pid: 201, ns: 17, fileInfo: masterA, sampler: &services.SamplerConfig{Name: services.SamplerAlwaysOn}},
		{pid: 401, ns: 17, fileInfo: masterB, sampler: &services.SamplerConfig{Name: services.SamplerAlwaysOn}},
	}, generic.samplerUpdates)
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

	(&traceAttacher{}).monitorPIDs(t.Context(), tracer, &ebpf.Instrumentable{
		Type: svc.InstrumentablePython, FileInfo: worker,
	})

	// Parent should receive main_ssl from worker before applying defaults,
	// rather than falling back to python3.14.
	assert.Equal(t, "main_ssl", parent.ServiceAttrs().UID.Name)
	assert.Equal(t, "main_ssl", worker.ServiceAttrs().UID.Name)
	assert.Equal(t, svc.InstrumentablePython, parent.SDKLanguage())
}
