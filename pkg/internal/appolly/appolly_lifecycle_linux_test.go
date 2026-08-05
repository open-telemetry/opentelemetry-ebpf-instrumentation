// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package appolly

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func runTracerLifecycleEvents(
	t *testing.T,
	cancelBeforeStart bool,
	eventTypes ...discover.WatchEventType,
) int {
	t.Helper()

	eventContext := ebpfcommon.NewEBPFEventContext()
	eventContext.EBPFMaps["sentinel"] = nil

	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1))
	processEventCh := processEvents.Subscribe()
	cfg := &obi.Config{ShutdownTimeout: time.Second}
	tracer := ebpf.NewProcessTracer(
		ebpf.Go,
		nil,
		cfg,
		imetrics.NoopReporter{},
	)
	instrumentable := &ebpf.Instrumentable{
		FileInfo: exec.New(exec.Init{Pid: 42, Ino: 1234}),
		Tracer:   tracer,
	}
	instrumenter := &Instrumenter{
		config:            cfg,
		tracersWg:         &sync.WaitGroup{},
		ebpfEventContext:  eventContext,
		processEventInput: processEvents,
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	events := make(chan discover.Event[*ebpf.Instrumentable], len(eventTypes))
	for _, eventType := range eventTypes {
		events <- discover.Event[*ebpf.Instrumentable]{
			Type: eventType,
			Obj:  instrumentable,
		}
	}
	if cancelBeforeStart {
		cancel()
		close(events)
	}
	instrumenter.startInstrumentedEventLoop(ctx, events, nil)

	if !cancelBeforeStart {
		hasCreated := false
		for _, eventType := range eventTypes {
			hasCreated = hasCreated || eventType == discover.EventCreated
		}
		if hasCreated {
			created := testutil.ReadChannel(t, processEventCh, time.Second)
			assert.Equal(t, exec.ProcessEventCreated, created.Type)
		}
		cancel()
		close(events)
	}
	require.NoError(t, instrumenter.stop())
	return len(eventContext.EBPFMaps)
}

func TestTracerLifecycleEventOwnsProcessTracerRun(t *testing.T) {
	assert.Equal(t,
		0,
		runTracerLifecycleEvents(t, false, discover.EventCreated),
	)
	assert.Equal(t,
		0,
		runTracerLifecycleEvents(
			t,
			false,
			discover.EventTracerInitialized,
			discover.EventCreated,
		),
	)
	assert.Equal(t,
		0,
		runTracerLifecycleEvents(
			t,
			true,
			discover.EventTracerInitialized,
			discover.EventCreated,
		),
	)
	assert.Equal(t,
		0,
		runTracerLifecycleEvents(t, false, discover.EventTracerInitialized),
	)
}

func TestTracerLifecycleDispatchWaitsForSubscriber(t *testing.T) {
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1))
	instrumenter := &Instrumenter{
		tracersWg:         &sync.WaitGroup{},
		processEventInput: processEvents,
	}
	events := make(chan discover.Event[*ebpf.Instrumentable], 1)
	events <- discover.Event[*ebpf.Instrumentable]{
		Type: discover.EventCreated,
		Obj: &ebpf.Instrumentable{
			FileInfo: exec.New(exec.Init{Pid: 42, Ino: 1234}),
		},
	}
	close(events)
	dispatchReady := make(chan struct{})
	instrumenter.startInstrumentedEventLoop(t.Context(), events, dispatchReady)

	processEventCh := processEvents.Subscribe()
	select {
	case event := <-processEventCh:
		t.Fatalf("process event dispatched before the graph was ready: %+v", event)
	case <-time.After(25 * time.Millisecond):
	}

	close(dispatchReady)
	created := testutil.ReadChannel(t, processEventCh, time.Second)
	assert.Equal(t, exec.ProcessEventCreated, created.Type)
	instrumenter.eventLoopWg.Wait()
}

func TestCanceledTracerLifecycleDrainSkipsBlockedDispatch(t *testing.T) {
	eventContext := ebpfcommon.NewEBPFEventContext()
	eventContext.EBPFMaps["sentinel"] = nil

	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1))
	processEventCh := processEvents.Subscribe()
	processEvents.Send(exec.ProcessEvent{
		Type: exec.ProcessEventCreated,
		File: exec.New(exec.Init{Pid: 1}),
	})
	cfg := &obi.Config{ShutdownTimeout: time.Second}
	tracer := ebpf.NewProcessTracer(ebpf.Go, nil, cfg, imetrics.NoopReporter{})
	instrumentable := &ebpf.Instrumentable{
		FileInfo: exec.New(exec.Init{Pid: 42, Ino: 1234}),
		Tracer:   tracer,
	}
	events := make(chan discover.Event[*ebpf.Instrumentable], 2)
	events <- discover.Event[*ebpf.Instrumentable]{
		Type: discover.EventCreated,
		Obj:  instrumentable,
	}
	events <- discover.Event[*ebpf.Instrumentable]{
		Type: discover.EventTracerInitialized,
		Obj:  instrumentable,
	}
	close(events)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	instrumenter := &Instrumenter{
		config:            cfg,
		tracersWg:         &sync.WaitGroup{},
		ebpfEventContext:  eventContext,
		processEventInput: processEvents,
	}
	instrumenter.startInstrumentedEventLoop(ctx, events, make(chan struct{}))

	require.NoError(t, instrumenter.stop())
	assert.Empty(t, eventContext.EBPFMaps)
	_ = testutil.ReadChannel(t, processEventCh, time.Second)
}

func TestStopWaitsForLateTracerLifecycleEvent(t *testing.T) {
	eventContext := ebpfcommon.NewEBPFEventContext()
	eventContext.EBPFMaps["sentinel"] = nil

	cfg := &obi.Config{ShutdownTimeout: time.Second}
	processEvents := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(1))
	tracer := ebpf.NewProcessTracer(ebpf.Go, nil, cfg, imetrics.NoopReporter{})
	instrumentable := &ebpf.Instrumentable{
		FileInfo: exec.New(exec.Init{Pid: 42, Ino: 1234}),
		Tracer:   tracer,
	}
	events := make(chan discover.Event[*ebpf.Instrumentable], 2)
	events <- discover.Event[*ebpf.Instrumentable]{
		Type: discover.EventCreated,
		Obj:  instrumentable,
	}
	events <- discover.Event[*ebpf.Instrumentable]{
		Type: discover.EventTracerInitialized,
		Obj:  instrumentable,
	}
	close(events)
	dispatchReady := make(chan struct{})
	instrumenter := &Instrumenter{
		config:            cfg,
		tracersWg:         &sync.WaitGroup{},
		ebpfEventContext:  eventContext,
		processEventInput: processEvents,
	}
	instrumenter.startInstrumentedEventLoop(t.Context(), events, dispatchReady)

	stopDone := make(chan error, 1)
	go func() {
		stopDone <- instrumenter.stop()
	}()
	select {
	case err := <-stopDone:
		t.Fatalf("stop returned before the lifecycle stream drained: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	close(dispatchReady)
	require.NoError(t, testutil.ReadChannel(t, stopDone, time.Second))
	assert.Empty(t, eventContext.EBPFMaps)
}
