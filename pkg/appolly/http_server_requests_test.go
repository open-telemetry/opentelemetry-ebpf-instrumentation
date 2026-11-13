// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"context"
	"log/slog"
	"maps"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestHTTPServerRequestTrackerLifecycle(t *testing.T) {
	var tracker httpServerRequestTracker

	start := ebpfcommon.HTTPServerRequestEvent{
		Type:            ebpfcommon.EventTypeHTTPServerRequestStart,
		IsTls:           true,
		Pid:             ebpfcommon.BpfPidInfoT{HostPid: 123},
		GoroutineAddr:   0x1234,
		StartMonotimeNs: 1000,
	}
	copy(start.Method[:], "GET")
	start.Conn.D_port = 8080

	got, delta := tracker.observe(start, svc.Attrs{})

	require.Equal(t, int64(1), delta)
	assert.Equal(t, ebpfcommon.HTTPServerRequestEventToSpan(&start), got)
	require.Len(t, tracker.active, 1)

	end := ebpfcommon.HTTPServerRequestEvent{
		Type:            ebpfcommon.EventTypeHTTPServerRequestEnd,
		Pid:             start.Pid,
		GoroutineAddr:   start.GoroutineAddr,
		StartMonotimeNs: start.StartMonotimeNs,
	}

	got, delta = tracker.observe(end, svc.Attrs{})

	require.Equal(t, int64(-1), delta)
	assert.Equal(t, ebpfcommon.HTTPServerRequestEventToSpan(&start), got)
	assert.Empty(t, tracker.active)
}

func TestHTTPServerRequestTrackerPreservesServiceAttrs(t *testing.T) {
	var tracker httpServerRequestTracker

	service := svc.Attrs{
		UID: svc.UID{Name: "shop"},
		Metadata: map[attr.Name]string{
			attr.K8sNamespaceName: "default",
		},
		EnvVars: map[string]string{
			"DEPLOYMENT_ENV": "dev",
		},
	}
	start := ebpfcommon.HTTPServerRequestEvent{
		Type:            ebpfcommon.EventTypeHTTPServerRequestStart,
		Pid:             ebpfcommon.BpfPidInfoT{HostPid: 123},
		GoroutineAddr:   0x1234,
		StartMonotimeNs: 1000,
	}

	started, delta := tracker.observe(start, service)

	require.Equal(t, int64(1), delta)
	assert.Equal(t, service, started.Service)

	service.UID.Name = "orders"
	service.Metadata[attr.K8sNamespaceName] = "updated"
	service.EnvVars["DEPLOYMENT_ENV"] = "prod"

	end := start
	end.Type = ebpfcommon.EventTypeHTTPServerRequestEnd

	got, delta := tracker.observe(end, service)

	require.Equal(t, int64(-1), delta)
	assert.Equal(t, started, got)
	assert.Equal(t, "shop", got.Service.UID.Name)
	assert.Equal(t, "default", got.Service.Metadata[attr.K8sNamespaceName])
	assert.Equal(t, "dev", got.Service.EnvVars["DEPLOYMENT_ENV"])
	assert.Empty(t, tracker.active)
}

func TestHTTPServerRequestTrackerDuplicateEvents(t *testing.T) {
	var tracker httpServerRequestTracker

	start := ebpfcommon.HTTPServerRequestEvent{
		Type:            ebpfcommon.EventTypeHTTPServerRequestStart,
		Pid:             ebpfcommon.BpfPidInfoT{HostPid: 123},
		GoroutineAddr:   0x1234,
		StartMonotimeNs: 1000,
	}

	_, delta := tracker.observe(start, svc.Attrs{})
	require.Equal(t, int64(1), delta)

	got, delta := tracker.observe(start, svc.Attrs{})

	assert.Zero(t, delta)
	assert.Equal(t, request.Span{}, got)
	require.Len(t, tracker.active, 1)

	end := ebpfcommon.HTTPServerRequestEvent{
		Type:            ebpfcommon.EventTypeHTTPServerRequestEnd,
		Pid:             start.Pid,
		GoroutineAddr:   start.GoroutineAddr,
		StartMonotimeNs: start.StartMonotimeNs,
	}

	got, delta = tracker.observe(end, svc.Attrs{})

	require.Equal(t, int64(-1), delta)
	assert.Equal(t, ebpfcommon.HTTPServerRequestEventToSpan(&start), got)
	require.Empty(t, tracker.active)

	got, delta = tracker.observe(end, svc.Attrs{})

	assert.Zero(t, delta)
	assert.Equal(t, request.Span{}, got)
	assert.Empty(t, tracker.active)
}

func TestHTTPServerRequestTrackerDistinctRequests(t *testing.T) {
	tests := []struct {
		name            string
		hostPID         uint32
		goroutineAddr   uint64
		startMonotimeNs uint64
	}{
		{
			name:            "different PID",
			hostPID:         124,
			goroutineAddr:   0x1234,
			startMonotimeNs: 1000,
		},
		{
			name:            "different goroutine",
			hostPID:         123,
			goroutineAddr:   0x5678,
			startMonotimeNs: 1000,
		},
		{
			name:            "different start time",
			hostPID:         123,
			goroutineAddr:   0x1234,
			startMonotimeNs: 2000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tracker httpServerRequestTracker

			first := ebpfcommon.HTTPServerRequestEvent{
				Type:            ebpfcommon.EventTypeHTTPServerRequestStart,
				Pid:             ebpfcommon.BpfPidInfoT{HostPid: 123},
				GoroutineAddr:   0x1234,
				StartMonotimeNs: 1000,
			}
			second := first
			second.Pid.HostPid = tt.hostPID
			second.GoroutineAddr = tt.goroutineAddr
			second.StartMonotimeNs = tt.startMonotimeNs

			for _, start := range []ebpfcommon.HTTPServerRequestEvent{first, second} {
				got, delta := tracker.observe(start, svc.Attrs{})

				require.Equal(t, int64(1), delta)
				assert.Equal(t, ebpfcommon.HTTPServerRequestEventToSpan(&start), got)
			}
			require.Len(t, tracker.active, 2)

			for _, start := range []ebpfcommon.HTTPServerRequestEvent{second, first} {
				end := ebpfcommon.HTTPServerRequestEvent{
					Type:            ebpfcommon.EventTypeHTTPServerRequestEnd,
					Pid:             start.Pid,
					GoroutineAddr:   start.GoroutineAddr,
					StartMonotimeNs: start.StartMonotimeNs,
				}

				got, delta := tracker.observe(end, svc.Attrs{})

				require.Equal(t, int64(-1), delta)
				assert.Equal(t, ebpfcommon.HTTPServerRequestEventToSpan(&start), got)
			}
			assert.Empty(t, tracker.active)
		})
	}
}

func TestHTTPServerRequestTrackerIgnoresUnmatchedEvents(t *testing.T) {
	tests := []struct {
		name            string
		eventType       uint8
		startMonotimeNs uint64
	}{
		{
			name:            "end without matching start",
			eventType:       ebpfcommon.EventTypeHTTPServerRequestEnd,
			startMonotimeNs: 2000,
		},
		{
			name:            "unrelated event type",
			eventType:       ebpfcommon.EventTypeHTTPRequest,
			startMonotimeNs: 1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tracker httpServerRequestTracker

			start := ebpfcommon.HTTPServerRequestEvent{
				Type:            ebpfcommon.EventTypeHTTPServerRequestStart,
				Pid:             ebpfcommon.BpfPidInfoT{HostPid: 123},
				GoroutineAddr:   0x1234,
				StartMonotimeNs: 1000,
			}

			_, delta := tracker.observe(start, svc.Attrs{})
			require.Equal(t, int64(1), delta)

			unmatched := start
			unmatched.Type = tt.eventType
			unmatched.StartMonotimeNs = tt.startMonotimeNs

			got, delta := tracker.observe(unmatched, svc.Attrs{})

			assert.Zero(t, delta)
			assert.Equal(t, request.Span{}, got)
			require.Len(t, tracker.active, 1)

			end := start
			end.Type = ebpfcommon.EventTypeHTTPServerRequestEnd

			got, delta = tracker.observe(end, svc.Attrs{})

			require.Equal(t, int64(-1), delta)
			assert.Equal(t, ebpfcommon.HTTPServerRequestEventToSpan(&start), got)
			assert.Empty(t, tracker.active)
		})
	}
}

func TestHTTPServerRequestTrackerRemovePID(t *testing.T) {
	var tracker httpServerRequestTracker

	service := svc.Attrs{ProcPID: 10}
	otherService := svc.Attrs{ProcPID: 20}

	first := ebpfcommon.HTTPServerRequestEvent{
		Type:            ebpfcommon.EventTypeHTTPServerRequestStart,
		Pid:             ebpfcommon.BpfPidInfoT{HostPid: 123},
		GoroutineAddr:   0x1234,
		StartMonotimeNs: 1000,
	}
	copy(first.Method[:], "GET")

	second := first
	second.GoroutineAddr = 0x5678
	second.IsTls = true
	copy(second.Method[:], "POST")

	other := first
	other.Pid.HostPid = 456

	for _, start := range []ebpfcommon.HTTPServerRequestEvent{first, second} {
		_, delta := tracker.observe(start, service)
		require.Equal(t, int64(1), delta)
	}

	_, delta := tracker.observe(other, otherService)
	require.Equal(t, int64(1), delta)

	assert.Empty(t, tracker.removePID(123))
	require.Len(t, tracker.active, 3)

	removed := tracker.removePID(10)

	expectedFirst := ebpfcommon.HTTPServerRequestEventToSpan(&first)
	expectedFirst.Service = service
	expectedSecond := ebpfcommon.HTTPServerRequestEventToSpan(&second)
	expectedSecond.Service = service

	assert.ElementsMatch(t, []request.Span{
		expectedFirst,
		expectedSecond,
	}, removed)
	require.Len(t, tracker.active, 1)

	assert.Empty(t, tracker.removePID(10))
	require.Len(t, tracker.active, 1)

	lateEnd := first
	lateEnd.Type = ebpfcommon.EventTypeHTTPServerRequestEnd

	_, delta = tracker.observe(lateEnd, svc.Attrs{})

	assert.Zero(t, delta)
	require.Len(t, tracker.active, 1)

	end := other
	end.Type = ebpfcommon.EventTypeHTTPServerRequestEnd

	got, delta := tracker.observe(end, svc.Attrs{})

	expectedOther := ebpfcommon.HTTPServerRequestEventToSpan(&other)
	expectedOther.Service = otherService

	require.Equal(t, int64(-1), delta)
	assert.Equal(t, expectedOther, got)
	assert.Empty(t, tracker.active)
}

func TestHTTPServerRequestService(t *testing.T) {
	service := svc.Attrs{
		UID:      svc.UID{Name: "shop"},
		Features: export.FeatureHTTPServerActiveRequests,
	}
	other := service
	other.UID.Name = "orders"

	currentPIDs := map[uint32]map[app.PID]svc.Attrs{
		67: {
			45: service,
			46: {Features: export.FeatureAll},
		},
		89: {
			45: other,
		},
	}

	collector := httpServerRequestCollector{currentPIDs: currentPIDs}
	got, ok := collector.service(ebpfcommon.BpfPidInfoT{
		HostPid: 123,
		UserPid: 45,
		Ns:      67,
	})
	require.True(t, ok)
	assert.Equal(t, service, got)

	got, ok = collector.service(ebpfcommon.BpfPidInfoT{
		HostPid: 456,
		UserPid: 45,
		Ns:      89,
	})
	require.True(t, ok)
	assert.Equal(t, other, got)

	tests := []struct {
		name string
		pid  ebpfcommon.BpfPidInfoT
	}{
		{
			name: "unknown namespace",
			pid:  ebpfcommon.BpfPidInfoT{UserPid: 45, Ns: 999},
		},
		{
			name: "unknown user PID",
			pid:  ebpfcommon.BpfPidInfoT{HostPid: 45, UserPid: 999, Ns: 67},
		},
		{
			name: "feature not selected",
			pid:  ebpfcommon.BpfPidInfoT{UserPid: 46, Ns: 67},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := collector.service(tt.pid)

			assert.False(t, ok)
			assert.Equal(t, svc.Attrs{}, got)
		})
	}
}

func TestHTTPServerRequestCollectorLifecycle(t *testing.T) {
	ctx := t.Context()
	output := msg.NewQueue[[]request.HTTPServerRequestDelta](
		msg.ChannelBufferLen(1),
	)
	t.Cleanup(output.Close)
	out := output.Subscribe()

	service := svc.Attrs{
		UID:      svc.UID{Name: "shop"},
		ProcPID:  10,
		Features: export.FeatureHTTPServerActiveRequests,
	}
	collector := httpServerRequestCollector{
		currentPIDs: map[uint32]map[app.PID]svc.Attrs{
			67: {45: service},
		},
		output: output,
	}

	start := ebpfcommon.HTTPServerRequestEvent{
		Type: ebpfcommon.EventTypeHTTPServerRequestStart,
		Pid: ebpfcommon.BpfPidInfoT{
			HostPid: 123,
			UserPid: 45,
			Ns:      67,
		},
		GoroutineAddr:   0x1234,
		StartMonotimeNs: 1000,
	}
	copy(start.Method[:], "GET")

	expected := ebpfcommon.HTTPServerRequestEventToSpan(&start)
	expected.Service = service

	collector.handleRequest(ctx, start)

	require.Len(t, out, 1)
	assert.Equal(t, []request.HTTPServerRequestDelta{{
		Span:  expected,
		Delta: 1,
	}}, <-out)

	collector.handleRequest(ctx, start)
	require.Empty(t, out)
	require.Len(t, collector.tracker.active, 1)

	collector.currentPIDs = nil

	end := start
	end.Type = ebpfcommon.EventTypeHTTPServerRequestEnd

	collector.handleRequest(ctx, end)

	require.Len(t, out, 1)
	assert.Equal(t, []request.HTTPServerRequestDelta{{
		Span:  expected,
		Delta: -1,
	}}, <-out)
	assert.Empty(t, collector.tracker.active)

	collector.handleRequest(ctx, end)
	require.Empty(t, out)

	collector.handleRequest(ctx, start)
	assert.Empty(t, out)
	assert.Empty(t, collector.tracker.active)
}

func TestHTTPServerRequestCollectorMetricsSelection(t *testing.T) {
	tests := []struct {
		name        string
		dynamicPID  app.PID
		selectedPID uint32
	}{
		{
			name:        "process PID",
			selectedPID: 10,
		},
		{
			name:        "dynamic selector PID",
			dynamicPID:  20,
			selectedPID: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			selector := discover.NewDynamicSelector()
			selector.Traces().AddPIDs(tt.selectedPID)

			output := msg.NewQueue[[]request.HTTPServerRequestDelta](
				msg.ChannelBufferLen(1),
			)
			t.Cleanup(output.Close)
			out := output.Subscribe()

			service := svc.Attrs{
				UID:                svc.UID{Name: "shop"},
				ProcPID:            10,
				DynamicSelectorPID: tt.dynamicPID,
				Features:           export.FeatureHTTPServerActiveRequests,
			}
			collector := httpServerRequestCollector{
				currentPIDs: map[uint32]map[app.PID]svc.Attrs{
					67: {45: service},
				},
				metricsSelector: selector.AppMetrics(),
				output:          output,
			}

			start := ebpfcommon.HTTPServerRequestEvent{
				Type: ebpfcommon.EventTypeHTTPServerRequestStart,
				Pid: ebpfcommon.BpfPidInfoT{
					HostPid: 123,
					UserPid: 45,
					Ns:      67,
				},
				GoroutineAddr:   0x1234,
				StartMonotimeNs: 1000,
			}
			copy(start.Method[:], "GET")

			collector.handleRequest(ctx, start)

			require.Empty(t, out)
			require.Empty(t, collector.tracker.active)

			selector.AppMetrics().AddPIDs(tt.selectedPID)
			collector.handleRequest(ctx, start)

			expected := ebpfcommon.HTTPServerRequestEventToSpan(&start)
			expected.Service = service

			require.Len(t, out, 1)
			assert.Equal(t, []request.HTTPServerRequestDelta{{
				Span:  expected,
				Delta: 1,
			}}, <-out)
			require.Len(t, collector.tracker.active, 1)

			selector.AppMetrics().RemovePIDs(tt.selectedPID)

			next := start
			next.StartMonotimeNs++
			collector.handleRequest(ctx, next)

			require.Empty(t, out)
			require.Len(t, collector.tracker.active, 1)

			end := start
			end.Type = ebpfcommon.EventTypeHTTPServerRequestEnd
			collector.handleRequest(ctx, end)

			require.Len(t, out, 1)
			assert.Equal(t, []request.HTTPServerRequestDelta{{
				Span:  expected,
				Delta: -1,
			}}, <-out)
			assert.Empty(t, collector.tracker.active)
		})
	}
}

func TestHTTPServerRequestCollectorRemoveProcess(t *testing.T) {
	ctx := t.Context()
	output := msg.NewQueue[[]request.HTTPServerRequestDelta](
		msg.ChannelBufferLen(1),
	)
	t.Cleanup(output.Close)
	out := output.Subscribe()

	service := svc.Attrs{
		UID:      svc.UID{Name: "shop"},
		ProcPID:  10,
		Features: export.FeatureHTTPServerActiveRequests,
	}
	otherService := service
	otherService.UID.Name = "orders"
	otherService.ProcPID = 20

	collector := httpServerRequestCollector{
		processFiles: map[app.PID]*exec.FileInfo{
			10: exec.New(exec.Init{Pid: 10, Service: service}),
			20: exec.New(exec.Init{Pid: 20, Service: otherService}),
		},
		currentPIDs: map[uint32]map[app.PID]svc.Attrs{
			67: {
				45:  service,
				123: service,
			},
			89: {45: otherService},
		},
		output: output,
	}

	first := ebpfcommon.HTTPServerRequestEvent{
		Type: ebpfcommon.EventTypeHTTPServerRequestStart,
		Pid: ebpfcommon.BpfPidInfoT{
			HostPid: 123,
			UserPid: 45,
			Ns:      67,
		},
		GoroutineAddr:   0x1234,
		StartMonotimeNs: 1000,
	}
	copy(first.Method[:], "GET")

	second := first
	second.GoroutineAddr = 0x5678
	second.IsTls = true
	copy(second.Method[:], "POST")

	other := first
	other.Pid.HostPid = 456
	other.Pid.Ns = 89

	var expected []request.HTTPServerRequestDelta
	for _, start := range []ebpfcommon.HTTPServerRequestEvent{first, second, other} {
		collector.handleRequest(ctx, start)

		require.Len(t, out, 1)
		deltas := <-out
		require.Len(t, deltas, 1)
		require.Equal(t, int64(1), deltas[0].Delta)

		deltas[0].Delta = -1
		expected = append(expected, deltas[0])
	}

	collector.removeProcess(ctx, 10)

	require.Len(t, out, 1)
	assert.ElementsMatch(t, expected[:2], <-out)
	require.Len(t, collector.tracker.active, 1)
	assert.Empty(t, collector.currentPIDs[67])
	assert.NotContains(t, collector.processFiles, app.PID(10))
	assert.Contains(t, collector.processFiles, app.PID(20))
	assert.Equal(t, otherService, collector.currentPIDs[89][45])

	collector.removeProcess(ctx, 10)
	require.Empty(t, out)
	require.Len(t, collector.tracker.active, 1)

	lateEnd := first
	lateEnd.Type = ebpfcommon.EventTypeHTTPServerRequestEnd

	collector.handleRequest(ctx, lateEnd)
	require.Empty(t, out)
	require.Len(t, collector.tracker.active, 1)

	end := other
	end.Type = ebpfcommon.EventTypeHTTPServerRequestEnd

	collector.handleRequest(ctx, end)

	require.Len(t, out, 1)
	assert.Equal(t, []request.HTTPServerRequestDelta{expected[2]}, <-out)
	assert.Empty(t, collector.tracker.active)
}

type httpServerRequestTestFilter struct {
	ebpfcommon.IdentityPidsFilter
	current map[uint32]map[app.PID]svc.Attrs
}

func (f *httpServerRequestTestFilter) CurrentPIDs(
	_ ebpfcommon.PIDType,
) map[uint32]map[app.PID]svc.Attrs {
	current := make(map[uint32]map[app.PID]svc.Attrs, len(f.current))
	for ns, pids := range f.current {
		current[ns] = maps.Clone(pids)
	}
	return current
}

func TestHTTPServerRequestsNodeLifecycle(t *testing.T) {
	service := svc.Attrs{
		UID:      svc.UID{Name: "shop"},
		ProcPID:  10,
		Features: export.FeatureHTTPServerActiveRequests,
	}
	eventContext := ebpfcommon.NewEBPFEventContext()
	eventContext.CommonPIDsFilter = &httpServerRequestTestFilter{
		current: map[uint32]map[app.PID]svc.Attrs{
			67: {45: service},
		},
	}

	processEvents := msg.NewQueue[exec.ProcessEvent]()
	t.Cleanup(processEvents.Close)

	output := msg.NewQueue[[]request.HTTPServerRequestDelta]()
	t.Cleanup(output.Close)
	out := output.Subscribe()

	run, err := httpServerRequestsNode(
		nil, eventContext, 1, processEvents, output,
	)(t.Context())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		testutil.ReadChannel(t, done, time.Second)
	})
	go func() {
		defer close(done)
		run(ctx)
	}()

	start := ebpfcommon.HTTPServerRequestEvent{
		Type: ebpfcommon.EventTypeHTTPServerRequestStart,
		Pid: ebpfcommon.BpfPidInfoT{
			HostPid: 123,
			UserPid: 45,
			Ns:      67,
		},
		GoroutineAddr:   0x1234,
		StartMonotimeNs: 1000,
	}
	copy(start.Method[:], "GET")

	expected := ebpfcommon.HTTPServerRequestEventToSpan(&start)
	expected.Service = service

	eventContext.HTTPServerRequests(start)

	got := testutil.ReadChannel(t, out, time.Second)
	assert.Equal(t, []request.HTTPServerRequestDelta{{
		Span:  expected,
		Delta: 1,
	}}, got)

	end := start
	end.Type = ebpfcommon.EventTypeHTTPServerRequestEnd

	eventContext.HTTPServerRequests(end)

	got = testutil.ReadChannel(t, out, time.Second)
	assert.Equal(t, []request.HTTPServerRequestDelta{{
		Span:  expected,
		Delta: -1,
	}}, got)
}

func TestHTTPServerRequestsNodeStopsCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	eventContext := ebpfcommon.NewEBPFEventContext()

	processEvents := msg.NewQueue[exec.ProcessEvent]()
	t.Cleanup(processEvents.Close)

	output := msg.NewQueue[[]request.HTTPServerRequestDelta]()
	t.Cleanup(output.Close)
	out := output.Subscribe()

	run, err := httpServerRequestsNode(
		nil, eventContext, 0, processEvents, output,
	)(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		testutil.ReadChannel(t, done, time.Second)
	})
	go func() {
		defer close(done)
		run(ctx)
	}()

	processEvents.Close()
	testutil.ReadChannel(t, done, time.Second)

	require.NoError(t, ctx.Err())
	select {
	case _, open := <-out:
		assert.False(t, open)
	default:
		t.Fatal("output queue is still open")
	}

	callbackDone := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		testutil.ReadChannel(t, callbackDone, time.Second)
	})
	go func() {
		defer close(callbackDone)
		eventContext.HTTPServerRequests(ebpfcommon.HTTPServerRequestEvent{
			Type: ebpfcommon.EventTypeHTTPServerRequestStart,
		})
	}()

	testutil.ReadChannel(t, callbackDone, time.Second)
}

func TestHTTPServerRequestsNodeUsesLiveProcessMetadata(t *testing.T) {
	pid := app.PID(os.Getpid())
	file := exec.New(exec.Init{Pid: pid, Service: svc.Attrs{
		ProcPID:  pid,
		UID:      svc.UID{Name: "before"},
		Features: export.FeatureHTTPServerActiveRequests,
		Metadata: map[attr.Name]string{attr.K8sNamespaceName: "before"},
	}})

	filter := ebpfcommon.NewPIDsFilter(&obi.DefaultConfig.Discovery, slog.Default(), imetrics.NoopReporter{})
	filter.AllowPID(pid, 67, file, ebpfcommon.PIDTypeGo)

	events := ebpfcommon.NewEBPFEventContext()
	events.CommonPIDsFilter = filter

	selector := discover.NewDynamicSelector()
	selector.AppMetrics().AddPIDs(uint32(pid))

	processes := msg.NewQueue[exec.ProcessEvent](msg.ChannelBufferLen(0))
	t.Cleanup(processes.Close)

	output := msg.NewQueue[[]request.HTTPServerRequestDelta](msg.ChannelBufferLen(4))
	out := output.Subscribe()

	gate := dynamicSignalProcessEventGate{
		selector:  selector.AppMetrics(),
		output:    processes,
		current:   map[app.PID]*exec.FileInfo{},
		forwarded: map[app.PID]bool{},
	}

	ctx, cancel := context.WithCancel(t.Context())
	run, err := httpServerRequestsNode(selector, events, 4, processes, output)(ctx)
	require.NoError(t, err)

	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		testutil.ReadChannel(t, done, time.Second)
	})
	go func() {
		defer close(done)
		run(ctx)
	}()

	gate.handleProcessEvent(exec.ProcessEvent{Type: exec.ProcessEventCreated, File: file})

	first := ebpfcommon.HTTPServerRequestEvent{
		Type:            ebpfcommon.EventTypeHTTPServerRequestStart,
		Pid:             ebpfcommon.BpfPidInfoT{HostPid: uint32(pid), UserPid: uint32(pid), Ns: 67},
		GoroutineAddr:   1234,
		StartMonotimeNs: 1000,
	}
	copy(first.Method[:], "GET")
	events.HTTPServerRequests(first)

	started := testutil.ReadChannel(t, out, time.Second)
	require.Equal(t, "before", started[0].Span.Service.UID.Name)

	file.SetUID(svc.UID{Name: "after"})
	file.SetMetadata(map[attr.Name]string{attr.K8sNamespaceName: "after"})
	gate.handleProcessEvent(exec.ProcessEvent{Type: exec.ProcessEventCreated, File: file})

	second := first
	second.GoroutineAddr++
	events.HTTPServerRequests(second)

	updated := testutil.ReadChannel(t, out, time.Second)
	require.Equal(t, "after", updated[0].Span.Service.UID.Name)
	require.Equal(t, "after", updated[0].Span.Service.Metadata[attr.K8sNamespaceName])
	require.Equal(t, "before", started[0].Span.Service.Metadata[attr.K8sNamespaceName])

	first.Type = ebpfcommon.EventTypeHTTPServerRequestEnd
	events.HTTPServerRequests(first)

	started[0].Delta = -1
	assert.Equal(t, started, testutil.ReadChannel(t, out, time.Second))

	filter.BlockPID(pid, 67)
	gate.handleProcessEvent(exec.ProcessEvent{Type: exec.ProcessEventTerminated, File: file})

	updated[0].Delta = -1
	assert.Equal(t, updated, testutil.ReadChannel(t, out, time.Second))

	second.Type = ebpfcommon.EventTypeHTTPServerRequestEnd
	events.HTTPServerRequests(second)

	second.Type = ebpfcommon.EventTypeHTTPServerRequestStart
	second.StartMonotimeNs++
	events.HTTPServerRequests(second)

	testutil.ChannelEmpty(t, out, 50*time.Millisecond)
}
