// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	execpkg "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

const gateTestTimeout = time.Second

func TestDynamicSignalSpanGate(t *testing.T) {
	sel := discover.NewDynamicPIDSelector()
	sel.Traces().AddPIDs(1)
	sel.AppMetrics().AddPIDs(2)
	sel.Traces().AddPIDs(3)
	sel.AppMetrics().AddPIDs(3)

	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(4))
	outCh := output.Subscribe()

	runFn, err := DynamicSignalSpanGate(sel, input, output)(t.Context())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go runFn(ctx)

	input.Send([]request.Span{
		{Service: svc.Attrs{ProcPID: 10, DynamicSelectorPID: 1}},
		{Service: svc.Attrs{ProcPID: 20, DynamicSelectorPID: 2}},
		{Service: svc.Attrs{ProcPID: 30, DynamicSelectorPID: 3}},
	})

	got := testutil.ReadChannel(t, outCh, gateTestTimeout)
	require.Len(t, got, 3)
	assert.False(t, request.IgnoreTraces(&got[0]))
	assert.True(t, request.IgnoreMetrics(&got[0]))

	assert.True(t, request.IgnoreTraces(&got[1]))
	assert.False(t, request.IgnoreMetrics(&got[1]))

	assert.False(t, request.IgnoreTraces(&got[2]))
	assert.False(t, request.IgnoreMetrics(&got[2]))
}

func TestDynamicSignalProcessEventGate(t *testing.T) {
	sel := discover.NewDynamicPIDSelector()
	sel.Traces().AddPIDs(1)
	sel.AppMetrics().AddPIDs(2)

	input := msg.NewQueue[execpkg.ProcessEvent](msg.ChannelBufferLen(8))
	output := msg.NewQueue[execpkg.ProcessEvent](msg.ChannelBufferLen(8))
	outCh := output.Subscribe()

	runFn, err := DynamicSignalProcessEventGate(sel, input, output)(t.Context())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go runFn(ctx)

	file1 := execpkg.New(execpkg.Init{
		Service: svc.Attrs{ProcPID: 100, DynamicSelectorPID: 1},
		Pid:     100,
	})
	file2 := execpkg.New(execpkg.Init{
		Service: svc.Attrs{ProcPID: 200, DynamicSelectorPID: 2},
		Pid:     200,
	})
	file3 := execpkg.New(execpkg.Init{
		Service: svc.Attrs{ProcPID: 300, DynamicSelectorPID: 1},
		Pid:     300,
	})

	input.Send(execpkg.ProcessEvent{Type: execpkg.ProcessEventCreated, File: file1})
	input.Send(execpkg.ProcessEvent{Type: execpkg.ProcessEventCreated, File: file2})
	input.Send(execpkg.ProcessEvent{Type: execpkg.ProcessEventCreated, File: file3})

	got := testutil.ReadChannel(t, outCh, gateTestTimeout)
	assert.Equal(t, app.PID(200), got.File.Pid())
	testutil.ChannelEmpty(t, outCh, 100*time.Millisecond)

	sel.AppMetrics().AddPIDs(1)
	got = testutil.ReadChannel(t, outCh, gateTestTimeout)
	got2 := testutil.ReadChannel(t, outCh, gateTestTimeout)
	assert.Equal(t, execpkg.ProcessEventCreated, got.Type)
	assert.Equal(t, execpkg.ProcessEventCreated, got2.Type)
	assert.ElementsMatch(t, []app.PID{100, 300}, []app.PID{got.File.Pid(), got2.File.Pid()})

	sel.AppMetrics().RemovePIDs(2)
	got = testutil.ReadChannel(t, outCh, gateTestTimeout)
	assert.Equal(t, execpkg.ProcessEventTerminated, got.Type)
	assert.Equal(t, app.PID(200), got.File.Pid())
}

func TestDynamicSignalProcessEventGate_DuplicateCreateBeforeRemoveNotify(t *testing.T) {
	sel := discover.NewDynamicPIDSelector()
	sel.AppMetrics().AddPIDs(1)

	output := msg.NewQueue[execpkg.ProcessEvent](msg.ChannelBufferLen(4))
	outCh := output.Subscribe()

	gate := &dynamicSignalProcessEventGate{
		output:    output,
		selector:  sel.AppMetrics(),
		current:   map[app.PID]*execpkg.FileInfo{},
		forwarded: map[app.PID]bool{},
	}

	file := execpkg.New(execpkg.Init{
		Service: svc.Attrs{ProcPID: 100, DynamicSelectorPID: 1},
		Pid:     100,
	})

	gate.handleProcessEvent(execpkg.ProcessEvent{Type: execpkg.ProcessEventCreated, File: file})
	got := testutil.ReadChannel(t, outCh, gateTestTimeout)
	assert.Equal(t, execpkg.ProcessEventCreated, got.Type)

	sel.AppMetrics().RemovePIDs(1)

	// Duplicate create (e.g. K8s re-enrichment) before RemovedNotify is processed.
	gate.handleProcessEvent(execpkg.ProcessEvent{Type: execpkg.ProcessEventCreated, File: file})

	assert.True(t, gate.forwarded[100], "duplicate create must not clear forwarded state")

	gate.handleSelectorRemove([]app.PID{1})

	got = testutil.ReadChannel(t, outCh, gateTestTimeout)
	assert.Equal(t, execpkg.ProcessEventTerminated, got.Type)
	assert.Equal(t, app.PID(100), got.File.Pid())
}

func TestDynamicSignalRuntimeMetricsGate(t *testing.T) {
	sel := discover.NewDynamicPIDSelector()
	sel.AppMetrics().AddPIDs(1)
	sel.Traces().AddPIDs(2)

	input := msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(4))
	output := msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(4))
	outCh := output.Subscribe()

	runFn, err := DynamicSignalRuntimeMetricsGate(sel, input, output)(t.Context())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go runFn(ctx)

	input.Send([]runtimemetrics.RuntimeMetricSnapshot{
		{Service: svc.Attrs{ProcPID: 10, DynamicSelectorPID: 1}, PID: 10},
		{Service: svc.Attrs{ProcPID: 20, DynamicSelectorPID: 2}, PID: 20},
		{Service: svc.Attrs{ProcPID: 30}, PID: 30},
	})

	got := testutil.ReadChannel(t, outCh, gateTestTimeout)
	require.Len(t, got, 1)
	assert.Equal(t, app.PID(10), got[0].PID)
	assert.Equal(t, app.PID(1), runtimeMetricSignalPID(got[0]))
}

func TestDynamicSignalRuntimeMetricsGate_BypassWhenSelectorNil(t *testing.T) {
	input := msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(2))
	output := msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(2))
	outCh := output.Subscribe()

	runFn, err := DynamicSignalRuntimeMetricsGate(nil, input, output)(t.Context())
	require.NoError(t, err)
	go runFn(t.Context())

	input.Send([]runtimemetrics.RuntimeMetricSnapshot{
		{Service: svc.Attrs{ProcPID: 10}, PID: 10},
	})
	got := testutil.ReadChannel(t, outCh, gateTestTimeout)
	require.Len(t, got, 1)
	assert.Equal(t, app.PID(10), got[0].PID)
}

func TestDynamicSignalSpanGate_BypassWhenSelectorNil(t *testing.T) {
	input := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(2))
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(2))
	output.Subscribe()

	runFn, err := DynamicSignalSpanGate(nil, input, output)(t.Context())
	require.NoError(t, err)
	go runFn(t.Context())

	input.Send([]request.Span{{Service: svc.Attrs{ProcPID: 1}}})
	time.Sleep(50 * time.Millisecond)
}
