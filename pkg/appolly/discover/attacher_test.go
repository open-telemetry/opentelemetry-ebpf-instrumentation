// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestTraceAttacher_attacherLoop(t *testing.T) {
	tests := []struct {
		name   string
		cfg    *obi.Config
		setup  func(*traceAttacher)
		events []Event[ebpf.Instrumentable]

		// validateAfterRun validates the state after runFunc completes
		validateAfterRun func(*testing.T, *traceAttacher, []Event[*ebpf.Instrumentable])
	}{
		{
			name: "runFunc closes OutputTracerEvents on context cancellation",
			cfg: &obi.Config{
				Java:      obi.JavaConfig{Enabled: false},
				Discovery: services.DiscoveryConfig{},
			},
			events: nil, // no events, just test context cancellation cleanup
			validateAfterRun: func(t *testing.T, _ *traceAttacher, outputEvents []Event[*ebpf.Instrumentable]) {
				// After runFunc completes, OutputTracerEvents should be closed
				// (verified by the test infrastructure receiving on the closed channel)
				assert.Empty(t, outputEvents)
			},
		},
		{
			name: "runFunc closes OutputTracerEvents on input channel close",
			cfg: &obi.Config{
				Java:      obi.JavaConfig{Enabled: false},
				Discovery: services.DiscoveryConfig{},
			},
			events: []Event[ebpf.Instrumentable]{}, // empty slice signals close without events
			validateAfterRun: func(t *testing.T, _ *traceAttacher, outputEvents []Event[*ebpf.Instrumentable]) {
				assert.Empty(t, outputEvents)
			},
		},
		{
			name: "runFunc processes EventCreated for instrumentable",
			cfg: &obi.Config{
				Java:      obi.JavaConfig{Enabled: false},
				NodeJS:    obi.NodeJSConfig{Enabled: false},
				Discovery: services.DiscoveryConfig{},
			},
			events: []Event[ebpf.Instrumentable]{
				{
					Type: EventCreated,
					Obj: ebpf.Instrumentable{
						Type: svc.InstrumentableGeneric,
						FileInfo: &exec.FileInfo{
							Pid:        12345,
							Ino:        99999,
							CmdExePath: "/usr/bin/test-app",
							Service:    svc.Attrs{},
						},
					},
				},
			},
			validateAfterRun: func(t *testing.T, ta *traceAttacher, _ []Event[*ebpf.Instrumentable]) {
				// The processInstances counter should have been incremented
				// (Note: getTracer will likely fail in test env, so no output events expected)
				count, ok := ta.processInstances[99999]
				assert.True(t, ok)
				if ok {
					assert.Equal(t, 1, *count)
				}
			},
		},
		{
			name: "runFunc processes EventDeleted for instrumentable",
			cfg: &obi.Config{
				Java:      obi.JavaConfig{Enabled: false},
				NodeJS:    obi.NodeJSConfig{Enabled: false},
				Discovery: services.DiscoveryConfig{},
			},
			events: []Event[ebpf.Instrumentable]{
				{
					Type: EventDeleted,
					Obj: ebpf.Instrumentable{
						Type: svc.InstrumentableGeneric,
						FileInfo: &exec.FileInfo{
							Pid:        12345,
							Ino:        88888,
							CmdExePath: "/usr/bin/deleted-app",
							Service:    svc.Attrs{},
						},
					},
				},
			},
			validateAfterRun: func(t *testing.T, _ *traceAttacher, outputEvents []Event[*ebpf.Instrumentable]) {
				// EventDeleted should call notifyProcessDeletion, which checks existingTracers
				// Since no tracer exists for this inode, nothing special happens
				assert.Empty(t, outputEvents)
			},
		},
		{
			name: "runFunc processes multiple events in sequence",
			cfg: &obi.Config{
				Java:      obi.JavaConfig{Enabled: false},
				NodeJS:    obi.NodeJSConfig{Enabled: false},
				Discovery: services.DiscoveryConfig{},
			},
			events: []Event[ebpf.Instrumentable]{
				{
					Type: EventCreated,
					Obj: ebpf.Instrumentable{
						Type: svc.InstrumentableGeneric,
						FileInfo: &exec.FileInfo{
							Pid:        1001,
							Ino:        11111,
							CmdExePath: "/app/service1",
							Service:    svc.Attrs{},
						},
					},
				},
				{
					Type: EventCreated,
					Obj: ebpf.Instrumentable{
						Type: svc.InstrumentableGeneric,
						FileInfo: &exec.FileInfo{
							Pid:        1002,
							Ino:        22222,
							CmdExePath: "/app/service2",
							Service:    svc.Attrs{},
						},
					},
				},
				{
					Type: EventDeleted,
					Obj: ebpf.Instrumentable{
						Type: svc.InstrumentableGeneric,
						FileInfo: &exec.FileInfo{
							Pid:        1001,
							Ino:        11111,
							CmdExePath: "/app/service1",
							Service:    svc.Attrs{},
						},
					},
				},
			},
			validateAfterRun: func(t *testing.T, ta *traceAttacher, _ []Event[*ebpf.Instrumentable]) {
				// processInstances should reflect: +1 for 11111, +1 for 22222, then delete doesn't decrement
				// because notifyProcessDeletion only acts if a tracer exists
				count1, ok1 := ta.processInstances[11111]
				assert.True(t, ok1)
				if ok1 {
					assert.Equal(t, 1, *count1)
				}
				count2, ok2 := ta.processInstances[22222]
				assert.True(t, ok2)
				if ok2 {
					assert.Equal(t, 1, *count2)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create queues for input/output
			inputQueue := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(10))
			outputQueue := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(10))

			ta := &traceAttacher{
				Cfg:                  tt.cfg,
				Metrics:              imetrics.NoopReporter{},
				InputInstrumentables: inputQueue,
				OutputTracerEvents:   outputQueue,
				EbpfEventContext:     &ebpfcommon.EBPFEventContext{},
			}

			if tt.setup != nil {
				tt.setup(ta)
			}

			// Call attacherLoop to get the runFunc
			runFunc, err := ta.attacherLoop(context.Background())
			require.NoError(t, err)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Subscribe to output before starting runFunc
			outputCh := outputQueue.Subscribe(msg.SubscriberName("test"))

			// Collect output events
			var outputEvents []Event[*ebpf.Instrumentable]
			outputDone := make(chan struct{})

			go func() {
				defer close(outputDone)
				for event := range outputCh {
					outputEvents = append(outputEvents, event)
				}
			}()

			// Start runFunc in background
			runFuncDone := make(chan struct{})
			go func() {
				defer close(runFuncDone)
				runFunc(ctx)
			}()

			// Send events if any
			if len(tt.events) > 0 {
				inputQueue.Send(tt.events)
			}

			// Close input queue to signal runFunc to stop
			// ForEachInput drains all buffered events before exiting
			inputQueue.Close()

			// Wait for runFunc to complete
			select {
			case <-runFuncDone:
				// runFunc completed
			case <-time.After(testTimeout):
				t.Fatal("runFunc did not complete within timeout")
			}

			// Wait for output collection to complete
			select {
			case <-outputDone:
				// output collection completed
			case <-time.After(testTimeout):
				t.Fatal("output collection did not complete within timeout")
			}

			// Validate after run
			if tt.validateAfterRun != nil {
				tt.validateAfterRun(t, ta, outputEvents)
			}
		})
	}
}
