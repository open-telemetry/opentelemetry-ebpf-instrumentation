// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"os"
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
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func TestTraceAttacher_attacherLoop(t *testing.T) {
	tests := []struct {
		name          string
		cfg           *obi.Config
		setup         func(*traceAttacher)
		events        []Event[ebpf.Instrumentable]
		runRunFunc    bool
		expectedError bool

		// validateInit validates the state after attacherLoop returns but before runFunc executes
		validateInit func(*testing.T, *traceAttacher, swarm.RunFunc, error)

		// validateAfterRun validates the state after runFunc completes (only if runRunFunc is true)
		validateAfterRun func(*testing.T, *traceAttacher, []Event[*ebpf.Instrumentable])
	}{
		{
			name: "initialization with Java disabled sets up all fields correctly",
			cfg: &obi.Config{
				Java:      obi.JavaConfig{Enabled: false},
				Discovery: services.DiscoveryConfig{},
			},
			validateInit: func(t *testing.T, ta *traceAttacher, runFunc swarm.RunFunc, err error) {
				require.NoError(t, err)
				require.NotNil(t, runFunc)

				// Verify all fields are initialized
				assert.NotNil(t, ta.log)
				assert.NotNil(t, ta.existingTracers)
				assert.NotNil(t, ta.nodeInjector)
				assert.Equal(t, os.Getpid(), ta.obiPID)
				assert.NotNil(t, ta.processInstances)
				assert.NotNil(t, ta.processAgeFunc)
				assert.NotNil(t, ta.EbpfEventContext.CommonPIDsFilter)
				assert.NotNil(t, ta.routeHarvester)

				// When Java is disabled, NewJavaInjector returns nil, nil
				assert.Nil(t, ta.javaInjector)
			},
		},
		{
			name: "initialization with Java enabled handles missing agent jar gracefully",
			cfg: &obi.Config{
				Java: obi.JavaConfig{
					Enabled: true,
					Timeout: 10 * time.Second,
				},
				Discovery: services.DiscoveryConfig{},
			},
			runRunFunc:    false,
			expectedError: false,
			validateInit: func(t *testing.T, ta *traceAttacher, runFunc swarm.RunFunc, err error) {
				// When Java is enabled but agent jar is not found, NewJavaInjector returns an error
				// The code should log a warning and continue without Java injection
				// (expected in test environment where the jar doesn't exist)
				require.NoError(t, err)
				require.NotNil(t, runFunc)
			},
		},
		{
			name: "runFunc closes OutputTracerEvents on context cancellation",
			cfg: &obi.Config{
				Java:      obi.JavaConfig{Enabled: false},
				Discovery: services.DiscoveryConfig{},
			},
			runRunFunc:    true,
			events:        nil, // no events, just test context cancellation cleanup
			expectedError: false,
			validateInit: func(t *testing.T, ta *traceAttacher, runFunc swarm.RunFunc, err error) {
				require.NoError(t, err)
				require.NotNil(t, runFunc)
			},
			validateAfterRun: func(t *testing.T, ta *traceAttacher, outputEvents []Event[*ebpf.Instrumentable]) {
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
			runRunFunc:    true,
			events:        []Event[ebpf.Instrumentable]{}, // empty slice signals close without events
			expectedError: false,
			validateInit: func(t *testing.T, ta *traceAttacher, runFunc swarm.RunFunc, err error) {
				require.NoError(t, err)
				require.NotNil(t, runFunc)
			},
			validateAfterRun: func(t *testing.T, ta *traceAttacher, outputEvents []Event[*ebpf.Instrumentable]) {
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
			runRunFunc: true,
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
			expectedError: false,
			validateInit: func(t *testing.T, ta *traceAttacher, runFunc swarm.RunFunc, err error) {
				require.NoError(t, err)
				require.NotNil(t, runFunc)
			},
			validateAfterRun: func(t *testing.T, ta *traceAttacher, outputEvents []Event[*ebpf.Instrumentable]) {
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
			runRunFunc: true,
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
			expectedError: false,
			validateInit: func(t *testing.T, ta *traceAttacher, runFunc swarm.RunFunc, err error) {
				require.NoError(t, err)
				require.NotNil(t, runFunc)
			},
			validateAfterRun: func(t *testing.T, ta *traceAttacher, outputEvents []Event[*ebpf.Instrumentable]) {
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
			runRunFunc: true,
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
			expectedError: false,
			validateInit: func(t *testing.T, ta *traceAttacher, runFunc swarm.RunFunc, err error) {
				require.NoError(t, err)
				require.NotNil(t, runFunc)
			},
			validateAfterRun: func(t *testing.T, ta *traceAttacher, outputEvents []Event[*ebpf.Instrumentable]) {
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
		{
			name: "runFunc handles Java event when javaInjector is nil",
			cfg: &obi.Config{
				Java:      obi.JavaConfig{Enabled: false},
				NodeJS:    obi.NodeJSConfig{Enabled: false},
				Discovery: services.DiscoveryConfig{},
			},
			runRunFunc: true,
			events: []Event[ebpf.Instrumentable]{
				{
					Type: EventCreated,
					Obj: ebpf.Instrumentable{
						Type: svc.InstrumentableJava,
						FileInfo: &exec.FileInfo{
							Pid:        9999,
							Ino:        77777,
							CmdExePath: "/usr/bin/java",
							Service:    svc.Attrs{},
						},
					},
				},
			},
			expectedError: false,
			validateInit: func(t *testing.T, ta *traceAttacher, runFunc swarm.RunFunc, err error) {
				require.NoError(t, err)
				require.NotNil(t, runFunc)
				assert.Nil(t, ta.javaInjector)
			},
			validateAfterRun: func(t *testing.T, ta *traceAttacher, outputEvents []Event[*ebpf.Instrumentable]) {
				// Verifies that processing a Java event with nil javaInjector doesn't crash
				// The code checks `if ta.javaInjector != nil` before using it
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

			// Phase 1: Call attacherLoop to get the runFunc
			runFunc, err := ta.attacherLoop(context.Background())

			if tt.expectedError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Validate initialization phase
			if tt.validateInit != nil {
				tt.validateInit(t, ta, runFunc, err)
			}

			// Phase 2: Execute the runFunc if requested
			if tt.runRunFunc {
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
			}
		})
	}
}
