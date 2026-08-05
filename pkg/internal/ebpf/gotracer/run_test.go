// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestRunOwnsGoTracerResources(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, *Tracer)
	}{
		{
			name: "ring buffer reader setup fails",
			run: func(t *testing.T, tracer *Tracer) {
				tracer.bpfObjects.Events = &ebpf.Map{}
				tracer.Run(t.Context(), ebpfcommon.NewEBPFEventContext(), nil)
			},
		},
		{
			name: "shared forwarder already owned",
			run: func(t *testing.T, tracer *Tracer) {
				eventContext := ebpfcommon.NewEBPFEventContext()
				ebpfcommon.SharedRingbuf[request.Span](
					eventContext,
					tracer.cfg,
					nil,
					nil,
					nil,
					tracer.log,
					nil,
				)
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				tracer.Run(ctx, eventContext, nil)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := obi.DefaultConfig.EBPF
			tracer := &Tracer{
				log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
				cfg:        &cfg,
				pidsFilter: &recordingServiceFilter{},
			}
			closer := &fakeGoTracerCloser{}
			tracer.resources = newGoTracerResources(tracer, closer)

			test.run(t, tracer)

			assert.Equal(t, 1, closer.closed)
		})
	}
}

func TestRunReportsUnsafeResourceTeardown(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, _, sampler := newGoAutoSDKLifecycleTestTracer(t)
	tracer.activateGoAutoSDKFlag(key)
	sampler.autoReady = true
	state := tracer.goAutoSDKFlagStates[process]
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	counterKey := goAutoSDKInflightKeyForState(state)
	counter := inflight.values[counterKey]
	setGoAutoSDKInflightActiveCalls(&counter, 1)
	inflight.values[counterKey] = counter
	tracer.goAutoSDKOuterCalls = &fakeGoAutoSDKOuterCallMap{
		values: map[goAddrKey]goAutoSDKOuterCallValue{
			{PID: key.PID, Addr: 0x88}: {
				StartTime:  tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
				Generation: key.Generation,
				FlagPtr:    flagPtr,
				Epoch:      flagMap.values[key].Epoch,
				State:      goAutoSDKOuterCallConsumedActive,
			},
		},
	}
	tracer.goAutoSDKDrainPause = func() {}
	cfg := obi.DefaultConfig.EBPF
	tracer.cfg = &cfg
	tracer.pidsFilter = &recordingServiceFilter{}
	tracer.bpfObjects.Events = &ebpf.Map{}
	closer := &fakeGoTracerCloser{}
	tracer.resources = newGoTracerResources(tracer, closer)

	runCtx, cancel := context.WithCancel(t.Context())
	cancel()
	runDone := make(chan struct{})
	go func() {
		tracer.Run(runCtx, ebpfcommon.NewEBPFEventContext(), nil)
		close(runDone)
	}()

	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("Go tracer Run did not return after its bounded unsafe shutdown")
	}

	require.False(t, tracer.ResourceTeardownReady())
	assert.Zero(t, closer.closed)
}

func TestRunWaitsThroughShutdownTimeoutForAutoSDKRestoration(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, _ := newGoAutoSDKLifecycleTestTracer(t)
	tracer.activateGoAutoSDKFlag(key)
	for range goAutoSDKDrainAttempts + 2 {
		access.writeResults = append(
			access.writeResults,
			fakeGoAutoSDKWriteResult{err: errors.New("restore failed")},
		)
	}
	tracer.goAutoSDKDrainPause = nil
	tracer.shutdownTimeout = 300 * time.Millisecond
	cfg := obi.DefaultConfig.EBPF
	tracer.cfg = &cfg
	tracer.pidsFilter = &recordingServiceFilter{}
	tracer.bpfObjects.Events = &ebpf.Map{}
	closer := &fakeGoTracerCloser{}
	tracer.resources = newGoTracerResources(tracer, closer)

	runCtx, cancel := context.WithCancel(t.Context())
	cancel()
	started := time.Now()
	tracer.Run(runCtx, ebpfcommon.NewEBPFEventContext(), nil)
	elapsed := time.Since(started)

	assert.GreaterOrEqual(
		t,
		elapsed,
		goAutoSDKDrainAttempts*goAutoSDKDrainInterval,
	)
	assert.Zero(t, access.memory[flagPtr])
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, flagMap.values, key)
	assert.Equal(t, 1, closer.closed)
	assert.True(t, tracer.ResourceTeardownReady())
}

func TestRunWaitsThroughShutdownTimeoutForOuterAutoSDKCall(t *testing.T) {
	tracer, process, key, flagPtr, flagMap, access, sampler := newGoAutoSDKLifecycleTestTracer(t)
	tracer.activateGoAutoSDKFlag(key)
	sampler.autoReady = true
	state := tracer.goAutoSDKFlagStates[process]
	inflight := tracer.goAutoSDKInflight.(*fakeGoAutoSDKInflightMap)
	counterKey := goAutoSDKInflightKeyForState(state)
	counter := inflight.values[counterKey]
	setGoAutoSDKInflightActiveCalls(&counter, 1)
	inflight.values[counterKey] = counter
	outerKey := goAddrKey{PID: key.PID, Addr: 0x88}
	outerCalls := &fakeGoAutoSDKOuterCallMap{
		values: map[goAddrKey]goAutoSDKOuterCallValue{
			outerKey: {
				StartTime:  tracer.goProcessGenerationByPID[process].fileInfo.StartTime(),
				Generation: key.Generation,
				FlagPtr:    flagPtr,
				Epoch:      flagMap.values[key].Epoch,
				State:      goAutoSDKOuterCallConsumedActive,
			},
		},
	}
	tracer.goAutoSDKOuterCalls = outerCalls
	pauseCount := 0
	tracer.goAutoSDKDrainPause = func() {
		time.Sleep(goAutoSDKDrainInterval)
		pauseCount++
		if pauseCount == goAutoSDKDrainAttempts+2 {
			counter := inflight.values[counterKey]
			setGoAutoSDKInflightActiveCalls(&counter, 0)
			inflight.values[counterKey] = counter
			clear(outerCalls.values)
		}
	}
	tracer.shutdownTimeout = 300 * time.Millisecond
	cfg := obi.DefaultConfig.EBPF
	tracer.cfg = &cfg
	tracer.pidsFilter = &recordingServiceFilter{}
	tracer.bpfObjects.Events = &ebpf.Map{}
	closer := &fakeGoTracerCloser{}
	tracer.resources = newGoTracerResources(tracer, closer)

	runCtx, cancel := context.WithCancel(t.Context())
	cancel()
	started := time.Now()
	tracer.Run(runCtx, ebpfcommon.NewEBPFEventContext(), nil)
	elapsed := time.Since(started)

	assert.GreaterOrEqual(
		t,
		elapsed,
		goAutoSDKDrainAttempts*goAutoSDKDrainInterval,
	)
	assert.Zero(t, access.memory[flagPtr])
	assert.NotContains(t, outerCalls.values, outerKey)
	assert.NotContains(t, tracer.goAutoSDKFlagStates, process)
	assert.NotContains(t, flagMap.values, key)
	assert.False(t, sampler.autoReady)
	assert.Equal(t, 2, sampler.quiesceCalls)
	assert.Equal(t, 1, closer.closed)
	assert.True(t, tracer.ResourceTeardownReady())
}
