// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package swarm

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

func TestSwarm_BuildWithError(t *testing.T) {
	inst := Instancer{}
	inst.Add(func(_ context.Context) (RunFunc, error) {
		return nil, errors.New("creation error")
	})
	_, err := inst.Instance(t.Context())
	require.Error(t, err)
}

func TestSwarm_StartTwice(t *testing.T) {
	inst := Instancer{}
	inst.Add(func(_ context.Context) (RunFunc, error) {
		return func(_ context.Context) {}, nil
	})
	s, err := inst.Instance(t.Context())
	require.NoError(t, err)
	s.Start(t.Context())
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic, got none")
		}
	}()
	s.Start(t.Context())
}

func TestSwarm_RunnerExecution(t *testing.T) {
	inst := Instancer{}
	runnerExecuted := atomic.Bool{}
	inst.Add(DirectInstance(func(_ context.Context) {
		runnerExecuted.Store(true)
	}))
	s, err := inst.Instance(t.Context())
	require.NoError(t, err)
	s.Start(t.Context())
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.True(ct, runnerExecuted.Load(), "runner was not executed")
	}, 5*time.Second, 100*time.Millisecond)
	assertDone(t, s)
}

func TestSwarm_CreatorFailure(t *testing.T) {
	inst := Instancer{}
	runnerStarted := atomic.Bool{}
	c1cancel := atomic.Bool{}
	c3exec := atomic.Bool{}
	inst.Add(func(ctx context.Context) (RunFunc, error) {
		go func() {
			<-ctx.Done()
			c1cancel.Store(true)
		}()
		return func(_ context.Context) {
			runnerStarted.Store(true)
		}, nil
	})
	inst.Add(func(_ context.Context) (RunFunc, error) {
		return nil, errors.New("creation error")
	})
	inst.Add(func(_ context.Context) (RunFunc, error) {
		c3exec.Store(true)
		return func(_ context.Context) {}, nil
	})

	// second creator fails, so the first one should be cancelled and the third one should not be instantiated
	_, err := inst.Instance(t.Context())
	require.Error(t, err)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.True(ct, c1cancel.Load(), "c1 was not cancelled")
	}, 5*time.Second, 100*time.Millisecond)
	assert.False(t, c3exec.Load(), "c3 was executed")
	assert.False(t, runnerStarted.Load(), "runner was started")
}

func TestSwarm_ContextPassed(t *testing.T) {
	startWg := sync.WaitGroup{}
	startWg.Add(3)
	doneWg := sync.WaitGroup{}
	doneWg.Add(3)
	inst := Instancer{}
	innerRunner := func(ctx context.Context) {
		startWg.Done()
		<-ctx.Done()
		doneWg.Done()
	}
	inst.Add(func(_ context.Context) (RunFunc, error) { return innerRunner, nil })
	inst.Add(func(_ context.Context) (RunFunc, error) { return innerRunner, nil })
	inst.Add(func(_ context.Context) (RunFunc, error) { return innerRunner, nil })
	ctx, cancel := context.WithCancel(t.Context())
	s, err := inst.Instance(t.Context())
	require.NoError(t, err)
	s.Start(ctx)
	require.EventuallyWithT(t, func(_ *assert.CollectT) {
		startWg.Wait()
	}, 5*time.Second, 100*time.Millisecond)
	cancel()
	require.EventuallyWithT(t, func(_ *assert.CollectT) {
		doneWg.Wait()
	}, 5*time.Second, 100*time.Millisecond)
	assertDone(t, s)
}

func TestSwarm_CancelInstancerCtx(t *testing.T) {
	swi := Instancer{}
	instancerCtxCancelled := make(chan struct{})
	stopRunFunc := make(chan struct{})
	swi.Add(func(ctx context.Context) (RunFunc, error) {
		go func() {
			<-ctx.Done()
			close(instancerCtxCancelled)
		}()
		return func(_ context.Context) {
			<-stopRunFunc
		}, nil
	})
	swi.Add(func(_ context.Context) (RunFunc, error) {
		return func(_ context.Context) {
			<-stopRunFunc
		}, nil
	})
	run, err := swi.Instance(t.Context())
	require.NoError(t, err)
	run.Start(t.Context())

	// while the RunFunc is not finished, the instancer context should not be cancelled
	select {
	case <-instancerCtxCancelled:
		t.Fatal("instancer context was cancelled while the RunFunc was running")
	default:
		// ok!!
	}

	// when the RunFunc is finished, the instancer context should be cancelled
	close(stopRunFunc)
	testutil.ReadChannel(t, instancerCtxCancelled, 5*time.Second)
}

func TestSwarm_CancelTimeout_Ok(t *testing.T) {
	runnerWaiter := func(ctx context.Context) { <-ctx.Done() }
	swi := Instancer{}
	swi.Add(DirectInstance(runnerWaiter))
	swi.Add(DirectInstance(runnerWaiter))
	swi.Add(DirectInstance(runnerWaiter))
	runner, err := swi.Instance(t.Context())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	runner.Start(ctx, WithCancelTimeout(5*time.Second))
	testutil.ChannelEmpty(t, runner.Done(), 10*time.Millisecond)
	cancel()
	assertDone(t, runner)
}

func TestSwarm_CancelTimeout_DontExit(t *testing.T) {
	runnerWaiter := func(ctx context.Context) { <-ctx.Done() }
	zombieRunner := func(_ context.Context) { <-make(chan struct{}) }

	swi := Instancer{}
	swi.Add(DirectInstance(runnerWaiter))
	swi.Add(DirectInstance(zombieRunner))
	swi.Add(DirectInstance(runnerWaiter), WithID("runnerWaiter"))
	swi.Add(DirectInstance(zombieRunner), WithID("zombieRunner"))

	runner, err := swi.Instance(t.Context())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	runner.Start(ctx, WithCancelTimeout(50*time.Millisecond))
	cancel()
	err = testutil.ReadChannel(t, runner.Done(), 5*time.Second)
	require.Error(t, err)
	cerr := CancelTimeoutError{}
	require.ErrorAs(t, err, &cerr)
	assert.Len(t, cerr.runningIDs, 2)
	assert.Contains(t, cerr.runningIDs, "#1")
	assert.Contains(t, cerr.runningIDs, "zombieRunner")
}

func TestSwarm_MutuallyExclusiveNodes(t *testing.T) {
	// in the test graph, two parallel channels share an input channel and an output channel,
	// but only one of the paths are enabled (halver or doubler, according to the "enabledNode" value)
	// This test just checks that the messages flow accordingly and no channel is blocked
	testGraph := func(ctx context.Context, enabledNode string) <-chan int {
		inst := Instancer{}
		inQueue := msg.NewQueue[int](msg.ChannelBufferLen(1), msg.Name("inQueue"))
		outQueue := msg.NewQueue[int](msg.ChannelBufferLen(1), msg.Name("outQueue"))
		inst.Add(func(_ context.Context) (RunFunc, error) {
			if enabledNode != "doubler" {
				return EmptyRunFunc()
			}
			in := inQueue.Subscribe()
			return func(ctx context.Context) {
				swarms.ForEachInput(ctx, in, slog.Debug, func(i int) {
					outQueue.SendCtx(ctx, i*2)
				})
			}, nil
		}, WithID("doubler"))
		inst.Add(func(_ context.Context) (RunFunc, error) {
			if enabledNode != "halver" {
				return EmptyRunFunc()
			}
			in := inQueue.Subscribe()
			return func(ctx context.Context) {
				swarms.ForEachInput(ctx, in, slog.Debug, func(i int) {
					outQueue.SendCtx(ctx, i/2)
				})
			}, nil
		}, WithID("halver"))
		outCh := outQueue.Subscribe(msg.SubscriberName("outputReader"))
		runner, err := inst.Instance(ctx)
		require.NoError(t, err)
		runner.Start(ctx)
		go func() {
			inQueue.SendCtx(ctx, 2)
			inQueue.SendCtx(ctx, 4)
			inQueue.SendCtx(ctx, 6)
		}()
		return outCh
	}

	t.Run("enable doubler", func(t *testing.T) {
		out := testGraph(t.Context(), "doubler")
		assert.Equal(t, 4, testutil.ReadChannel(t, out, 5*time.Second))
		assert.Equal(t, 8, testutil.ReadChannel(t, out, 5*time.Second))
		assert.Equal(t, 12, testutil.ReadChannel(t, out, 5*time.Second))
	})

	t.Run("enable halver", func(t *testing.T) {
		out := testGraph(t.Context(), "halver")
		assert.Equal(t, 1, testutil.ReadChannel(t, out, 5*time.Second))
		assert.Equal(t, 2, testutil.ReadChannel(t, out, 5*time.Second))
		assert.Equal(t, 3, testutil.ReadChannel(t, out, 5*time.Second))
	})
}

func assertDone(t *testing.T, s *Runner) {
	timeout := time.After(5 * time.Second)
	select {
	case err := <-s.Done():
		require.NoError(t, err)
	case <-timeout:
		t.Fatal("Runner instance did not properly finish")
	}
}
