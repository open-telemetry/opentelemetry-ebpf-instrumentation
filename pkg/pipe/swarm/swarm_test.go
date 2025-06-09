package swarm

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/testutil"
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
	test.Eventually(t, 5*time.Second, func(t require.TestingT) {
		assert.True(t, runnerExecuted.Load(), "runner was not executed")
	})
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
	test.Eventually(t, 5*time.Second, func(t require.TestingT) {
		assert.True(t, c1cancel.Load(), "c1 was not cancelled")
	})
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
	test.Eventually(t, 5*time.Second, func(_ require.TestingT) {
		startWg.Wait()
	})
	cancel()
	test.Eventually(t, 5*time.Second, func(_ require.TestingT) {
		doneWg.Wait()
	})
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

func assertDone(t *testing.T, s *Runner) {
	timeout := time.After(5 * time.Second)
	select {
	case err := <-s.Done():
		require.NoError(t, err)
	case <-timeout:
		t.Fatal("Runner instance did not properly finish")
	}
}
