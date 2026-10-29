// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/watcher"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

const testTimeout = 5 * time.Second

func TestWatcherExecutableReplacement(t *testing.T) {
	for _, ports := range [][]uint32{nil, {8080, 8081}} {
		for _, replacement := range []cacheKey{{Dev: 1, Ino: 3}, {Dev: 2, Ino: 2}} {
			t.Run(fmt.Sprintf("ports=%v/executable=%v", ports, replacement), func(t *testing.T) {
				acc := pollAccounter{
					cfg:               &obi.Config{},
					executableReady:   func(app.PID) (string, bool) { return "", true },
					bpfWatcherEnabled: true,
				}
				original := ProcessAttrs{pid: 123, executable: cacheKey{Dev: 1, Ino: 2}, openPorts: ports}
				require.Equal(t, []Event[ProcessAttrs]{{Type: EventCreated, Obj: original}}, acc.snapshot(map[app.PID]ProcessAttrs{123: original}, false))
				require.Empty(t, acc.snapshot(map[app.PID]ProcessAttrs{123: original}, false))
				unreadable := original
				unreadable.executable = cacheKey{}
				require.Empty(t, acc.snapshot(map[app.PID]ProcessAttrs{123: unreadable}, false))
				require.Equal(t, original.executable, acc.pids[123].executable)
				current := original
				current.executable = replacement
				require.Equal(t, []Event[ProcessAttrs]{
					{Type: EventDeleted, Obj: original},
					{Type: EventCreated, Obj: current},
				}, acc.snapshot(map[app.PID]ProcessAttrs{123: current}, false))
				fetchPorts, forceRescan := acc.pollRequirements()
				require.True(t, fetchPorts)
				require.False(t, forceRescan)
				require.Empty(t, acc.snapshot(map[app.PID]ProcessAttrs{123: current}, false))
				require.Equal(t, []Event[ProcessAttrs]{{Type: EventDeleted, Obj: current}}, acc.snapshot(nil, false))
			})
		}
	}
}

func TestWatcher_Poll(t *testing.T) {
	// mocking a fake listProcesses method
	p1_1 := ProcessAttrs{pid: 1, openPorts: []uint32{3030}}
	p1_2 := ProcessAttrs{pid: 1, openPorts: []uint32{3030, 3031}}
	p2 := ProcessAttrs{pid: 2, openPorts: []uint32{123}}
	p3 := ProcessAttrs{pid: 3, openPorts: []uint32{456}}
	p4 := ProcessAttrs{pid: 4, openPorts: []uint32{789}}
	p5 := ProcessAttrs{pid: 10}
	invocation := 0
	ctx, cancel := context.WithCancel(t.Context())
	// GIVEN a pollAccounter
	acc := pollAccounter{
		interval: time.Microsecond,
		cfg:      &obi.Config{},
		pidPorts: map[pidPort]ProcessAttrs{},
		listProcesses: func(bool) (map[app.PID]ProcessAttrs, error) {
			invocation++
			switch invocation {
			case 1:
				return map[app.PID]ProcessAttrs{p1_1.pid: p1_1, p2.pid: p2, p3.pid: p3}, nil
			case 2:
				// p1_2 simulates that a new connection has been created for an existing process
				return map[app.PID]ProcessAttrs{p1_2.pid: p1_2, p3.pid: p3, p4.pid: p4}, nil
			case 3:
				return map[app.PID]ProcessAttrs{p2.pid: p2, p3.pid: p3, p4.pid: p4}, nil
			default:
				// new processes with no connections (p5) should be also reported
				return map[app.PID]ProcessAttrs{p5.pid: p5, p2.pid: p2, p3.pid: p3, p4.pid: p4}, nil
			}
		},
		executableReady: func(app.PID) (string, bool) {
			return "", true
		},
		loadBPFWatcher: func(context.Context, *ebpfcommon.EBPFEventContext, *obi.Config, chan<- watcher.Event) error {
			return nil
		},
		loadBPFLogger: func(context.Context, *ebpfcommon.EBPFEventContext, *obi.Config) error {
			return nil
		},
		output: msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(1)),
	}
	accounterOutput := acc.output.Subscribe()
	accounterExited := make(chan struct{})
	go func() {
		acc.run(ctx)
		close(accounterExited)
	}()

	// WHEN it polls the process for the first time
	// THEN it returns the creation of all the events
	out := testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []Event[ProcessAttrs]{
		{Type: EventCreated, Obj: p1_1},
		{Type: EventCreated, Obj: p2},
		{Type: EventCreated, Obj: p3},
	}, sort(out))

	// WHEN it polls the process for the successive times
	// THEN it returns the creation of the new processes/connections
	// AND the deletion of the old processes
	out = testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []Event[ProcessAttrs]{
		{Type: EventCreated, Obj: p1_2},
		{Type: EventDeleted, Obj: p2},
		{Type: EventCreated, Obj: p4},
	}, sort(out))
	out = testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []Event[ProcessAttrs]{
		{Type: EventDeleted, Obj: p1_2},
		{Type: EventCreated, Obj: p2},
	}, sort(out))

	// WHEN a new process with no connections is created
	// THEN it should be also reported
	// (use case: we want to later match by executable path a client process with short-lived connections)
	out = testutil.ReadChannel(t, accounterOutput, testTimeout)
	assert.Equal(t, []Event[ProcessAttrs]{
		{Type: EventCreated, Obj: p5},
	}, sort(out))

	// WHEN no changes in the process, it doesn't send anything
	select {
	case procs := <-accounterOutput:
		assert.Failf(t, "no output expected", "got %v", procs)
	default:
		// ok!
	}

	// WHEN its context is cancelled
	cancel()
	// THEN the main loop exits
	select {
	case <-accounterExited:
	// ok!
	case <-time.After(testTimeout):
		assert.Fail(t, "expected to exit the main loop")
	}
}

func TestWatcherRescanDuringPoll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		original := processInfo
		t.Cleanup(func() { processInfo = original })
		processInfo = func(p ProcessAttrs) (*services.ProcessInfo, error) {
			return &services.ProcessInfo{Pid: p.pid, ExePath: "/srv/app", OpenPorts: p.openPorts}, nil
		}
		cfg := criteriaConfig(t, "    - open_ports: 8080\n")
		ctx, cancel := context.WithCancel(t.Context())
		requests := make(chan bool)
		type pollResult struct {
			processes map[app.PID]ProcessAttrs
			err       error
		}
		results := make(chan pollResult)
		targetsChanged := make(chan struct{})
		acc := pollAccounter{
			cfg: cfg, interval: time.Second,
			pids: map[app.PID]ProcessAttrs{}, pidPorts: map[pidPort]ProcessAttrs{},
			bpfWatcherEnabled: true, fetchPorts: true,
			criteriaUpdates: services.NewCriteriaUpdates(FindingCriteria(cfg), nil),
			rescan:          ProcessWatcherRescan{TargetsChanged: targetsChanged},
			listProcesses: func(fetchPorts bool) (map[app.PID]ProcessAttrs, error) {
				select {
				case requests <- fetchPorts:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				select {
				case result := <-results:
					return result.processes, result.err
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			},
			executableReady: func(app.PID) (string, bool) { return "/srv/app", true },
			loadBPFWatcher: func(context.Context, *ebpfcommon.EBPFEventContext, *obi.Config, chan<- watcher.Event) error {
				return nil
			},
			output: msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(10)),
		}
		events := acc.output.Subscribe()
		done := make(chan struct{})
		go func() { defer close(done); acc.run(ctx) }()
		t.Cleanup(func() {
			cancel()
			testutil.ReadChannel(t, done, testTimeout)
		})
		matcher := &Matcher{
			Log: slog.Default(), Criteria: FindingCriteria(cfg),
			ProcessHistory: map[app.PID]ProcessMatch{}, observed: map[app.PID]observedProcess{},
		}
		withPorts := map[app.PID]ProcessAttrs{10: {pid: 10, openPorts: []uint32{8080}}}
		require.True(t, testutil.ReadChannel(t, requests, testTimeout))
		results <- pollResult{processes: withPorts}
		require.Len(t, matcher.filter(testutil.ReadChannel(t, events, testTimeout)), 1)

		// The reload arrives after port fetching was disabled for the active poll.
		require.False(t, testutil.ReadChannel(t, requests, testTimeout))
		targetsChanged <- struct{}{}
		synctest.Wait()
		results <- pollResult{processes: map[app.PID]ProcessAttrs{10: {pid: 10}}}
		synctest.Wait()
		select {
		case batch := <-events:
			require.Empty(t, matcher.filter(batch), "the portless poll must not uninstrument a selected process")
		default:
		}
		require.Contains(t, matcher.ProcessHistory, app.PID(10))

		require.True(t, testutil.ReadChannel(t, requests, testTimeout))
		// A further request during this rescan belongs to the following poll.
		targetsChanged <- struct{}{}
		synctest.Wait()
		results <- pollResult{processes: withPorts}
		rescanned := testutil.ReadChannel(t, events, testTimeout)
		require.Len(t, rescanned, 1)
		require.Equal(t, []uint32{8080}, rescanned[0].Obj.openPorts)
		require.Empty(t, matcher.filter(rescanned))

		require.True(t, testutil.ReadChannel(t, requests, testTimeout))
		results <- pollResult{err: errors.New("temporary process listing failure")}
		// A failed enumeration must not consume the pending rescan.
		require.True(t, testutil.ReadChannel(t, requests, testTimeout))
		results <- pollResult{processes: withPorts}
		rescanned = testutil.ReadChannel(t, events, testTimeout)
		require.Len(t, rescanned, 1)
		require.Equal(t, []uint32{8080}, rescanned[0].Obj.openPorts)
		require.Empty(t, matcher.filter(rescanned))
		require.False(t, testutil.ReadChannel(t, requests, testTimeout))
	})
}

func TestProcessNotReady(t *testing.T) {
	// mocking a fake listProcesses method
	p1 := ProcessAttrs{pid: 1, openPorts: []uint32{3030, 3031}}
	p2 := ProcessAttrs{pid: 2, openPorts: []uint32{123}}
	p3 := ProcessAttrs{pid: 3, openPorts: []uint32{456}}
	p4 := ProcessAttrs{pid: 4, openPorts: []uint32{789}}
	p5 := ProcessAttrs{pid: 10}

	acc := pollAccounter{
		interval: time.Microsecond,
		cfg:      &obi.Config{},
		pidPorts: map[pidPort]ProcessAttrs{},
		listProcesses: func(bool) (map[app.PID]ProcessAttrs, error) {
			return map[app.PID]ProcessAttrs{p1.pid: p1, p5.pid: p5, p2.pid: p2, p3.pid: p3, p4.pid: p4}, nil
		},
		executableReady: func(pid app.PID) (string, bool) {
			return "", pid >= 3
		},
		loadBPFWatcher: func(context.Context, *ebpfcommon.EBPFEventContext, *obi.Config, chan<- watcher.Event) error {
			return nil
		},
		loadBPFLogger: func(context.Context, *ebpfcommon.EBPFEventContext, *obi.Config) error {
			return nil
		},
	}

	procs, err := acc.listProcesses(true)
	require.NoError(t, err)
	assert.Len(t, procs, 5)
	events := acc.snapshot(procs, false)
	assert.Len(t, events, 3)       // 2 are not ready
	assert.Len(t, acc.pids, 3)     // this should equal the first invocation of snapshot
	assert.Len(t, acc.pidPorts, 2) // only 2 ports opened, p5 has no ports

	eventsNext := acc.snapshot(procs, false)
	assert.Empty(t, eventsNext) // 0 new events
	assert.Len(t, acc.pids, 3)  // this should equal the first invocation of snapshot, no changes

	acc.executableReady = func(pid app.PID) (string, bool) { // we change so that pid=1 becomes ready
		return "", pid != 2
	}

	eventsNextNext := acc.snapshot(procs, false)
	assert.Len(t, eventsNextNext, 1) // 1 net new event
	assert.Len(t, acc.pids, 4)       // this should increase by one since we have one more app.PID we are caching now
	assert.Len(t, acc.pidPorts, 4)   // this is now 4 because pid=1 has 2 port mappings
}

func TestPortsFetchRequired(t *testing.T) {
	synctest.Test(t, testPortsFetchRequired)
}

func testPortsFetchRequired(t *testing.T) {
	userConfig := bytes.NewBufferString("channel_buffer_len: 33")
	t.Setenv("OTEL_EBPF_OPEN_PORT", "8080-8089")

	cfg, err := obi.LoadConfig(userConfig)
	require.NoError(t, err)

	channelReturner := make(chan chan<- watcher.Event)

	ctx, cancel := context.WithCancel(t.Context())

	acc := pollAccounter{
		cfg:      cfg,
		interval: time.Hour, // don't let the inner loop mess with our test
		pidPorts: map[pidPort]ProcessAttrs{},
		listProcesses: func(bool) (map[app.PID]ProcessAttrs, error) {
			return nil, nil
		},
		executableReady: func(_ app.PID) (string, bool) {
			return "", true
		},
		loadBPFWatcher: func(_ context.Context, _ *ebpfcommon.EBPFEventContext, _ *obi.Config, events chan<- watcher.Event) error {
			channelReturner <- events
			return nil
		},
		loadBPFLogger: func(context.Context, *ebpfcommon.EBPFEventContext, *obi.Config) error {
			return nil
		},
		stateMux:          sync.Mutex{},
		bpfWatcherEnabled: false,
		fetchPorts:        true,
		findingCriteria:   FindingCriteria(cfg),
		output:            msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(1)),
	}

	accounterExited := make(chan struct{})
	go func() {
		acc.run(ctx)
		close(accounterExited)
	}()

	eventsChan := testutil.ReadChannel(t, channelReturner, testTimeout)
	portFetchRequired := func() bool {
		fetchPorts, _ := acc.pollRequirements()
		return fetchPorts
	}

	assert.True(t, portFetchRequired()) // initial state means poll all ports until we are ready to look for binds in bpf
	eventsChan <- watcher.Event{Type: watcher.NewPort}
	assert.True(t, portFetchRequired())
	eventsChan <- watcher.Event{Type: watcher.Ready}
	assert.True(t, portFetchRequired()) // we must see it true one more time
	assert.EventuallyWithTf(t, func(c *assert.CollectT) {
		assert.False(c, portFetchRequired()) // eventually we'll see this being false
	}, 5*time.Second, 100*time.Millisecond, "eventsChan was never set")
	assert.False(t, portFetchRequired()) // another false after that

	// we send new port watcher event which matches the port range
	eventsChan <- watcher.Event{Type: watcher.NewPort, Payload: 8080}
	assert.EventuallyWithTf(t, func(c *assert.CollectT) {
		assert.True(c, portFetchRequired()) // eventually we'll see this being true
	}, 5*time.Second, 100*time.Millisecond, "eventsChan was never set")
	assert.False(t, portFetchRequired()) // once we see it true, next time it's false

	// we send port that's not in our port range
	eventsChan <- watcher.Event{Type: watcher.NewPort, Payload: 8090}
	// 5 seconds should be enough to have the channel send something
	for range 5 {
		assert.False(t, portFetchRequired()) // once we see it true, next time it's false
		time.Sleep(1 * time.Second)
	}

	// WHEN its context is cancelled
	cancel()
	// THEN the main loop exits
	select {
	case <-accounterExited:
	// ok!
	case <-time.After(testTimeout):
		assert.Fail(t, "expected to exit the main loop")
	}
}

// auxiliary function just to allow comparing slices whose order is not deterministic
func sort(events []Event[ProcessAttrs]) []Event[ProcessAttrs] {
	slices.SortFunc(events, func(a, b Event[ProcessAttrs]) int {
		return int(a.Obj.pid) - int(b.Obj.pid)
	})
	return events
}

func TestMinProcessAge(t *testing.T) {
	count := 1
	processAgeFunc = func(pid app.PID) time.Duration {
		if pid == 3 {
			return time.Duration(0)
		}
		count++
		return time.Duration(count * 1000000 * 1000)
	}

	processPidsFunc = func() ([]int32, error) {
		return []int32{1, 2, 3}, nil
	}

	userConfig := bytes.NewBufferString("channel_buffer_len: 33")
	t.Setenv("OTEL_EBPF_OPEN_PORT", "8080-8089")

	cfg, err := obi.LoadConfig(userConfig)
	require.NoError(t, err)

	channelReturner := make(chan chan<- watcher.Event)

	acc := pollAccounter{
		cfg:      cfg,
		interval: time.Hour, // don't let the inner loop mess with our test
		pidPorts: map[pidPort]ProcessAttrs{},
		listProcesses: func(bool) (map[app.PID]ProcessAttrs, error) {
			return nil, nil
		},
		executableReady: func(_ app.PID) (string, bool) {
			return "", true
		},
		loadBPFWatcher: func(_ context.Context, _ *ebpfcommon.EBPFEventContext, _ *obi.Config, events chan<- watcher.Event) error {
			channelReturner <- events
			return nil
		},
		loadBPFLogger: func(context.Context, *ebpfcommon.EBPFEventContext, *obi.Config) error {
			return nil
		},
		stateMux:          sync.Mutex{},
		bpfWatcherEnabled: false,
		fetchPorts:        true,
		findingCriteria:   FindingCriteria(cfg),
		output:            msg.NewQueue[[]Event[ProcessAttrs]](msg.ChannelBufferLen(1)),
	}

	procs, err := fetchProcessPorts(false)
	require.NoError(t, err)
	process, ok := procs[app.PID(1)]

	assert.True(t, ok)
	assert.True(t, acc.processTooNew(process))

	// Pid 3 has 0 duration meaning we had to scan it without checking duration
	// it's never too new
	process, ok = procs[app.PID(3)]

	assert.True(t, ok)
	assert.False(t, acc.processTooNew(process))

	for range 10 {
		procs, err = fetchProcessPorts(false)
		require.NoError(t, err)
	}

	process, ok = procs[app.PID(1)]

	assert.True(t, ok)
	assert.False(t, acc.processTooNew(process))
}

// TestForgetPIDs_ReemitsExistingProcess verifies that when a PID was already seen by the watcher,
// forgetting it causes the next poll to emit EventCreated again.
// This supports the use case of adding an existing process to the dynamic selector.
func TestForgetPIDs_ReemitsExistingProcess(t *testing.T) {
	p1 := ProcessAttrs{pid: 1, openPorts: []uint32{3030}}
	p2 := ProcessAttrs{pid: 2, openPorts: []uint32{123}}
	acc := pollAccounter{
		interval: time.Hour,
		cfg:      &obi.Config{},
		pids:     map[app.PID]ProcessAttrs{},
		pidPorts: map[pidPort]ProcessAttrs{},
		listProcesses: func(bool) (map[app.PID]ProcessAttrs, error) {
			return map[app.PID]ProcessAttrs{p1.pid: p1, p2.pid: p2}, nil
		},
		executableReady: func(app.PID) (string, bool) {
			return "", true
		},
		loadBPFWatcher: func(context.Context, *ebpfcommon.EBPFEventContext, *obi.Config, chan<- watcher.Event) error {
			return nil
		},
		loadBPFLogger: func(context.Context, *ebpfcommon.EBPFEventContext, *obi.Config) error {
			return nil
		},
	}
	procs, err := acc.listProcesses(false)
	require.NoError(t, err)
	events := acc.snapshot(procs, false)
	require.Len(t, events, 2)
	assert.Equal(t, EventCreated, sort(events)[0].Type)
	assert.Equal(t, EventCreated, sort(events)[1].Type)
	// Second snapshot: no new events (already seen)
	events2 := acc.snapshot(procs, false)
	assert.Empty(t, events2)
	// Forget p1 only
	acc.forgetPIDs([]app.PID{1})
	// Next snapshot: p1 should appear as created again
	events3 := acc.snapshot(procs, false)
	require.Len(t, events3, 1)
	assert.Equal(t, EventCreated, events3[0].Type)
	assert.Equal(t, app.PID(1), events3[0].Obj.pid)
	// p2 still not re-emitted
	events4 := acc.snapshot(procs, false)
	assert.Empty(t, events4)
}
