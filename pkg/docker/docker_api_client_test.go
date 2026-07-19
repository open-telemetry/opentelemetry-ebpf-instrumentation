// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"errors"
	"io"
	"strconv"
	"sync"
	"testing"
	"time"

	containerTypes "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/helpers/container"
)

type mockDockerClient struct {
	inspectResult  client.ContainerInspectResult
	inspectErr     error
	eventsChan     chan events.Message
	errsChan       chan error
	inspectCallsMu sync.Mutex
	inspectCalls   int
	eventsOptsMu   sync.Mutex
	eventsOpts     []client.EventsListOptions
}

func (m *mockDockerClient) ContainerInspect(_ context.Context, _ string, _ client.ContainerInspectOptions) (client.ContainerInspectResult, error) {
	m.inspectCallsMu.Lock()
	m.inspectCalls++
	m.inspectCallsMu.Unlock()
	return m.inspectResult, m.inspectErr
}

func (m *mockDockerClient) Events(_ context.Context, opts client.EventsListOptions) client.EventsResult {
	m.eventsOptsMu.Lock()
	m.eventsOpts = append(m.eventsOpts, opts)
	m.eventsOptsMu.Unlock()
	return client.EventsResult{
		Messages: m.eventsChan,
		Err:      m.errsChan,
	}
}

func (m *mockDockerClient) eventsCallCount() int {
	m.eventsOptsMu.Lock()
	defer m.eventsOptsMu.Unlock()
	return len(m.eventsOpts)
}

func (m *mockDockerClient) eventsCallOpts(i int) client.EventsListOptions {
	m.eventsOptsMu.Lock()
	defer m.eventsOptsMu.Unlock()
	return m.eventsOpts[i]
}

// requireConsistency verifies the bidirectional invariants between byPID and byContainerID:
//   - every (pid → meta) in byPID: byContainerID[meta.FullID].pids contains that pid
//   - every (fullID → entry) in byContainerID: every pid in entry.pids has a byPID entry pointing back to fullID
func requireConsistency(t *testing.T, s *ContainerStore) {
	t.Helper()
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()

	for pid, meta := range s.byPID {
		entry, ok := s.byContainerID[meta.FullID]
		require.Truef(t, ok,
			"byPID[%d] references fullID %q but byContainerID has no entry for it", pid, meta.FullID)
		found := false
		for _, p := range entry.pids {
			if p == pid {
				found = true
				break
			}
		}
		require.Truef(t, found,
			"byPID[%d] references fullID %q but that pid is not listed in byContainerID[%q].pids", pid, meta.FullID, meta.FullID)
	}

	for fullID, entry := range s.byContainerID {
		for _, pid := range entry.pids {
			meta, ok := s.byPID[pid]
			require.Truef(t, ok,
				"byContainerID[%q] lists pid %d but byPID has no entry for it", fullID, pid)
			require.Equalf(t, fullID, meta.FullID,
				"byContainerID[%q] lists pid %d but byPID[%d].FullID is %q", fullID, pid, pid, meta.FullID)
		}
	}
}

func eofMock() *mockDockerClient {
	errsChan := make(chan error, 1)
	errsChan <- io.EOF
	return &mockDockerClient{
		eventsChan: make(chan events.Message),
		errsChan:   errsChan,
	}
}

func TestIsEnabled(t *testing.T) {
	t.Run("nil_store_returns_false", func(t *testing.T) {
		var s *ContainerStore
		assert.False(t, s.IsEnabled(context.Background()))
	})

	t.Run("returns_true_when_docker_client_set", func(t *testing.T) {
		s := NewStore()
		s.docker = eofMock()
		assert.True(t, s.IsEnabled(context.Background()))
	})
}

func TestContainerInfo(t *testing.T) {
	const fullID = "abc123def456789abc123def456789abc123def456789abc123def456789abcdef"

	t.Run("cache_hit_returns_cached_meta", func(t *testing.T) {
		s := NewStore()
		pid := app.PID(42)
		expected := ContainerMeta{ID: fullID[:abbreviationLength], FullID: fullID, Name: "cached"}
		s.cacheMu.Lock()
		s.byPID[pid] = expected
		s.cacheMu.Unlock()

		got, ok := s.ContainerInfo(context.Background(), pid)
		require.True(t, ok)
		assert.Equal(t, expected, got)
	})

	t.Run("osinfo_error_returns_false", func(t *testing.T) {
		s := NewStore()
		s.docker = eofMock()

		orig := osInfoForPID
		osInfoForPID = func(_ app.PID) (container.Info, error) {
			return container.Info{}, errors.New("no cgroup")
		}
		defer func() { osInfoForPID = orig }()

		_, ok := s.ContainerInfo(context.Background(), app.PID(1))
		assert.False(t, ok)
	})

	t.Run("inspect_error_returns_false", func(t *testing.T) {
		s := NewStore()
		s.docker = &mockDockerClient{inspectErr: errors.New("not found")}

		orig := osInfoForPID
		osInfoForPID = func(_ app.PID) (container.Info, error) {
			return container.Info{ContainerID: fullID}, nil
		}
		defer func() { osInfoForPID = orig }()

		_, ok := s.ContainerInfo(context.Background(), app.PID(1))
		assert.False(t, ok)
	})

	t.Run("success_with_compose_service", func(t *testing.T) {
		s := NewStore()
		s.docker = &mockDockerClient{
			inspectResult: client.ContainerInspectResult{
				Container: containerTypes.InspectResponse{
					ID:   fullID,
					Name: "/my-container",
					Config: &containerTypes.Config{
						Labels: map[string]string{composeServiceLabelKey: "web"},
					},
				},
			},
		}

		orig := osInfoForPID
		osInfoForPID = func(_ app.PID) (container.Info, error) {
			return container.Info{ContainerID: fullID}, nil
		}
		defer func() { osInfoForPID = orig }()

		pid := app.PID(10)
		got, ok := s.ContainerInfo(context.Background(), pid)
		require.True(t, ok)
		assert.Equal(t, fullID[:abbreviationLength], got.ID)
		assert.Equal(t, ContainerID(fullID), got.FullID)
		assert.Equal(t, "my-container", got.Name)
		assert.Equal(t, "web", got.ComposeService)
		requireConsistency(t, s)

		// Verify cache was populated
		s.cacheMu.RLock()
		cached, inCache := s.byPID[pid]
		s.cacheMu.RUnlock()
		assert.True(t, inCache)
		assert.Equal(t, got, cached)
	})

	t.Run("second_pid_same_container_skips_inspect", func(t *testing.T) {
		mock := &mockDockerClient{
			inspectResult: client.ContainerInspectResult{
				Container: containerTypes.InspectResponse{
					ID:   fullID,
					Name: "/multi-proc",
					Config: &containerTypes.Config{
						Labels: map[string]string{},
					},
				},
			},
		}
		s := NewStore()
		s.docker = mock

		orig := osInfoForPID
		osInfoForPID = func(_ app.PID) (container.Info, error) {
			return container.Info{ContainerID: fullID}, nil
		}
		defer func() { osInfoForPID = orig }()

		got1, ok1 := s.ContainerInfo(context.Background(), app.PID(10))
		require.True(t, ok1)

		got2, ok2 := s.ContainerInfo(context.Background(), app.PID(11))
		require.True(t, ok2)

		assert.Equal(t, got1, got2)
		mock.inspectCallsMu.Lock()
		calls := mock.inspectCalls
		mock.inspectCallsMu.Unlock()
		assert.Equal(t, 1, calls, "ContainerInspect should be called only once for two PIDs in the same container")
		requireConsistency(t, s)
	})

	t.Run("success_without_config", func(t *testing.T) {
		s := NewStore()
		s.docker = &mockDockerClient{
			inspectResult: client.ContainerInspectResult{
				Container: containerTypes.InspectResponse{
					ID:   fullID,
					Name: "plain",
				},
			},
		}

		orig := osInfoForPID
		osInfoForPID = func(_ app.PID) (container.Info, error) {
			return container.Info{ContainerID: fullID}, nil
		}
		defer func() { osInfoForPID = orig }()

		got, ok := s.ContainerInfo(context.Background(), app.PID(20))
		require.True(t, ok)
		assert.Equal(t, fullID[:abbreviationLength], got.ID)
		assert.Equal(t, "plain", got.Name)
		assert.Empty(t, got.ComposeService)
	})
}

func TestDecorateService(t *testing.T) {
	t.Run("autoname_with_compose_service_sets_name", func(t *testing.T) {
		ci := &ContainerMeta{Name: "my-container", ComposeService: "web"}
		s := &svc.Attrs{}
		s.SetAutoName()

		ci.DecorateService(s)

		assert.Equal(t, "web", s.UID.Name)
		assert.Equal(t, "web.my-container", s.UID.Instance)
	})

	t.Run("autoname_without_compose_service_uses_container_name", func(t *testing.T) {
		ci := &ContainerMeta{Name: "my-container"}
		s := &svc.Attrs{}
		s.SetAutoName()

		ci.DecorateService(s)

		assert.Equal(t, "my-container", s.UID.Name)
		assert.Equal(t, "my-container", s.UID.Instance)
	})

	t.Run("with_namespace_builds_instance_from_namespace", func(t *testing.T) {
		ci := &ContainerMeta{Name: "my-container", ComposeService: "web"}
		s := &svc.Attrs{UID: svc.UID{Namespace: "prod", Name: "svc"}}

		ci.DecorateService(s)

		assert.Equal(t, "prod.svc.my-container", s.UID.Instance)
	})

	t.Run("metadata_is_populated", func(t *testing.T) {
		ci := &ContainerMeta{Name: "my-container", ID: "abc123def456"}
		s := &svc.Attrs{}

		ci.DecorateService(s)

		assert.Equal(t, "my-container", s.Metadata[attr.ContainerName])
		assert.Equal(t, "abc123def456", s.Metadata[attr.ContainerID])
	})
}

func TestContainerMetadata(t *testing.T) {
	ci := &ContainerMeta{Name: "svc", ID: "short123"}

	t.Run("nil_dst_creates_new_map", func(t *testing.T) {
		out := ContainerMetadata(nil, ci, func(n attr.Name) attr.Name { return n })
		assert.Equal(t, "svc", out[attr.ContainerName])
		assert.Equal(t, "short123", out[attr.ContainerID])
	})

	t.Run("existing_dst_is_cloned_not_mutated", func(t *testing.T) {
		original := map[attr.Name]string{"existing": "value"}
		out := ContainerMetadata(original, ci, func(n attr.Name) attr.Name { return n })
		assert.Equal(t, "svc", out[attr.ContainerName])
		assert.Equal(t, "value", out["existing"])
		_, mutated := original[attr.ContainerName]
		assert.False(t, mutated, "original map should not be mutated")
	})
}

func TestStart(t *testing.T) {
	t.Run("starts_watcher_goroutine_and_processes_events", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		const fullID = "abc123def456789abc123def456789abc123def456789abc123def456789abcdef"
		pid := app.PID(99)

		// eventsChan is unbuffered so the send blocks until the goroutine reads,
		// ensuring the destroy event is processed before EOF is sent.
		eventsChan := make(chan events.Message)
		errsChan := make(chan error, 1)

		s := NewStore()
		s.cacheMu.Lock()
		meta := ContainerMeta{ID: fullID[:abbreviationLength], FullID: fullID, Name: "svc"}
		s.byPID[pid] = meta
		s.byContainerID[fullID] = containerEntry{meta: meta, pids: []app.PID{pid}}
		s.cacheMu.Unlock()

		s.docker = &mockDockerClient{eventsChan: eventsChan, errsChan: errsChan}

		s.Start(ctx)

		// Blocking send: goroutine must receive before we proceed to send EOF.
		eventsChan <- events.Message{
			Action: events.ActionDestroy,
			Actor:  events.Actor{ID: fullID},
		}
		errsChan <- io.EOF

		assert.Eventually(t, func() bool {
			s.cacheMu.RLock()
			_, found := s.byPID[pid]
			s.cacheMu.RUnlock()
			return !found
		}, 500*time.Millisecond, 5*time.Millisecond)
	})
}

// TestStartSinceCheckpoint verifies that the event watcher seeds Since on initial
// connect and carries the checkpoint across reconnects so die/destroy events that
// arrive during the 1-second backoff gap are not silently dropped.
func TestStartSinceCheckpoint(t *testing.T) {
	t.Run("initial_since_covers_gap_between_start_and_first_events_call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		before := time.Now().Unix()

		errsChan := make(chan error, 1)
		errsChan <- io.EOF
		mock := &mockDockerClient{
			eventsChan: make(chan events.Message),
			errsChan:   errsChan,
		}
		s := NewStore()
		s.docker = mock

		s.Start(ctx)
		after := time.Now().Unix()

		// Wait until Events has been called at least once.
		assert.Eventually(t, func() bool {
			return mock.eventsCallCount() >= 1
		}, 500*time.Millisecond, 5*time.Millisecond)

		opts := mock.eventsCallOpts(0)
		require.NotEmpty(t, opts.Since, "Since must be set on the initial Events call")

		since, err := strconv.ParseInt(opts.Since, 10, 64)
		require.NoError(t, err)
		// since = lastEventAt-1; lastEventAt is seeded inside Start before the goroutine
		// is launched, so since must be >= before-1.
		assert.GreaterOrEqual(t, since, before-1,
			"Since must be anchored to before Start returned, not to when the goroutine ran")
		assert.LessOrEqual(t, since, after)
	})

	t.Run("eventsloop_advances_checkpoint_and_reconnect_since_reflects_it", func(t *testing.T) {
		const fullID = "abc123def456789abc123def456789abc123def456789abc123def456789abcdef"

		fltrs := make(client.Filters).
			Add("type", string(events.ContainerEventType)).
			Add("event", string(events.ActionDie), string(events.ActionDestroy))

		ec := make(chan events.Message, 1)
		erc := make(chan error, 1)
		ec <- events.Message{Action: events.ActionDestroy, Actor: events.Actor{ID: fullID}}
		erc <- io.EOF

		s := NewStore()
		s.docker = &mockDockerClient{eventsChan: ec, errsChan: erc}
		s.lastEventAt.Store(time.Now().Unix())
		beforeEvent := s.lastEventAt.Load()

		_ = s.eventsLoop(context.Background(), fltrs, s.lastEventAt.Load()-1)

		// lastEventAt must advance when an event is processed.
		assert.GreaterOrEqual(t, s.lastEventAt.Load(), beforeEvent,
			"lastEventAt must be updated when a Docker event is processed")

		// The Since value for the next reconnect must not predate the event.
		reconnectSince := s.lastEventAt.Load() - 1
		assert.GreaterOrEqual(t, reconnectSince, beforeEvent-1,
			"reconnect Since must not regress to before the last processed event")
	})
}

// TestCacheConsistency is a table-driven suite that verifies the bidirectional
// invariant between byPID and byContainerID is preserved across every invalidation path.
func TestCacheConsistency(t *testing.T) {
	const (
		fullID1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		fullID2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	meta1 := ContainerMeta{ID: fullID1[:abbreviationLength], FullID: fullID1, Name: "c1"}
	meta2 := ContainerMeta{ID: fullID2[:abbreviationLength], FullID: fullID2, Name: "c2"}

	// setup builds a store with two containers: container1 has pid1+pid2, container2 has pid3.
	setup := func() (*ContainerStore, app.PID, app.PID, app.PID) {
		pid1, pid2, pid3 := app.PID(1), app.PID(2), app.PID(3)
		s := NewStore()
		s.cacheMu.Lock()
		s.byPID[pid1] = meta1
		s.byPID[pid2] = meta1
		s.byPID[pid3] = meta2
		s.byContainerID[fullID1] = containerEntry{meta: meta1, pids: []app.PID{pid1, pid2}}
		s.byContainerID[fullID2] = containerEntry{meta: meta2, pids: []app.PID{pid3}}
		s.cacheMu.Unlock()
		return s, pid1, pid2, pid3
	}

	t.Run("initial_state_is_consistent", func(t *testing.T) {
		s, _, _, _ := setup()
		requireConsistency(t, s)
	})

	t.Run("invalidate_one_of_two_pids_in_container", func(t *testing.T) {
		s, pid1, _, _ := setup()
		s.InvalidatePID(pid1)
		requireConsistency(t, s)

		// pid1 gone from byPID; byContainerID still lists pid2; other container intact
		s.cacheMu.RLock()
		_, p1ok := s.byPID[pid1]
		entry1 := s.byContainerID[fullID1]
		_, p3ok := s.byPID[app.PID(3)]
		entry2 := s.byContainerID[fullID2]
		s.cacheMu.RUnlock()
		assert.False(t, p1ok)
		assert.Equal(t, []app.PID{app.PID(2)}, entry1.pids)
		assert.True(t, p3ok)
		assert.Equal(t, []app.PID{app.PID(3)}, entry2.pids)
	})

	t.Run("invalidate_last_pid_of_container_removes_bycontainer_entry", func(t *testing.T) {
		s, _, _, pid3 := setup()
		s.InvalidatePID(pid3)
		requireConsistency(t, s)

		s.cacheMu.RLock()
		_, p3ok := s.byPID[pid3]
		_, id2ok := s.byContainerID[fullID2]
		s.cacheMu.RUnlock()
		assert.False(t, p3ok, "byPID entry for last pid should be gone")
		assert.False(t, id2ok, "byContainerID entry should be removed when all its pids are gone")
	})

	t.Run("invalidate_container_removes_all_its_pids_from_bypid", func(t *testing.T) {
		s, pid1, pid2, _ := setup()
		s.invalidateContainer(fullID1)
		requireConsistency(t, s)

		s.cacheMu.RLock()
		_, p1ok := s.byPID[pid1]
		_, p2ok := s.byPID[pid2]
		_, id1ok := s.byContainerID[fullID1]
		s.cacheMu.RUnlock()
		assert.False(t, p1ok, "all pids of invalidated container should be removed from byPID")
		assert.False(t, p2ok, "all pids of invalidated container should be removed from byPID")
		assert.False(t, id1ok, "byContainerID entry for invalidated container should be gone")
	})

	t.Run("sequential_pid_invalidations_leave_empty_maps", func(t *testing.T) {
		s, pid1, pid2, pid3 := setup()

		s.InvalidatePID(pid1)
		requireConsistency(t, s)
		s.InvalidatePID(pid2)
		requireConsistency(t, s)
		s.InvalidatePID(pid3)
		requireConsistency(t, s)

		s.cacheMu.RLock()
		assert.Empty(t, s.byPID)
		assert.Empty(t, s.byContainerID)
		s.cacheMu.RUnlock()
	})

	t.Run("invalidate_container_does_not_affect_other_containers", func(t *testing.T) {
		s, _, _, _ := setup()
		s.invalidateContainer(fullID1)
		requireConsistency(t, s)

		s.cacheMu.RLock()
		_, p3ok := s.byPID[app.PID(3)]
		entry2 := s.byContainerID[fullID2]
		s.cacheMu.RUnlock()
		assert.True(t, p3ok, "other container's pid must remain in byPID")
		assert.Equal(t, []app.PID{app.PID(3)}, entry2.pids, "other container's byContainerID entry must remain")
	})

	t.Run("unknown_pid_is_noop", func(t *testing.T) {
		s, _, _, _ := setup()
		s.InvalidatePID(app.PID(9999)) // must not panic or corrupt state
		requireConsistency(t, s)
	})
}
