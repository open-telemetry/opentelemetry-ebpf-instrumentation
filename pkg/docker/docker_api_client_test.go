// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"errors"
	"io"
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
	inspectResult client.ContainerInspectResult
	inspectErr    error
	eventsChan    chan events.Message
	errsChan      chan error
}

func (m *mockDockerClient) ContainerInspect(_ context.Context, _ string, _ client.ContainerInspectOptions) (client.ContainerInspectResult, error) {
	return m.inspectResult, m.inspectErr
}

func (m *mockDockerClient) Events(_ context.Context, _ client.EventsListOptions) client.EventsResult {
	return client.EventsResult{
		Messages: m.eventsChan,
		Err:      m.errsChan,
	}
}

// requireConsistency verifies the bidirectional invariant between byPID and byID:
//   - every (pid → meta) in byPID: byID[meta.FullID] contains that pid
//   - every (fullID → pids) in byID: every pid in the slice has a byPID entry pointing back to fullID
func requireConsistency(t *testing.T, s *ContainerStore) {
	t.Helper()
	s.cacheMu.RLock()
	defer s.cacheMu.RUnlock()

	for pid, meta := range s.byPID {
		pids, ok := s.byID[string(meta.FullID)]
		require.Truef(t, ok,
			"byPID[%d] references fullID %q but byID has no entry for it", pid, meta.FullID)
		found := false
		for _, p := range pids {
			if p == pid {
				found = true
				break
			}
		}
		require.Truef(t, found,
			"byPID[%d] references fullID %q but that pid is not listed in byID[%q]", pid, meta.FullID, meta.FullID)
	}

	for fullID, pids := range s.byID {
		for _, pid := range pids {
			meta, ok := s.byPID[pid]
			require.Truef(t, ok,
				"byID[%q] lists pid %d but byPID has no entry for it", fullID, pid)
			require.Equalf(t, ContainerID(fullID), meta.FullID,
				"byID[%q] lists pid %d but byPID[%d].FullID is %q", fullID, pid, pid, meta.FullID)
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
		s.byID[fullID] = []app.PID{pid}
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

// TestCacheConsistency is a table-driven suite that verifies the bidirectional
// invariant between byPID and byID is preserved across every invalidation path.
func TestCacheConsistency(t *testing.T) {
	const (
		fullID1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		fullID2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	meta1 := ContainerMeta{ID: fullID1[:abbreviationLength], FullID: fullID1, Name: "c1"}
	meta2 := ContainerMeta{ID: fullID2[:abbreviationLength], FullID: fullID2, Name: "c2"}

	// setup builds a store with two containers sharing pid1+pid2 and pid3 respectively.
	setup := func() (*ContainerStore, app.PID, app.PID, app.PID) {
		pid1, pid2, pid3 := app.PID(1), app.PID(2), app.PID(3)
		s := NewStore()
		s.cacheMu.Lock()
		s.byPID[pid1] = meta1
		s.byPID[pid2] = meta1
		s.byPID[pid3] = meta2
		s.byID[fullID1] = []app.PID{pid1, pid2}
		s.byID[fullID2] = []app.PID{pid3}
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

		// pid1 gone from byPID; byID still lists pid2; other container intact
		s.cacheMu.RLock()
		_, p1ok := s.byPID[pid1]
		pids1 := s.byID[fullID1]
		_, p3ok := s.byPID[app.PID(3)]
		pids2 := s.byID[fullID2]
		s.cacheMu.RUnlock()
		assert.False(t, p1ok)
		assert.Equal(t, []app.PID{app.PID(2)}, pids1)
		assert.True(t, p3ok)
		assert.Equal(t, []app.PID{app.PID(3)}, pids2)
	})

	t.Run("invalidate_last_pid_of_container_removes_byid_entry", func(t *testing.T) {
		s, _, _, pid3 := setup()
		s.InvalidatePID(pid3)
		requireConsistency(t, s)

		s.cacheMu.RLock()
		_, p3ok := s.byPID[pid3]
		_, id2ok := s.byID[fullID2]
		s.cacheMu.RUnlock()
		assert.False(t, p3ok, "byPID entry for last pid should be gone")
		assert.False(t, id2ok, "byID entry should be removed when all its pids are gone")
	})

	t.Run("invalidate_container_removes_all_its_pids_from_bypid", func(t *testing.T) {
		s, pid1, pid2, _ := setup()
		s.invalidateContainer(fullID1)
		requireConsistency(t, s)

		s.cacheMu.RLock()
		_, p1ok := s.byPID[pid1]
		_, p2ok := s.byPID[pid2]
		_, id1ok := s.byID[fullID1]
		s.cacheMu.RUnlock()
		assert.False(t, p1ok, "all pids of invalidated container should be removed from byPID")
		assert.False(t, p2ok, "all pids of invalidated container should be removed from byPID")
		assert.False(t, id1ok, "byID entry for invalidated container should be gone")
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
		assert.Empty(t, s.byID)
		s.cacheMu.RUnlock()
	})

	t.Run("invalidate_container_does_not_affect_other_containers", func(t *testing.T) {
		s, _, _, _ := setup()
		s.invalidateContainer(fullID1)
		requireConsistency(t, s)

		s.cacheMu.RLock()
		_, p3ok := s.byPID[app.PID(3)]
		pids2 := s.byID[fullID2]
		s.cacheMu.RUnlock()
		assert.True(t, p3ok, "other container's pid must remain in byPID")
		assert.Equal(t, []app.PID{app.PID(3)}, pids2, "other container's byID entry must remain")
	})

	t.Run("unknown_pid_is_noop", func(t *testing.T) {
		s, _, _, _ := setup()
		s.InvalidatePID(app.PID(9999)) // must not panic or corrupt state
		requireConsistency(t, s)
	})
}
