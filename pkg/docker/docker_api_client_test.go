// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"io"
	"testing"

	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func TestContainerStoreInvalidation(t *testing.T) {
	t.Run("invalidation_clears_all_pids_for_container", func(t *testing.T) {
		store := NewStore()
		pid1 := app.PID(1111)
		pid2 := app.PID(2222)
		fullContainerID := "abc123def456789abc123def456789abc123def456789abc123def456789abcdef"

		// Manually populate cache to simulate a successful ContainerInfo call
		meta := ContainerMeta{
			ID:             fullContainerID,
			Name:           "test-container",
			ComposeService: "",
		}

		store.cacheMu.Lock()
		store.byPID[pid1] = meta
		store.byPID[pid2] = meta
		store.byID[fullContainerID] = []app.PID{pid1, pid2}
		store.cacheMu.Unlock()

		// Verify both PIDs are cached
		store.cacheMu.RLock()
		_, ok1 := store.byPID[pid1]
		_, ok2 := store.byPID[pid2]
		store.cacheMu.RUnlock()
		assert.True(t, ok1)
		assert.True(t, ok2)

		// Invalidate by full container ID (as Docker events would)
		store.invalidateContainer(fullContainerID)

		// Verify both PIDs are cleared
		store.cacheMu.RLock()
		_, ok1 = store.byPID[pid1]
		_, ok2 = store.byPID[pid2]
		_, ok3 := store.byID[fullContainerID]
		store.cacheMu.RUnlock()
		assert.False(t, ok1)
		assert.False(t, ok2)
		assert.False(t, ok3)
	})

	t.Run("invalidation_only_affects_specified_container", func(t *testing.T) {
		store := NewStore()
		pid1 := app.PID(1111)
		pid2 := app.PID(2222)
		fullContainerID1 := "abc123def456789abc123def456789abc123def456789abc123def456789abcdef"
		fullContainerID2 := "xyz789abc012xyz789abc012xyz789abc012xyz789abc012xyz789abc012xyzabc"

		meta1 := ContainerMeta{ID: fullContainerID1, Name: "container1"}
		meta2 := ContainerMeta{ID: fullContainerID2, Name: "container2"}

		store.cacheMu.Lock()
		store.byPID[pid1] = meta1
		store.byPID[pid2] = meta2
		store.byID[fullContainerID1] = []app.PID{pid1}
		store.byID[fullContainerID2] = []app.PID{pid2}
		store.cacheMu.Unlock()

		// Invalidate only the first container (by full ID, as Docker events would)
		store.invalidateContainer(fullContainerID1)

		// Verify only pid1 is cleared, pid2 remains
		store.cacheMu.RLock()
		_, ok1 := store.byPID[pid1]
		_, ok2 := store.byPID[pid2]
		store.cacheMu.RUnlock()
		assert.False(t, ok1)
		assert.True(t, ok2)
	})

	t.Run("pid_invalidation_removes_pid_from_both_indexes", func(t *testing.T) {
		store := NewStore()
		pid1 := app.PID(1111)
		pid2 := app.PID(2222)
		containerID := "abc123def456789abc123def456789abc123def456789abc123def456789abcdef"

		meta := ContainerMeta{
			ID:   containerID,
			Name: "test-container",
		}

		store.cacheMu.Lock()
		store.byPID[pid1] = meta
		store.byPID[pid2] = meta
		store.byID[containerID] = []app.PID{pid1, pid2}
		store.cacheMu.Unlock()

		store.InvalidatePID(pid1)

		store.cacheMu.RLock()
		_, ok1 := store.byPID[pid1]
		_, ok2 := store.byPID[pid2]
		pids := store.byID[containerID]
		store.cacheMu.RUnlock()

		assert.False(t, ok1)
		assert.True(t, ok2)
		assert.Equal(t, []app.PID{pid2}, pids)
	})

	t.Run("event_stream_can_be_created", func(t *testing.T) {
		store := NewStore()
		eventsChan := make(chan events.Message, 1)
		errsChan := make(chan error, 1)
		errsChan <- io.EOF

		mockClient := &struct {
			*mockDockerClientBase
		}{
			mockDockerClientBase: &mockDockerClientBase{
				eventsChan: eventsChan,
				errsChan:   errsChan,
			},
		}
		store.docker = mockClient.mockDockerClientBase

		assert.NotNil(t, store.docker)
	})
}

type mockDockerClientBase struct {
	eventsChan chan events.Message
	errsChan   chan error
}

func (m *mockDockerClientBase) ContainerInspect(_ context.Context, _ string, _ client.ContainerInspectOptions) (client.ContainerInspectResult, error) {
	return client.ContainerInspectResult{}, nil
}

func (m *mockDockerClientBase) Events(_ context.Context, _ client.EventsListOptions) client.EventsResult {
	return client.EventsResult{
		Messages: m.eventsChan,
		Err:      m.errsChan,
	}
}
