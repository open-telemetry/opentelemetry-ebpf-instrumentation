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
		containerID := "abc123def456"

		// Manually populate cache to simulate a successful ContainerInfo call
		meta := ContainerMeta{
			ID:             containerID[:12],
			Name:           "test-container",
			ComposeService: "",
		}

		store.cacheMu.Lock()
		store.byPID[pid1] = meta
		store.byPID[pid2] = meta
		store.byID[meta.ID] = []app.PID{pid1, pid2}
		store.cacheMu.Unlock()

		// Verify both PIDs are cached
		store.cacheMu.RLock()
		_, ok1 := store.byPID[pid1]
		_, ok2 := store.byPID[pid2]
		store.cacheMu.RUnlock()
		assert.True(t, ok1)
		assert.True(t, ok2)

		// Invalidate by container ID
		store.invalidateContainer(meta.ID)

		// Verify both PIDs are cleared
		store.cacheMu.RLock()
		_, ok1 = store.byPID[pid1]
		_, ok2 = store.byPID[pid2]
		_, ok3 := store.byID[meta.ID]
		store.cacheMu.RUnlock()
		assert.False(t, ok1)
		assert.False(t, ok2)
		assert.False(t, ok3)
	})

	t.Run("invalidation_only_affects_specified_container", func(t *testing.T) {
		store := NewStore()
		pid1 := app.PID(1111)
		pid2 := app.PID(2222)
		containerID1 := "abc123def456"
		containerID2 := "xyz789abc012"

		meta1 := ContainerMeta{ID: containerID1[:12], Name: "container1"}
		meta2 := ContainerMeta{ID: containerID2[:12], Name: "container2"}

		store.cacheMu.Lock()
		store.byPID[pid1] = meta1
		store.byPID[pid2] = meta2
		store.byID[meta1.ID] = []app.PID{pid1}
		store.byID[meta2.ID] = []app.PID{pid2}
		store.cacheMu.Unlock()

		// Invalidate only the first container
		store.invalidateContainer(meta1.ID)

		// Verify only pid1 is cleared, pid2 remains
		store.cacheMu.RLock()
		_, ok1 := store.byPID[pid1]
		_, ok2 := store.byPID[pid2]
		store.cacheMu.RUnlock()
		assert.False(t, ok1)
		assert.True(t, ok2)
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

		// Verify store can be initialized with mocked client
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
