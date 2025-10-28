// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/helpers/maps"
)

func TestPidContainerTracker_Track(t *testing.T) {
	tests := []struct {
		name        string
		containerID string
		events      []*exec.ProcessEvent
		expectStore bool
	}{
		{
			name:        "single process tracking",
			containerID: "container-1",
			events: []*exec.ProcessEvent{
				{
					File: &exec.FileInfo{Pid: 1000},
					Type: exec.ProcessEventCreated,
				},
			},
			expectStore: true,
		},
		{
			name:        "multiple processes same container",
			containerID: "container-1",
			events: []*exec.ProcessEvent{
				{
					File: &exec.FileInfo{Pid: 1000},
					Type: exec.ProcessEventCreated,
				},
				{
					File: &exec.FileInfo{Pid: 1001},
					Type: exec.ProcessEventCreated,
				},
				{
					File: &exec.FileInfo{Pid: 1002},
					Type: exec.ProcessEventCreated,
				},
			},
			expectStore: true,
		},
		{
			name:        "empty container ID",
			containerID: "",
			events: []*exec.ProcessEvent{
				{
					File: &exec.FileInfo{Pid: 1000},
					Type: exec.ProcessEventCreated,
				},
			},
			expectStore: true,
		},
		{
			name:        "nil process event",
			containerID: "container-1",
			events:      []*exec.ProcessEvent{nil},
			expectStore: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := &pidContainerTracker{
				missedPods:    maps.Map2[string, int32, *exec.ProcessEvent]{},
				missedPodPids: make(map[int32]string),
			}

			for _, event := range tt.events {
				tracker.track(tt.containerID, event)
			}

			if tt.expectStore {
				stored, ok := tracker.info(tt.containerID)
				require.True(t, ok, "Expected container to be tracked")
				assert.Len(t, stored, len(tt.events), "Expected all events to be stored")

				// Verify each event is stored correctly
				for _, event := range tt.events {
					if event != nil {
						storedEvent, exists := stored[event.File.Pid]
						assert.True(t, exists, "Expected PID %d to be stored", event.File.Pid)
						assert.Equal(t, event, storedEvent, "Stored event should match original")

						// Check reverse mapping
						containerID, exists := tracker.missedPodPids[event.File.Pid]
						assert.True(t, exists, "Expected reverse mapping for PID %d", event.File.Pid)
						assert.Equal(t, tt.containerID, containerID, "Reverse mapping should match container ID")
					}
				}
			}
		})
	}
}

func TestPidContainerTracker_Remove(t *testing.T) {
	tests := []struct {
		name          string
		setupEvents   map[string][]*exec.ProcessEvent
		removePid     int32
		expectRemoved bool
		expectRemain  map[string][]int32 // containerID -> remaining PIDs
	}{
		{
			name: "remove existing PID",
			setupEvents: map[string][]*exec.ProcessEvent{
				"container-1": {
					{File: &exec.FileInfo{Pid: 1000}, Type: exec.ProcessEventCreated},
					{File: &exec.FileInfo{Pid: 1001}, Type: exec.ProcessEventCreated},
				},
			},
			removePid:     1000,
			expectRemoved: true,
			expectRemain: map[string][]int32{
				"container-1": {1001},
			},
		},
		{
			name: "remove non-existing PID",
			setupEvents: map[string][]*exec.ProcessEvent{
				"container-1": {
					{File: &exec.FileInfo{Pid: 1000}, Type: exec.ProcessEventCreated},
				},
			},
			removePid:     2000,
			expectRemoved: false,
			expectRemain: map[string][]int32{
				"container-1": {1000},
			},
		},
		{
			name: "remove last PID from container",
			setupEvents: map[string][]*exec.ProcessEvent{
				"container-1": {
					{File: &exec.FileInfo{Pid: 1000}, Type: exec.ProcessEventCreated},
				},
			},
			removePid:     1000,
			expectRemoved: true,
			expectRemain:  map[string][]int32{},
		},
		{
			name: "remove PID from multiple containers",
			setupEvents: map[string][]*exec.ProcessEvent{
				"container-1": {
					{File: &exec.FileInfo{Pid: 1000}, Type: exec.ProcessEventCreated},
					{File: &exec.FileInfo{Pid: 1001}, Type: exec.ProcessEventCreated},
				},
				"container-2": {
					{File: &exec.FileInfo{Pid: 2000}, Type: exec.ProcessEventCreated},
				},
			},
			removePid:     1000,
			expectRemoved: true,
			expectRemain: map[string][]int32{
				"container-1": {1001},
				"container-2": {2000},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := &pidContainerTracker{
				missedPods:    maps.Map2[string, int32, *exec.ProcessEvent]{},
				missedPodPids: make(map[int32]string),
			}

			// Setup initial state
			for containerID, events := range tt.setupEvents {
				for _, event := range events {
					tracker.track(containerID, event)
				}
			}

			// Perform removal
			tracker.remove(tt.removePid)

			// Verify reverse mapping is cleaned up
			_, exists := tracker.missedPodPids[tt.removePid]
			assert.False(t, exists, "Reverse mapping should be removed for PID %d", tt.removePid)

			// Verify remaining state
			for containerID, expectedPids := range tt.expectRemain {
				stored, ok := tracker.info(containerID)
				if len(expectedPids) == 0 {
					// Container should either not exist or be empty
					if ok {
						assert.Empty(t, stored, "Container %s should be empty", containerID)
					}
				} else {
					require.True(t, ok, "Container %s should exist", containerID)
					assert.Len(t, stored, len(expectedPids), "Container %s should have %d processes", containerID, len(expectedPids))

					for _, pid := range expectedPids {
						_, exists := stored[pid]
						assert.True(t, exists, "PID %d should exist in container %s", pid, containerID)
					}
				}
			}
		})
	}
}

func TestPidContainerTracker_RemoveAll(t *testing.T) {
	tests := []struct {
		name            string
		setupEvents     map[string][]*exec.ProcessEvent
		removeContainer string
		expectRemain    map[string][]int32
	}{
		{
			name: "remove all processes from single container",
			setupEvents: map[string][]*exec.ProcessEvent{
				"container-1": {
					{File: &exec.FileInfo{Pid: 1000}, Type: exec.ProcessEventCreated},
					{File: &exec.FileInfo{Pid: 1001}, Type: exec.ProcessEventCreated},
					{File: &exec.FileInfo{Pid: 1002}, Type: exec.ProcessEventCreated},
				},
			},
			removeContainer: "container-1",
			expectRemain:    map[string][]int32{},
		},
		{
			name: "remove all from one of multiple containers",
			setupEvents: map[string][]*exec.ProcessEvent{
				"container-1": {
					{File: &exec.FileInfo{Pid: 1000}, Type: exec.ProcessEventCreated},
					{File: &exec.FileInfo{Pid: 1001}, Type: exec.ProcessEventCreated},
				},
				"container-2": {
					{File: &exec.FileInfo{Pid: 2000}, Type: exec.ProcessEventCreated},
				},
				"container-3": {
					{File: &exec.FileInfo{Pid: 3000}, Type: exec.ProcessEventCreated},
					{File: &exec.FileInfo{Pid: 3001}, Type: exec.ProcessEventCreated},
				},
			},
			removeContainer: "container-1",
			expectRemain: map[string][]int32{
				"container-2": {2000},
				"container-3": {3000, 3001},
			},
		},
		{
			name: "remove non-existing container",
			setupEvents: map[string][]*exec.ProcessEvent{
				"container-1": {
					{File: &exec.FileInfo{Pid: 1000}, Type: exec.ProcessEventCreated},
				},
			},
			removeContainer: "non-existing",
			expectRemain: map[string][]int32{
				"container-1": {1000},
			},
		},
		{
			name:            "remove from empty tracker",
			setupEvents:     map[string][]*exec.ProcessEvent{},
			removeContainer: "container-1",
			expectRemain:    map[string][]int32{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := &pidContainerTracker{
				missedPods:    maps.Map2[string, int32, *exec.ProcessEvent]{},
				missedPodPids: make(map[int32]string),
			}

			// Setup initial state
			removedPids := []int32{}
			for containerID, events := range tt.setupEvents {
				for _, event := range events {
					tracker.track(containerID, event)
					if containerID == tt.removeContainer {
						removedPids = append(removedPids, event.File.Pid)
					}
				}
			}

			// Perform removal
			tracker.removeAll(tt.removeContainer)

			// Verify removed container is gone
			stored, ok := tracker.info(tt.removeContainer)
			if ok {
				assert.Empty(t, stored, "Removed container should be empty")
			}

			// Verify reverse mappings are cleaned up for removed container
			for _, pid := range removedPids {
				_, exists := tracker.missedPodPids[pid]
				assert.False(t, exists, "Reverse mapping should be removed for PID %d", pid)
			}

			// Verify remaining state
			for containerID, expectedPids := range tt.expectRemain {
				stored, ok := tracker.info(containerID)
				require.True(t, ok, "Container %s should exist", containerID)
				assert.Len(t, stored, len(expectedPids), "Container %s should have %d processes", containerID, len(expectedPids))

				for _, pid := range expectedPids {
					_, exists := stored[pid]
					assert.True(t, exists, "PID %d should exist in container %s", pid, containerID)

					// Verify reverse mapping still exists
					mappedContainer, exists := tracker.missedPodPids[pid]
					assert.True(t, exists, "Reverse mapping should exist for PID %d", pid)
					assert.Equal(t, containerID, mappedContainer, "Reverse mapping should be correct for PID %d", pid)
				}
			}
		})
	}
}

func TestPidContainerTracker_Info(t *testing.T) {
	tests := []struct {
		name           string
		setupEvents    map[string][]*exec.ProcessEvent
		queryContainer string
		expectFound    bool
		expectCount    int
	}{
		{
			name: "get info for existing container",
			setupEvents: map[string][]*exec.ProcessEvent{
				"container-1": {
					{File: &exec.FileInfo{Pid: 1000}, Type: exec.ProcessEventCreated},
					{File: &exec.FileInfo{Pid: 1001}, Type: exec.ProcessEventCreated},
				},
			},
			queryContainer: "container-1",
			expectFound:    true,
			expectCount:    2,
		},
		{
			name: "get info for non-existing container",
			setupEvents: map[string][]*exec.ProcessEvent{
				"container-1": {
					{File: &exec.FileInfo{Pid: 1000}, Type: exec.ProcessEventCreated},
				},
			},
			queryContainer: "container-2",
			expectFound:    false,
			expectCount:    0,
		},
		{
			name:           "get info from empty tracker",
			setupEvents:    map[string][]*exec.ProcessEvent{},
			queryContainer: "container-1",
			expectFound:    false,
			expectCount:    0,
		},
		{
			name: "get info for empty container ID",
			setupEvents: map[string][]*exec.ProcessEvent{
				"": {
					{File: &exec.FileInfo{Pid: 1000}, Type: exec.ProcessEventCreated},
				},
			},
			queryContainer: "",
			expectFound:    true,
			expectCount:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := &pidContainerTracker{
				missedPods:    maps.Map2[string, int32, *exec.ProcessEvent]{},
				missedPodPids: make(map[int32]string),
			}

			// Setup initial state
			for containerID, events := range tt.setupEvents {
				for _, event := range events {
					tracker.track(containerID, event)
				}
			}

			// Query info
			stored, found := tracker.info(tt.queryContainer)

			assert.Equal(t, tt.expectFound, found, "Found status should match expectation")
			if tt.expectFound {
				assert.Len(t, stored, tt.expectCount, "Should have expected number of processes")

				// Verify all returned processes belong to the correct container
				expectedEvents := tt.setupEvents[tt.queryContainer]
				for _, expectedEvent := range expectedEvents {
					storedEvent, exists := stored[expectedEvent.File.Pid]
					assert.True(t, exists, "Expected PID %d should be present", expectedEvent.File.Pid)
					assert.Equal(t, expectedEvent, storedEvent, "Stored event should match original")
				}
			} else {
				assert.Nil(t, stored, "Should return nil for non-existing container")
			}
		})
	}
}

func TestPidContainerTracker_ConcurrentAccess(*testing.T) {
	tracker := &pidContainerTracker{
		missedPods:    maps.Map2[string, int32, *exec.ProcessEvent]{},
		missedPodPids: make(map[int32]string),
	}

	const numGoroutines = 10
	const numOperationsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 4) // 4 types of operations

	// Concurrent track operations
	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			for j := range numOperationsPerGoroutine {
				event := &exec.ProcessEvent{
					File: &exec.FileInfo{Pid: int32(id*1000 + j)},
					Type: exec.ProcessEventCreated,
				}
				tracker.track("container-"+string(rune(id)), event)
			}
		}(i)
	}

	// Concurrent remove operations
	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			for j := range numOperationsPerGoroutine {
				tracker.remove(int32(id*1000 + j))
			}
		}(i)
	}

	// Concurrent removeAll operations
	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			for range numOperationsPerGoroutine {
				tracker.removeAll("container-" + string(rune(id)))
			}
		}(i)
	}

	// Concurrent info operations
	for i := range numGoroutines {
		go func(id int) {
			defer wg.Done()
			for range numOperationsPerGoroutine {
				tracker.info("container-" + string(rune(id)))
			}
		}(i)
	}

	wg.Wait()

	// Test should complete without race conditions or panics
	// The exact state is unpredictable due to concurrent operations,
	// but the operations should be thread-safe
}

func TestPidContainerTracker_ComplexScenarios(t *testing.T) {
	t.Run("multiple containers with overlapping PIDs", func(t *testing.T) {
		tracker := &pidContainerTracker{
			missedPods:    maps.Map2[string, int32, *exec.ProcessEvent]{},
			missedPodPids: make(map[int32]string),
		}

		// This scenario should not happen in practice (PIDs should be unique),
		// but we test the tracker's behavior anyway
		event1 := &exec.ProcessEvent{
			File: &exec.FileInfo{Pid: 1000},
			Type: exec.ProcessEventCreated,
		}
		event2 := &exec.ProcessEvent{
			File: &exec.FileInfo{Pid: 1000},
			Type: exec.ProcessEventTerminated,
		}

		tracker.track("container-1", event1)
		tracker.track("container-2", event2)

		// The second track should overwrite the first in missedPodPids
		containerID, exists := tracker.missedPodPids[1000]
		assert.True(t, exists)
		assert.Equal(t, "container-2", containerID)

		// But both containers should have their events
		stored1, ok1 := tracker.info("container-1")
		stored2, ok2 := tracker.info("container-2")

		assert.True(t, ok1)
		assert.True(t, ok2)
		assert.Equal(t, event1, stored1[1000])
		assert.Equal(t, event2, stored2[1000])
	})

	t.Run("large number of processes", func(t *testing.T) {
		tracker := &pidContainerTracker{
			missedPods:    maps.Map2[string, int32, *exec.ProcessEvent]{},
			missedPodPids: make(map[int32]string),
		}

		const numContainers = 10
		const numProcessesPerContainer = 1000

		// Track many processes
		for containerID := range numContainers {
			for pid := range numProcessesPerContainer {
				event := &exec.ProcessEvent{
					File: &exec.FileInfo{
						Pid:     int32(containerID*numProcessesPerContainer + pid),
						Service: svc.Attrs{},
					},
					Type: exec.ProcessEventCreated,
				}
				tracker.track("container-"+string(rune(containerID)), event)
			}
		}

		// Verify all are tracked
		for containerID := range numContainers {
			stored, ok := tracker.info("container-" + string(rune(containerID)))
			assert.True(t, ok)
			assert.Len(t, stored, numProcessesPerContainer)
		}

		// Remove half the containers
		for containerID := range numContainers / 2 {
			tracker.removeAll("container-" + string(rune(containerID)))
		}

		// Verify removal
		for containerID := range numContainers / 2 {
			stored, ok := tracker.info("container-" + string(rune(containerID)))
			if ok {
				assert.Empty(t, stored)
			}
		}

		// Verify remaining containers are intact
		for containerID := numContainers / 2; containerID < numContainers; containerID++ {
			stored, ok := tracker.info("container-" + string(rune(containerID)))
			assert.True(t, ok)
			assert.Len(t, stored, numProcessesPerContainer)
		}
	})

	t.Run("track remove track cycle", func(t *testing.T) {
		tracker := &pidContainerTracker{
			missedPods:    maps.Map2[string, int32, *exec.ProcessEvent]{},
			missedPodPids: make(map[int32]string),
		}

		event := &exec.ProcessEvent{
			File: &exec.FileInfo{Pid: 1000},
			Type: exec.ProcessEventCreated,
		}

		// Track, remove, track again
		tracker.track("container-1", event)
		tracker.remove(1000)
		tracker.track("container-1", event)

		// Should be tracked again
		stored, ok := tracker.info("container-1")
		assert.True(t, ok)
		assert.Len(t, stored, 1)
		assert.Equal(t, event, stored[1000])
	})
}
