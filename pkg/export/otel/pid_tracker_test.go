// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

func makeUID(name, ns string) svc.UID {
	return svc.UID{
		Name:      name,
		Namespace: ns,
	}
}

func makeNameNamespace(name, ns string) svc.ServiceNameNamespace {
	return svc.ServiceNameNamespace{
		Name:      name,
		Namespace: ns,
	}
}

func TestPidServiceTracker_AddAndRemovePID(t *testing.T) {
	tracker := NewPidServiceTracker()
	uid := makeUID("foo", "bar")
	pid := int32(1234)

	tracker.AddPID(pid, uid)

	if got, ok := tracker.pidToService[pid]; !ok || got != uid {
		t.Errorf("AddPID: pidToService not set correctly, got %v, want %v", got, uid)
	}
	if _, ok := tracker.servicePIDs[uid][pid]; !ok {
		t.Errorf("AddPID: servicePIDs not set correctly")
	}
	if got, ok := tracker.names[uid.NameNamespace()]; !ok || got != uid {
		t.Errorf("AddPID: names not set correctly, got %v, want %v", got, uid)
	}

	removed, removedUID := tracker.RemovePID(pid)
	if !removed {
		t.Errorf("RemovePID: should return true when last pid removed")
	}
	if removedUID != uid {
		t.Errorf("RemovePID: should return correct UID, got %v, want %v", removedUID, uid)
	}
	if _, ok := tracker.pidToService[pid]; ok {
		t.Errorf("RemovePID: pidToService not deleted")
	}
	if _, ok := tracker.servicePIDs[uid]; ok {
		t.Errorf("RemovePID: servicePIDs not deleted")
	}
	if _, ok := tracker.names[uid.NameNamespace()]; ok {
		t.Errorf("RemovePID: names not deleted")
	}

	assert.False(t, tracker.ServiceLive(uid))
}

func TestPidServiceTracker_RemovePID_NotLast(t *testing.T) {
	tracker := NewPidServiceTracker()
	uid := makeUID("foo1", "bar1")
	pid1 := int32(1)
	pid2 := int32(2)
	tracker.AddPID(pid1, uid)
	tracker.AddPID(pid2, uid)

	removed, removedUID := tracker.RemovePID(pid1)
	if removed {
		t.Errorf("RemovePID: should return false when not last pid removed")
	}
	if removedUID != (svc.UID{}) {
		t.Errorf("RemovePID: should return zero UID when not last pid removed")
	}
	if _, ok := tracker.pidToService[pid1]; ok {
		t.Errorf("RemovePID: pidToService not deleted for pid1")
	}
	if _, ok := tracker.servicePIDs[uid][pid1]; ok {
		t.Errorf("RemovePID: servicePIDs not deleted for pid1")
	}
	if _, ok := tracker.names[uid.NameNamespace()]; !ok {
		t.Errorf("RemovePID: names should still exist")
	}

	assert.True(t, tracker.ServiceLive(uid))
}

func TestPidServiceTracker_RemovePID_Last(t *testing.T) {
	tracker := NewPidServiceTracker()
	uid := makeUID("foo", "bar")
	pid1 := int32(1)
	pid2 := int32(2)
	tracker.AddPID(pid1, uid)
	tracker.AddPID(pid2, uid)

	removed, removedUID := tracker.RemovePID(pid1)
	if removed {
		t.Errorf("RemovePID: should return false when not last pid removed")
	}
	if removedUID != (svc.UID{}) {
		t.Errorf("RemovePID: should return zero UID when not last pid removed")
	}
	removed, removedUID = tracker.RemovePID(pid2)
	if !removed {
		t.Errorf("RemovePID: should return true when last pid removed")
	}
	if removedUID == (svc.UID{}) {
		t.Errorf("RemovePID: should return non zero UID when last pid removed")
	}
	if _, ok := tracker.pidToService[pid1]; ok {
		t.Errorf("RemovePID: pidToService not deleted for pid1")
	}
	if _, ok := tracker.pidToService[pid2]; ok {
		t.Errorf("RemovePID: pidToService not deleted for pid2")
	}
	if _, ok := tracker.servicePIDs[uid]; ok {
		t.Errorf("RemovePID: servicePIDs not deleted for both pids")
	}
	if _, ok := tracker.names[uid.NameNamespace()]; ok {
		t.Errorf("RemovePID: names should not exist")
	}

	assert.False(t, tracker.ServiceLive(uid))
}

func TestPidServiceTracker_Count(t *testing.T) {
	tracker := NewPidServiceTracker()
	uid := makeUID("foo", "bar")
	pid1 := int32(1)
	pid2 := int32(2)

	assert.Equal(t, 0, tracker.Count())

	tracker.AddPID(pid1, uid)
	tracker.AddPID(pid2, uid)

	assert.Equal(t, 2, tracker.Count())

	_, _ = tracker.RemovePID(pid1)
	assert.Equal(t, 1, tracker.Count())

	_, _ = tracker.RemovePID(pid2)
	assert.Equal(t, 0, tracker.Count())
}

func TestPidServiceTracker_IsTrackingServerService(t *testing.T) {
	tracker := NewPidServiceTracker()
	uid := makeUID("foo", "bar")
	tracker.AddPID(42, uid)
	nameNs := uid.NameNamespace()
	if !tracker.IsTrackingServerService(nameNs) {
		t.Errorf("IsTrackingServerService: should return true for tracked service")
	}
	if !tracker.IsTrackingServerService(makeNameNamespace("foo", "bar")) {
		t.Errorf("IsTrackingServerService: should return true for tracked service")
	}
	other := makeNameNamespace("other", "bar")
	if tracker.IsTrackingServerService(other) {
		t.Errorf("IsTrackingServerService: should return false for untracked service")
	}
}

func TestPidServiceTracker_TracksPID(t *testing.T) {
	tracker := NewPidServiceTracker()
	uid1 := makeUID("service1", "namespace1")
	uid2 := makeUID("service2", "namespace2")
	pid1 := int32(1001)
	pid2 := int32(1002)
	pid3 := int32(1003) // untracked PID

	// Test tracking non-existent PID
	gotUID, exists := tracker.TracksPID(pid1)
	assert.False(t, exists, "TracksPID should return false for non-existent PID")
	assert.Equal(t, svc.UID{}, gotUID, "TracksPID should return zero UID for non-existent PID")

	// Add PIDs
	tracker.AddPID(pid1, uid1)
	tracker.AddPID(pid2, uid2)

	// Test tracking existing PIDs
	gotUID, exists = tracker.TracksPID(pid1)
	assert.True(t, exists, "TracksPID should return true for existing PID")
	assert.Equal(t, uid1, gotUID, "TracksPID should return correct UID for PID1")

	gotUID, exists = tracker.TracksPID(pid2)
	assert.True(t, exists, "TracksPID should return true for existing PID")
	assert.Equal(t, uid2, gotUID, "TracksPID should return correct UID for PID2")

	// Test tracking non-existent PID again
	gotUID, exists = tracker.TracksPID(pid3)
	assert.False(t, exists, "TracksPID should return false for untracked PID")
	assert.Equal(t, svc.UID{}, gotUID, "TracksPID should return zero UID for untracked PID")

	// Test after removing a PID
	tracker.RemovePID(pid1)
	gotUID, exists = tracker.TracksPID(pid1)
	assert.False(t, exists, "TracksPID should return false for removed PID")
	assert.Equal(t, svc.UID{}, gotUID, "TracksPID should return zero UID for removed PID")

	// Verify other PID still tracked
	gotUID, exists = tracker.TracksPID(pid2)
	assert.True(t, exists, "TracksPID should still return true for remaining PID")
	assert.Equal(t, uid2, gotUID, "TracksPID should return correct UID for remaining PID")
}

func TestPidServiceTracker_UpdateUID(t *testing.T) {
	t.Run("update existing service UID", func(t *testing.T) {
		tracker := NewPidServiceTracker()
		oldUID := makeUID("old-service", "namespace1")
		newUID := makeUID("new-service", "namespace1")
		pid1 := int32(1001)
		pid2 := int32(1002)

		// Add PIDs to old UID
		tracker.AddPID(pid1, oldUID)
		tracker.AddPID(pid2, oldUID)

		// Verify initial state
		gotUID, exists := tracker.TracksPID(pid1)
		assert.True(t, exists)
		assert.Equal(t, oldUID, gotUID)

		gotUID, exists = tracker.TracksPID(pid2)
		assert.True(t, exists)
		assert.Equal(t, oldUID, gotUID)

		assert.True(t, tracker.ServiceLive(oldUID))
		assert.False(t, tracker.ServiceLive(newUID))

		// Update UID
		tracker.ReplaceUID(oldUID, newUID)

		// Verify PIDs now map to new UID
		gotUID, exists = tracker.TracksPID(pid1)
		assert.True(t, exists, "PID1 should still be tracked after UID update")
		assert.Equal(t, newUID, gotUID, "PID1 should map to new UID")

		gotUID, exists = tracker.TracksPID(pid2)
		assert.True(t, exists, "PID2 should still be tracked after UID update")
		assert.Equal(t, newUID, gotUID, "PID2 should map to new UID")

		// Verify service live status
		assert.False(t, tracker.ServiceLive(oldUID), "Old UID should not be live")
		assert.True(t, tracker.ServiceLive(newUID), "New UID should be live")

		// Verify internal state consistency
		assert.Equal(t, 2, tracker.Count(), "Count should remain unchanged")

		// Verify old UID is completely removed from servicePIDs
		assert.NotContains(t, tracker.servicePIDs, oldUID, "Old UID should be removed from servicePIDs")
		assert.Contains(t, tracker.servicePIDs, newUID, "New UID should exist in servicePIDs")
		assert.Len(t, tracker.servicePIDs[newUID], 2, "New UID should have 2 PIDs")
	})

	t.Run("update non-existent service UID", func(t *testing.T) {
		tracker := NewPidServiceTracker()
		nonExistentUID := makeUID("non-existent", "namespace1")
		newUID := makeUID("new-service", "namespace1")

		// Try to update non-existent UID - should be no-op
		tracker.ReplaceUID(nonExistentUID, newUID)

		// Verify no changes occurred
		assert.Equal(t, 0, tracker.Count(), "Count should remain 0")
		assert.False(t, tracker.ServiceLive(nonExistentUID), "Non-existent UID should not be live")
		assert.False(t, tracker.ServiceLive(newUID), "New UID should not be live")
	})

	t.Run("update UID with multiple services", func(t *testing.T) {
		tracker := NewPidServiceTracker()
		uid1 := makeUID("service1", "namespace1")
		uid2 := makeUID("service2", "namespace2")
		newUID := makeUID("updated-service1", "namespace1")
		pid1 := int32(1001)
		pid2 := int32(1002)
		pid3 := int32(1003)

		// Add PIDs to different UIDs
		tracker.AddPID(pid1, uid1)
		tracker.AddPID(pid2, uid1)
		tracker.AddPID(pid3, uid2)

		// Update only uid1
		tracker.ReplaceUID(uid1, newUID)

		// Verify uid1 PIDs are updated
		gotUID, exists := tracker.TracksPID(pid1)
		assert.True(t, exists)
		assert.Equal(t, newUID, gotUID)

		gotUID, exists = tracker.TracksPID(pid2)
		assert.True(t, exists)
		assert.Equal(t, newUID, gotUID)

		// Verify uid2 PID is unchanged
		gotUID, exists = tracker.TracksPID(pid3)
		assert.True(t, exists)
		assert.Equal(t, uid2, gotUID, "uid2 should remain unchanged")

		// Verify service states
		assert.False(t, tracker.ServiceLive(uid1), "Original uid1 should not be live")
		assert.True(t, tracker.ServiceLive(newUID), "New UID should be live")
		assert.True(t, tracker.ServiceLive(uid2), "uid2 should still be live")

		assert.Equal(t, 3, tracker.Count(), "Count should remain 3")
	})

	t.Run("update UID to same UID", func(t *testing.T) {
		tracker := NewPidServiceTracker()
		uid := makeUID("same-service", "namespace1")
		pid1 := int32(1001)

		tracker.AddPID(pid1, uid)

		// Update to same UID (edge case)
		tracker.ReplaceUID(uid, uid)

		// Verify state remains consistent
		gotUID, exists := tracker.TracksPID(pid1)
		assert.True(t, exists)
		assert.Equal(t, uid, gotUID)
		assert.True(t, tracker.ServiceLive(uid))
		assert.Equal(t, 1, tracker.Count())
	})
}
