// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/components/svc"
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
