// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type snapshotRefresher struct {
	snapshot MetadataSnapshot
	err      error
}

func (*snapshotRefresher) Name() string { return "test" }
func (r *snapshotRefresher) Refresh(_ context.Context, snapshot *MetadataSnapshot) error {
	*snapshot = r.snapshot
	return r.err
}

func TestInventoryContainerChanges(t *testing.T) {
	refresher := &snapshotRefresher{snapshot: MetadataSnapshot{
		ServiceByContainerID: map[string]string{"a": "checkout", "b": "payments"},
		ServiceByIP:          map[string]string{"127.0.0.1": "checkout"},
	}}
	inventory := NewInventory([]MetadataRefresher{refresher})
	changes := inventory.SubscribeContainerChanges()
	inventory.refresh(t.Context())
	first := <-changes
	assert.Equal(t, refresher.snapshot.ServiceByContainerID, first.Changed)
	assert.Empty(t, first.Removed)
	name, ok := inventory.ServiceNameForContainerID("a")
	require.True(t, ok)
	assert.Equal(t, "checkout", name)
	name, ok = inventory.ServiceNameForIP("::ffff:127.0.0.1")
	require.True(t, ok)
	assert.Equal(t, "checkout", name)

	inventory.refresh(t.Context())
	select {
	case change := <-changes:
		t.Fatalf("unchanged snapshot published changes: %+v", change)
	default:
	}
	refresher.snapshot.ServiceByContainerID = map[string]string{"a": "renamed", "c": "new"}
	inventory.refresh(t.Context())
	next := <-changes
	assert.Equal(t, map[string]string{"a": "renamed", "c": "new"}, next.Changed)
	assert.Equal(t, map[string]string{"b": "payments"}, next.Removed)
	_, ok = inventory.ServiceNameForContainerID("b")
	assert.False(t, ok)
}

func TestInventoryFailedRenewalRetainsMetadata(t *testing.T) {
	refresher := &snapshotRefresher{snapshot: MetadataSnapshot{
		ServiceByContainerID: map[string]string{"a": "checkout"},
	}}
	inventory := NewInventory([]MetadataRefresher{refresher})
	changes := inventory.SubscribeContainerChanges()
	inventory.refresh(t.Context())
	<-changes
	refresher.snapshot = MetadataSnapshot{}
	refresher.err = errors.New("unavailable")
	inventory.refresh(t.Context())
	name, ok := inventory.ServiceNameForContainerID("a")
	require.True(t, ok)
	assert.Equal(t, "checkout", name)
	select {
	case change := <-changes:
		t.Fatalf("failed renewal published changes: %+v", change)
	default:
	}
}

func TestInventoryRefresherNodeInitialRefresh(t *testing.T) {
	refresher := &snapshotRefresher{snapshot: MetadataSnapshot{
		ServiceByContainerID: map[string]string{"a": "checkout"},
		ServiceByIP:          map[string]string{"127.0.0.1": "checkout"},
	}}
	inventory := NewInventory([]MetadataRefresher{refresher})
	changes := inventory.SubscribeContainerChanges()

	run, err := InventoryRefresherNode(inventory, time.Hour)(t.Context())
	require.NoError(t, err)
	require.NotNil(t, run)

	name, ok := inventory.ServiceNameForContainerID("a")
	require.True(t, ok)
	assert.Equal(t, "checkout", name)
	name, ok = inventory.ServiceNameForIP("127.0.0.1")
	require.True(t, ok)
	assert.Equal(t, "checkout", name)

	select {
	case change := <-changes:
		assert.Equal(t, refresher.snapshot.ServiceByContainerID, change.Changed)
		assert.Empty(t, change.Removed)
	default:
		t.Fatal("initial refresh did not publish container changes before the node runs")
	}
}

func TestInventoryRefresherNodeWithoutMetadata(t *testing.T) {
	for _, inventory := range []*Inventory{nil, NewInventory(nil)} {
		run, err := InventoryRefresherNode(inventory, 0)(t.Context())
		require.NoError(t, err)
		run(t.Context())
	}
}

func TestInventorySourcesRefreshIndependently(t *testing.T) {
	route53 := &snapshotRefresher{snapshot: MetadataSnapshot{ServiceByIP: map[string]string{"10.0.0.1": "dns", "10.0.0.2": "dns-only"}}}
	ecs := &snapshotRefresher{snapshot: MetadataSnapshot{ServiceByIP: map[string]string{"10.0.0.1": "ecs"}}}
	inventory := NewInventory([]MetadataRefresher{route53, ecs})
	inventory.refresh(t.Context())
	name, _ := inventory.ServiceNameForIP("10.0.0.1")
	require.Equal(t, "ecs", name)

	route53.err = errors.New("throttled")
	ecs.snapshot = MetadataSnapshot{ServiceByIP: map[string]string{"10.0.0.1": "ecs-updated"}}
	inventory.refresh(t.Context())
	name, _ = inventory.ServiceNameForIP("10.0.0.1")
	require.Equal(t, "ecs-updated", name)
	name, _ = inventory.ServiceNameForIP("10.0.0.2")
	require.Equal(t, "dns-only", name)

	ecs.snapshot = MetadataSnapshot{}
	inventory.refreshSource(t.Context(), 1)
	name, _ = inventory.ServiceNameForIP("10.0.0.1")
	require.Equal(t, "dns", name)
	route53.err = nil
	route53.snapshot = MetadataSnapshot{}
	inventory.refreshSource(t.Context(), 0)
	_, ok := inventory.ServiceNameForIP("10.0.0.1")
	require.False(t, ok)
}

type blockingScheduledRefresher struct {
	started chan struct{}
	stopped chan struct{}
}

func (*blockingScheduledRefresher) Name() string                    { return "blocked" }
func (*blockingScheduledRefresher) RefreshDelay(bool) time.Duration { return 0 }
func (r *blockingScheduledRefresher) Refresh(ctx context.Context, _ *MetadataSnapshot) error {
	close(r.started)
	<-ctx.Done()
	close(r.stopped)
	return ctx.Err()
}

type notifyingRefresher struct{ calls chan struct{} }

func (*notifyingRefresher) Name() string { return "ecs" }
func (r *notifyingRefresher) Refresh(_ context.Context, snapshot *MetadataSnapshot) error {
	snapshot.ServiceByIP["10.0.0.1"] = "ecs"
	r.calls <- struct{}{}
	return nil
}

func TestInventoryPollingDoesNotWaitForOtherSources(t *testing.T) {
	blocked := &blockingScheduledRefresher{started: make(chan struct{}), stopped: make(chan struct{})}
	ecs := &notifyingRefresher{calls: make(chan struct{}, 100)}
	inventory := NewInventory([]MetadataRefresher{blocked, ecs})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	run, err := InventoryRefresherNode(inventory, time.Millisecond)(ctx)
	require.NoError(t, err)
	<-ecs.calls // ECS's initial fetch remains synchronous.
	select {
	case <-blocked.started:
		t.Fatal("scheduled discovery started synchronously")
	default:
	}
	done := make(chan struct{})
	go func() { defer close(done); run(ctx) }()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("scheduled source did not start")
	}
	select {
	case <-ecs.calls:
	case <-time.After(time.Second):
		t.Fatal("ECS polling was blocked")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("workers did not stop")
	}
	<-blocked.stopped
}
