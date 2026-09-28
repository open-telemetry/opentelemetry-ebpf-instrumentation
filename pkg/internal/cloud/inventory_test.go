// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"context"
	"errors"
	"testing"

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

func TestInventoryRefresherNodeWithoutMetadata(t *testing.T) {
	for _, inventory := range []*Inventory{nil, NewInventory(nil)} {
		run, err := InventoryRefresherNode(inventory, 0)(t.Context())
		require.NoError(t, err)
		run(t.Context())
	}
}
