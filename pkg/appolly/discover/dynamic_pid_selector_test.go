// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func TestDynamicPIDSelector_AddPIDs_RemovePIDs_GetPIDs(t *testing.T) {
	d := NewDynamicPIDSelector()
	pids, ok := d.GetPIDs()
	assert.False(t, ok)
	assert.Nil(t, pids)

	d.AddPIDs(1, 2, 3)
	pids, ok = d.GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{1, 2, 3}, pids)

	d.AddPIDs(2, 3, 4)
	pids, ok = d.GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{1, 2, 3, 4}, pids)

	d.RemovePIDs(2, 4)
	pids, ok = d.GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{1, 3}, pids)

	d.RemovePIDs(1, 3)
	pids, ok = d.GetPIDs()
	assert.False(t, ok)
	assert.Nil(t, pids)
}

func TestDynamicPIDSelector_RemovePIDs_Notify(t *testing.T) {
	d := NewDynamicPIDSelector()
	d.AddPIDs(42, 100)
	ch := d.RemovedNotify()

	d.RemovePIDs(100)
	got := <-ch
	assert.Equal(t, []app.PID{100}, got)

	d.RemovePIDs(42)
	got = <-ch
	assert.Equal(t, []app.PID{42}, got)
}

func TestDynamicPIDSelector_AddPIDs_Notify(t *testing.T) {
	d := NewDynamicPIDSelector()
	ch := d.AddedPIDsNotify()

	d.AddPIDs(42, 100)
	got := <-ch
	assert.Equal(t, []app.PID{42, 100}, got)

	// Adding already-present PIDs does not notify
	d.AddPIDs(42)
	select {
	case <-ch:
		t.Fatal("expected no send when adding existing PID")
	default:
	}
	// New PIDs only
	d.AddPIDs(42, 99)
	got = <-ch
	assert.Equal(t, []app.PID{99}, got)
}

// TestDynamicPIDSelector_QueueNoDrop verifies that rapid AddPIDs/RemovePIDs accumulate
// in a single pending slice and are sent together when the consumer drains (no drops).
func TestDynamicPIDSelector_QueueNoDrop(t *testing.T) {
	d := NewDynamicPIDSelector()
	d.AddPIDs(1, 2, 3, 4)
	removedCh := d.RemovedNotify()
	addedCh := d.AddedPIDsNotify()

	// Drain the initial AddPIDs(1,2,3,4)
	<-addedCh

	d.RemovePIDs(1)
	d.RemovePIDs(2, 3)
	gotRemoved := <-removedCh
	assert.ElementsMatch(t, []app.PID{1, 2, 3}, gotRemoved)

	d.AddPIDs(10, 20)
	d.AddPIDs(30)
	gotAdded := <-addedCh
	assert.ElementsMatch(t, []app.PID{10, 20, 30}, gotAdded)
}
