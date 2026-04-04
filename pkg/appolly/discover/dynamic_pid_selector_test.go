// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

// pidMultisetEqual reports whether a and b contain the same PIDs with the same multiplicity.
func pidMultisetEqual(a, b []app.PID) bool {
	if len(a) != len(b) {
		return false
	}
	sa := slices.Clone(a)
	sb := slices.Clone(b)
	slices.Sort(sa)
	slices.Sort(sb)
	return slices.Equal(sa, sb)
}

// readPIDNotifyBatchesUntil reads from ch until the concatenation of batches matches want
// as a multiset (order of batches and within batches does not matter).
func readPIDNotifyBatchesUntil(t *testing.T, ch <-chan []app.PID, want []app.PID) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	var got []app.PID
	for !pidMultisetEqual(got, want) {
		if len(got) > len(want) {
			t.Fatalf("unexpected extra PID notify batches: got %v want %v", got, want)
		}
		select {
		case b := <-ch:
			got = append(got, b...)
		case <-ctx.Done():
			t.Fatalf("timeout reading notify batches: got %v want %v", got, want)
		}
	}
}

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

// TestDynamicPIDSelector_QueueNoDrop verifies that rapid AddPIDs/RemovePIDs are all delivered
// on the notify channels (nothing dropped). With a buffered notify channel, one logical burst can
// span multiple receives; the consumer must drain until the expected multiset is complete.
func TestDynamicPIDSelector_QueueNoDrop(t *testing.T) {
	d := NewDynamicPIDSelector()
	d.AddPIDs(1, 2, 3, 4)
	removedCh := d.RemovedNotify()
	addedCh := d.AddedPIDsNotify()

	<-addedCh

	d.RemovePIDs(1)
	d.RemovePIDs(2, 3)
	readPIDNotifyBatchesUntil(t, removedCh, []app.PID{1, 2, 3})

	d.AddPIDs(10, 20)
	d.AddPIDs(30)
	readPIDNotifyBatchesUntil(t, addedCh, []app.PID{10, 20, 30})
}
