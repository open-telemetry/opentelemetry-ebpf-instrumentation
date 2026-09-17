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
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/selection"
)

const (
	dynamicPIDNotifyBufferSize = dynamicNotifyBufferSize
	dynamicPIDNotifyPendingMax = dynamicNotifyPendingMax
)

func newDynamicPIDSubscriber(ctx context.Context, maxPending int) *dynamicBatchSubscriber[app.PID] {
	return newDynamicBatchSubscriber[app.PID](ctx, maxPending)
}

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

func TestDynamicSelector_AddPIDs_RemovePIDs_GetPIDs(t *testing.T) {
	d := NewDynamicSelector()
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

func TestDynamicSelector_Subviews(t *testing.T) {
	d := NewDynamicSelector()

	d.Traces().AddPIDs(1, 2)
	d.AppMetrics().AddPIDs(2, 3)
	d.NetworkMetrics().AddPIDs(4)
	d.StatsMetrics().AddPIDs(5)

	rootPIDs, ok := d.GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{1, 2, 3, 4, 5}, rootPIDs)

	tracesPIDs, ok := d.Traces().GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{1, 2}, tracesPIDs)

	appMetricPIDs, ok := d.AppMetrics().GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{2, 3}, appMetricPIDs)

	appSignalPIDs, ok := d.appSignals().GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{1, 2, 3}, appSignalPIDs)

	assert.True(t, d.Traces().IncludesPID(1))
	assert.False(t, d.Traces().IncludesPID(3))
	assert.True(t, d.AppMetrics().IncludesPID(3))
	assert.False(t, d.NetworkMetrics().IncludesPID(3))
}

func TestDynamicSelector_AppUnionNotifications(t *testing.T) {
	d := NewDynamicSelector()
	tracesAdded := d.Traces().AddedPIDsNotify()
	metricsAdded := d.AppMetrics().AddedPIDsNotify()
	appAdded := d.appSignals().AddedPIDsNotify()
	rootAdded := d.AddedPIDsNotify()

	d.Traces().AddPIDs(42)
	assert.Equal(t, []app.PID{42}, <-tracesAdded)
	assert.Equal(t, []app.PID{42}, <-appAdded)
	assert.Equal(t, []app.PID{42}, <-rootAdded)

	d.AppMetrics().AddPIDs(42)
	assert.Equal(t, []app.PID{42}, <-metricsAdded)
	select {
	case <-appAdded:
		t.Fatal("expected no app-union add when PID already selected for traces")
	default:
	}
	select {
	case <-rootAdded:
		t.Fatal("expected no root add when PID already selected by another signal")
	default:
	}

	tracesRemoved := d.Traces().RemovedNotify()
	metricsRemoved := d.AppMetrics().RemovedNotify()
	appRemoved := d.appSignals().RemovedNotify()
	rootRemoved := d.RemovedNotify()

	d.Traces().RemovePIDs(42)
	assert.Equal(t, []app.PID{42}, <-tracesRemoved)
	select {
	case <-appRemoved:
		t.Fatal("expected no app-union remove while metrics still selected")
	default:
	}
	select {
	case <-rootRemoved:
		t.Fatal("expected no root remove while another signal still selected")
	default:
	}

	d.AppMetrics().RemovePIDs(42)
	assert.Equal(t, []app.PID{42}, <-metricsRemoved)
	assert.Equal(t, []app.PID{42}, <-appRemoved)
	assert.Equal(t, []app.PID{42}, <-rootRemoved)
}

func TestDynamicSelector_NotifyBroadcastsToAllSubscribers(t *testing.T) {
	d := NewDynamicSelector()
	addedOne := d.AddedPIDsNotify()
	addedTwo := d.AddedPIDsNotify()
	removedOne := d.RemovedNotify()
	removedTwo := d.RemovedNotify()

	d.AddPIDs(42)
	assert.Equal(t, []app.PID{42}, <-addedOne)
	assert.Equal(t, []app.PID{42}, <-addedTwo)

	d.RemovePIDs(42)
	assert.Equal(t, []app.PID{42}, <-removedOne)
	assert.Equal(t, []app.PID{42}, <-removedTwo)
}

func waitNotifyBufferLen(t *testing.T, ch <-chan []app.PID, want int) {
	t.Helper()
	require.Eventually(t, func() bool {
		return len(ch) == want
	}, 2*time.Second, 10*time.Millisecond)
}

func readPIDNotifyBatch(t *testing.T, ch <-chan []app.PID) []app.PID {
	t.Helper()
	select {
	case batch := <-ch:
		return batch
	case <-time.After(2 * time.Second):
		t.Fatal("timeout reading notify batch")
	}
	return nil
}

func TestDynamicSelector_AddedNotifyDoesNotBlockBehindFullSubscriber(t *testing.T) {
	d := NewDynamicSelector()
	stale := d.AddedPIDsNotify()

	for pid := uint32(1); pid <= dynamicPIDNotifyBufferSize; pid++ {
		d.AddPIDs(pid)
		waitNotifyBufferLen(t, stale, int(pid))
	}

	active := d.AddedPIDsNotify()
	d.AddPIDs(dynamicPIDNotifyBufferSize + 1)
	assert.Equal(t, []app.PID{dynamicPIDNotifyBufferSize + 1}, readPIDNotifyBatch(t, active))

	for pid := app.PID(1); pid <= dynamicPIDNotifyBufferSize; pid++ {
		assert.Equal(t, []app.PID{pid}, readPIDNotifyBatch(t, stale))
	}
	assert.Equal(t, []app.PID{dynamicPIDNotifyBufferSize + 1}, readPIDNotifyBatch(t, stale))
}

func TestDynamicSelector_RemovedNotifyDoesNotBlockBehindFullSubscriber(t *testing.T) {
	d := NewDynamicSelector()
	for pid := uint32(1); pid <= dynamicPIDNotifyBufferSize+1; pid++ {
		d.AddPIDs(pid)
	}
	stale := d.RemovedNotify()

	for pid := uint32(1); pid <= dynamicPIDNotifyBufferSize; pid++ {
		d.RemovePIDs(pid)
		waitNotifyBufferLen(t, stale, int(pid))
	}

	active := d.RemovedNotify()
	d.RemovePIDs(dynamicPIDNotifyBufferSize + 1)
	assert.Equal(t, []app.PID{dynamicPIDNotifyBufferSize + 1}, readPIDNotifyBatch(t, active))

	for pid := app.PID(1); pid <= dynamicPIDNotifyBufferSize; pid++ {
		assert.Equal(t, []app.PID{pid}, readPIDNotifyBatch(t, stale))
	}
	assert.Equal(t, []app.PID{dynamicPIDNotifyBufferSize + 1}, readPIDNotifyBatch(t, stale))
}

func TestDynamicPIDSubscriber_BoundsLegacyFullSubscriberBacklog(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	subscriber := newDynamicPIDSubscriber(ctx, dynamicPIDNotifyPendingMax)

	for pid := app.PID(1); pid <= dynamicPIDNotifyBufferSize; pid++ {
		subscriber.ch <- []app.PID{pid}
	}
	subscriber.notify([]app.PID{dynamicPIDNotifyBufferSize + 1})

	require.Eventually(t, func() bool {
		subscriber.mu.Lock()
		defer subscriber.mu.Unlock()
		return len(subscriber.pending) == 0
	}, 2*time.Second, 10*time.Millisecond)

	var batch []app.PID
	for pid := app.PID(dynamicPIDNotifyBufferSize + 2); pid <= dynamicPIDNotifyBufferSize+dynamicPIDNotifyPendingMax+20; pid++ {
		batch = append(batch, pid)
	}
	subscriber.notify(batch)

	subscriber.mu.Lock()
	assert.Len(t, subscriber.pending, dynamicPIDNotifyPendingMax)
	subscriber.mu.Unlock()

	cancel()
	<-subscriber.done
}

func TestDynamicPIDSubscriber_ContextSubscriberQueuesBeyondLegacyLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	subscriber := newDynamicPIDSubscriber(ctx, 0)

	for pid := app.PID(1); pid <= dynamicPIDNotifyBufferSize; pid++ {
		subscriber.ch <- []app.PID{pid}
	}
	subscriber.notify([]app.PID{dynamicPIDNotifyBufferSize + 1})

	require.Eventually(t, func() bool {
		subscriber.mu.Lock()
		defer subscriber.mu.Unlock()
		return len(subscriber.pending) == 0
	}, 2*time.Second, 10*time.Millisecond)

	var batch []app.PID
	for pid := app.PID(dynamicPIDNotifyBufferSize + 2); pid <= dynamicPIDNotifyBufferSize+dynamicPIDNotifyPendingMax+20; pid++ {
		batch = append(batch, pid)
	}
	subscriber.notify(batch)

	subscriber.mu.Lock()
	assert.Equal(t, batch, subscriber.pending)
	subscriber.mu.Unlock()

	cancel()
	<-subscriber.done
}

func TestDynamicPIDSubscriber_PreservesDuplicatePendingPIDEdges(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	subscriber := newDynamicPIDSubscriber(ctx, 0)

	for pid := app.PID(1); pid <= dynamicPIDNotifyBufferSize; pid++ {
		subscriber.ch <- []app.PID{pid}
	}
	subscriber.notify([]app.PID{dynamicPIDNotifyBufferSize + 1})

	require.Eventually(t, func() bool {
		subscriber.mu.Lock()
		defer subscriber.mu.Unlock()
		return len(subscriber.pending) == 0
	}, 2*time.Second, 10*time.Millisecond)

	batch := []app.PID{
		dynamicPIDNotifyBufferSize + 2,
		dynamicPIDNotifyBufferSize + 2,
		dynamicPIDNotifyBufferSize + 3,
	}
	subscriber.notify(batch)

	subscriber.mu.Lock()
	assert.Equal(t, batch, subscriber.pending)
	subscriber.mu.Unlock()

	cancel()
	<-subscriber.done
}

func TestDynamicSelector_NotifyContextRemovesSubscriberOnCancel(t *testing.T) {
	d := NewDynamicSelector()
	ctx, cancel := context.WithCancel(t.Context())
	added := d.AddedPIDsNotifyContext(ctx)
	removed := d.RemovedNotifyContext(ctx)

	cancel()

	require.Eventually(t, func() bool {
		d.rootView.notifier.added.mu.Lock()
		defer d.rootView.notifier.added.mu.Unlock()
		return len(d.rootView.notifier.added.subscribers) == 0
	}, 2*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		d.rootView.notifier.removed.mu.Lock()
		defer d.rootView.notifier.removed.mu.Unlock()
		return len(d.rootView.notifier.removed.subscribers) == 0
	}, 2*time.Second, 10*time.Millisecond)

	_, ok := <-added
	assert.False(t, ok)
	_, ok = <-removed
	assert.False(t, ok)
}

func TestDynamicSelector_RemovePIDs_Notify(t *testing.T) {
	d := NewDynamicSelector()
	d.AddPIDs(42, 100)
	ch := d.RemovedNotify()

	d.RemovePIDs(100)
	got := <-ch
	assert.Equal(t, []app.PID{100}, got)

	d.RemovePIDs(42)
	got = <-ch
	assert.Equal(t, []app.PID{42}, got)
}

func TestDynamicSelector_AddPIDs_Notify(t *testing.T) {
	d := NewDynamicSelector()
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

// TestDynamicSelector_QueueNoDrop verifies that rapid AddPIDs/RemovePIDs are all delivered
// on the notify channels (nothing dropped). With a buffered notify channel, one logical burst can
// span multiple receives; the consumer must drain until the expected multiset is complete.
func TestDynamicSelector_QueueNoDrop(t *testing.T) {
	d := NewDynamicSelector()
	removedCh := d.RemovedNotify()
	addedCh := d.AddedPIDsNotify()

	d.AddPIDs(1, 2, 3, 4)
	readPIDNotifyBatchesUntil(t, addedCh, []app.PID{1, 2, 3, 4})

	d.RemovePIDs(1)
	d.RemovePIDs(2, 3)
	readPIDNotifyBatchesUntil(t, removedCh, []app.PID{1, 2, 3})

	d.AddPIDs(10, 20)
	d.AddPIDs(30)
	readPIDNotifyBatchesUntil(t, addedCh, []app.PID{10, 20, 30})
}

// TestDynamicSelector_NoNotifyWithoutSubscribers checks that adds before any subscriber are
// not replayed later; callers recover current membership via GetPIDs.
func TestDynamicSelector_NoNotifyWithoutSubscribers(t *testing.T) {
	d := NewDynamicSelector()
	d.AddPIDs(1, 2, 3)

	ch := d.AddedPIDsNotify()
	select {
	case got := <-ch:
		t.Fatalf("expected no replay of pre-subscribe adds, got %v", got)
	default:
	}

	pids, ok := d.GetPIDs()
	require.True(t, ok)
	assert.ElementsMatch(t, []app.PID{1, 2, 3}, pids)
}

func TestDynamicSelector_AddPID_WithOptions(t *testing.T) {
	d := NewDynamicSelector()
	d.Traces().AddPID(42, selection.DynamicOptions{
		ServiceName:      "custom-svc",
		ServiceNamespace: "custom-ns",
		ResourceAttributes: map[string]string{
			"deployment.environment": "staging",
		},
	})

	entry, ok := d.GetPID(42)
	require.True(t, ok)
	assert.Equal(t, app.PID(42), entry.PID)
	assert.Equal(t, "custom-svc", entry.ServiceName)
	assert.Equal(t, "custom-ns", entry.ServiceNamespace)
	assert.Equal(t, "staging", entry.ResourceAttributes["deployment.environment"])
	assert.True(t, d.Traces().IncludesPID(42))
	assert.False(t, d.AppMetrics().IncludesPID(42))

	selector := d.appSignals().SelectorForPID(42)
	require.NotNil(t, selector)
	assert.Equal(t, "custom-svc", selector.GetName())
	attrs := ResourceAttributesFromSelector(selector)
	assert.Equal(t, "staging", attrs[attr.Name("deployment.environment")])
}

func TestDynamicSelector_GetPID_SetPID(t *testing.T) {
	d := NewDynamicSelector()
	d.AddPIDs(42)

	entry, ok := d.GetPID(42)
	require.True(t, ok)
	assert.Equal(t, app.PID(42), entry.PID)
	assert.Empty(t, entry.ServiceName)

	entry.ServiceName = "my app"
	entry.ResourceAttributes = map[string]string{"team": "platform"}
	require.True(t, d.SetPID(entry))

	updated, ok := d.GetPID(42)
	require.True(t, ok)
	assert.Equal(t, "my app", updated.ServiceName)
	assert.Equal(t, "platform", updated.ResourceAttributes["team"])

	assert.False(t, d.SetPID(selection.DynamicPIDEntry{PID: 99, ServiceName: "missing"}))
}

func TestDynamicSelector_AddPID_UpdatesExistingAttributes(t *testing.T) {
	d := NewDynamicSelector()
	d.Traces().AddPID(42, selection.DynamicOptions{ServiceName: "first"})
	d.Traces().AddPID(42, selection.DynamicOptions{ServiceName: "updated"})

	entry, ok := d.GetPID(42)
	require.True(t, ok)
	assert.Equal(t, "updated", entry.ServiceName)
}

func TestDynamicSelector_AttributesSharedAcrossSignals(t *testing.T) {
	d := NewDynamicSelector()
	d.Traces().AddPID(42, selection.DynamicOptions{ServiceName: "shared-svc"})

	d.AppMetrics().AddPIDs(42)
	entry, ok := d.GetPID(42)
	require.True(t, ok)
	assert.Equal(t, "shared-svc", entry.ServiceName)
	assert.True(t, d.Traces().IncludesPID(42))
	assert.True(t, d.AppMetrics().IncludesPID(42))
}

func TestDynamicSelector_SetPID_UpdatesFileInfo(t *testing.T) {
	d := NewDynamicSelector()
	d.AddPIDs(42)

	fi := exec.New(exec.Init{
		Pid: 42,
		Service: svc.Attrs{
			UID:                svc.UID{Name: "old"},
			DynamicSelectorPID: 42,
		},
	})
	d.RegisterFileInfo(42, fi)

	entry := selection.DynamicPIDEntry{
		PID:         42,
		ServiceName: "live-svc",
		ResourceAttributes: map[string]string{
			"team": "payments",
		},
	}
	require.True(t, d.SetPID(entry))

	snap := fi.ServiceAttrs()
	assert.Equal(t, "live-svc", snap.UID.Name)
	assert.Equal(t, "payments", snap.Metadata["team"])
}

func TestDynamicSelector_SetPID_NotifiesFileInfoUpdate(t *testing.T) {
	d := NewDynamicSelector()
	d.AddPIDs(42)

	fi := exec.New(exec.Init{Pid: 42, Service: svc.Attrs{DynamicSelectorPID: 42}})
	d.RegisterFileInfo(42, fi)

	var notified *exec.FileInfo
	d.SetOnFileInfoUpdated(func(updated *exec.FileInfo) { notified = updated })

	require.True(t, d.SetPID(selection.DynamicPIDEntry{
		PID:         42,
		ServiceName: "metrics-svc",
	}))
	assert.Same(t, fi, notified)
}

func TestDynamicSelector_SetPID_NotifiesAttrsUpdated(t *testing.T) {
	d := NewDynamicSelector()
	d.AddPIDs(7)

	ch := d.AttrsUpdatedNotify()
	require.True(t, d.SetPID(selection.DynamicPIDEntry{PID: 7, ServiceName: "net-svc"}))

	select {
	case pid := <-ch:
		assert.Equal(t, app.PID(7), pid)
	default:
		t.Fatal("expected attrs updated notification")
	}
}
