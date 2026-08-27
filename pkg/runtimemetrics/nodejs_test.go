// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	nodejsruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestNodejsCounterDelta(t *testing.T) {
	assert.Equal(t, uint64(5_000_000_000), NodejsCounterDelta(false, 0, 5_000_000_000))            // first sample counts fully
	assert.Equal(t, uint64(3_000_000_000), NodejsCounterDelta(true, 5_000_000_000, 8_000_000_000)) // normal delta
	assert.Equal(t, uint64(2_000_000_000), NodejsCounterDelta(true, 8_000_000_000, 2_000_000_000)) // reset counts current
	assert.Equal(t, uint64(0), NodejsCounterDelta(true, 8_000_000_000, 8_000_000_000))             // no change
	// a sub-tolerance regression (float64 encoding jitter) is clamped to
	// zero instead of being misread as a counter reset
	assert.Equal(t, uint64(0), NodejsCounterDelta(true, 8_000_000_000, 8_000_000_000-500))
}

func testNodejsRuntimeEvent() nodejsruntime.NodejsRuntimeEvent {
	return nodejsruntime.NodejsRuntimeEvent{
		PID:            app.PID(55),
		PIDNamespaceID: 99,
		Service:        svc.Attrs{UID: svc.UID{Name: "node-svc"}},
		Time:           time.Now(),
		NodejsEventLoopValues: nodejsruntime.NodejsEventLoopValues{
			ELUIdleNs:   1_000_000_000,
			ELUActiveNs: 250_000_000,
			DelayP99Ns:  13_300_000,
			DelayCount:  181,
		},
	}
}

func TestSnapshotFromNodejsRuntimeEvent(t *testing.T) {
	event := testNodejsRuntimeEvent()

	snapshot := SnapshotFromNodejsRuntimeEvent(event)

	assert.Equal(t, event.Service, snapshot.Service)
	assert.Equal(t, event.PID, snapshot.PID)
	assert.Equal(t, event.Time, snapshot.Time)
	require.NotNil(t, snapshot.Nodejs)
	assert.Equal(t, event.NodejsEventLoopValues, snapshot.Nodejs.NodejsEventLoopValues)
	assert.Nil(t, snapshot.Go)
	assert.Nil(t, snapshot.JVM)
}

func TestQueueSenderSendsNodejsRuntimeMetrics(t *testing.T) {
	queue := msg.NewQueue[[]RuntimeMetricSnapshot](msg.ChannelBufferLen(1))
	input := queue.Subscribe()
	sender := NewQueueSender(queue)

	sender.SendNodejsRuntimeMetrics(context.Background(), []nodejsruntime.NodejsRuntimeEvent{testNodejsRuntimeEvent()})

	select {
	case snapshots := <-input:
		require.Len(t, snapshots, 1)
		require.NotNil(t, snapshots[0].Nodejs)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for nodejs runtime snapshot")
	}
}

func TestQueueSenderNodejsNilSafety(_ *testing.T) {
	var sender *QueueSender
	sender.SendNodejsRuntimeMetrics(context.Background(), []nodejsruntime.NodejsRuntimeEvent{testNodejsRuntimeEvent()})
	NewQueueSender(nil).SendNodejsRuntimeMetrics(context.Background(), nil)
}

func testNodejsGCEvent() nodejsruntime.NodejsGCEvent {
	return nodejsruntime.NodejsGCEvent{
		PID:            app.PID(55),
		PIDNamespaceID: 99,
		Service:        svc.Attrs{UID: svc.UID{Name: "node-svc"}},
		Time:           time.Now(),
		GCType:         nodejsruntime.NodejsGCTypeMajor,
		DurationNs:     350_000_000,
	}
}

func testNodejsHeapSpaceEvent() nodejsruntime.NodejsHeapSpaceEvent {
	return nodejsruntime.NodejsHeapSpaceEvent{
		PID:            app.PID(55),
		PIDNamespaceID: 99,
		Service:        svc.Attrs{UID: svc.UID{Name: "node-svc"}},
		Time:           time.Now(),
		SpaceName:      "old_space",
		NodejsHeapSpaceValues: nodejsruntime.NodejsHeapSpaceValues{
			SpaceSize:          200 << 20,
			SpaceUsedSize:      150 << 20,
			SpaceAvailableSize: 30 << 20,
			PhysicalSpaceSize:  200 << 20,
		},
	}
}

func TestSnapshotFromNodejsGCEvent(t *testing.T) {
	event := testNodejsGCEvent()

	snapshot := SnapshotFromNodejsGCEvent(event)

	assert.Equal(t, event.Service, snapshot.Service)
	assert.Equal(t, event.PID, snapshot.PID)
	assert.Equal(t, event.Time, snapshot.Time)
	require.NotNil(t, snapshot.NodejsGC)
	assert.Equal(t, nodejsruntime.NodejsGCTypeMajor, snapshot.NodejsGC.GCType)
	assert.Equal(t, uint64(350_000_000), snapshot.NodejsGC.DurationNs)
	assert.Nil(t, snapshot.Nodejs)
	assert.Nil(t, snapshot.NodejsHeapSpace)
}

func TestSnapshotFromNodejsHeapSpaceEvent(t *testing.T) {
	event := testNodejsHeapSpaceEvent()

	snapshot := SnapshotFromNodejsHeapSpaceEvent(event)

	assert.Equal(t, event.Service, snapshot.Service)
	assert.Equal(t, event.PID, snapshot.PID)
	assert.Equal(t, event.Time, snapshot.Time)
	require.NotNil(t, snapshot.NodejsHeapSpace)
	assert.Equal(t, "old_space", snapshot.NodejsHeapSpace.SpaceName)
	assert.Equal(t, event.NodejsHeapSpaceValues, snapshot.NodejsHeapSpace.NodejsHeapSpaceValues)
	assert.Nil(t, snapshot.Nodejs)
	assert.Nil(t, snapshot.NodejsGC)
}

func TestQueueSenderSendsNodejsV8Metrics(t *testing.T) {
	queue := msg.NewQueue[[]RuntimeMetricSnapshot](msg.ChannelBufferLen(2))
	input := queue.Subscribe()
	sender := NewQueueSender(queue)

	sender.SendNodejsGCMetrics(context.Background(), []nodejsruntime.NodejsGCEvent{testNodejsGCEvent()})
	sender.SendNodejsHeapSpaceMetrics(context.Background(), []nodejsruntime.NodejsHeapSpaceEvent{testNodejsHeapSpaceEvent()})

	select {
	case snapshots := <-input:
		require.Len(t, snapshots, 1)
		require.NotNil(t, snapshots[0].NodejsGC)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for nodejs gc snapshot")
	}
	select {
	case snapshots := <-input:
		require.Len(t, snapshots, 1)
		require.NotNil(t, snapshots[0].NodejsHeapSpace)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for nodejs heap-space snapshot")
	}
}

func TestQueueSenderNodejsV8NilSafety(_ *testing.T) {
	var sender *QueueSender
	sender.SendNodejsGCMetrics(context.Background(), []nodejsruntime.NodejsGCEvent{testNodejsGCEvent()})
	sender.SendNodejsHeapSpaceMetrics(context.Background(), []nodejsruntime.NodejsHeapSpaceEvent{testNodejsHeapSpaceEvent()})
	NewQueueSender(nil).SendNodejsGCMetrics(context.Background(), nil)
	NewQueueSender(nil).SendNodejsHeapSpaceMetrics(context.Background(), nil)
}
