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
