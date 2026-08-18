// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"context"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	nodejsruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

// Guards the manual mirror of struct nodejs_eventloop_event in
// bpf/generictracer/types/nodejs.h.
func TestNodejsEventLoopRawABI(t *testing.T) {
	var raw nodejsEventLoopRawEvent
	assert.Equal(t, uintptr(120), unsafe.Sizeof(raw))
	assert.Equal(t, uintptr(0), unsafe.Offsetof(raw.Type))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(raw.Timestamp))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(raw.GlobalPid))
	assert.Equal(t, uintptr(24), unsafe.Offsetof(raw.NsPid))
	assert.Equal(t, uintptr(32), unsafe.Offsetof(raw.PidNsID))
	assert.Equal(t, uintptr(40), unsafe.Offsetof(raw.Values))
}

func nodejsRawSample(values nodejsruntime.NodejsEventLoopValues) []byte {
	raw := nodejsEventLoopRawEvent{
		Type:      EventTypeNodejsEventLoop,
		Timestamp: 12345,
		GlobalPid: 10,
		GlobalTid: 11,
		NsPid:     55,
		NsTid:     56,
		PidNsID:   99,
		Values:    values,
	}
	size := int(unsafe.Sizeof(raw))
	sample := make([]byte, size)
	copy(sample, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), size))
	return sample
}

func testNodejsEventLoopValues() nodejsruntime.NodejsEventLoopValues {
	return nodejsruntime.NodejsEventLoopValues{
		ELUIdleNs:     1_000_000_000,
		ELUActiveNs:   250_000_000,
		DelayMinNs:    9_000_000,
		DelayMaxNs:    153_000_000,
		DelayMeanNs:   12_000_000,
		DelayStddevNs: 10_000_000,
		DelayP50Ns:    11_000_000,
		DelayP90Ns:    12_700_000,
		DelayP99Ns:    13_300_000,
		DelayCount:    181,
	}
}

func TestParseNodejsEventLoopRecord(t *testing.T) {
	values := testNodejsEventLoopValues()

	event, err := ParseNodejsEventLoopRecord(&ringbuf.Record{RawSample: nodejsRawSample(values)})
	require.NoError(t, err)

	assert.Equal(t, app.PID(55), event.PID)
	assert.Equal(t, uint32(99), event.PIDNamespaceID)
	assert.Equal(t, values, event.NodejsEventLoopValues)
	assert.False(t, event.Time.IsZero())
}

func TestParseNodejsEventLoopRecordRejectsShortSample(t *testing.T) {
	_, err := ParseNodejsEventLoopRecord(&ringbuf.Record{RawSample: []byte{EventTypeNodejsEventLoop}})
	require.Error(t, err)
}

func TestHandleRuntimeMetricsRecordSendsDecoratedNodejsEvent(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "node-svc"}}
	filter := fakeRuntimeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{
		99: {55: service},
	}}
	sender := &fakeRuntimeMetricsSender{}
	eventCtx := &EBPFEventContext{RuntimeMetrics: sender}

	handled, err := HandleRuntimeMetricsRecord(context.Background(), eventCtx, &ringbuf.Record{
		RawSample: nodejsRawSample(testNodejsEventLoopValues()),
	}, filter, nil)

	require.NoError(t, err)
	assert.True(t, handled)
	require.Len(t, sender.nodejsEvents, 1)
	assert.Equal(t, "node-svc", sender.nodejsEvents[0].Service.UID.Name)
	assert.Equal(t, testNodejsEventLoopValues(), sender.nodejsEvents[0].NodejsEventLoopValues)
}

func TestHandleRuntimeMetricsRecordDropsUnmatchedNodejsEvent(t *testing.T) {
	sender := &fakeRuntimeMetricsSender{}
	eventCtx := &EBPFEventContext{RuntimeMetrics: sender}

	handled, err := HandleRuntimeMetricsRecord(context.Background(), eventCtx, &ringbuf.Record{
		RawSample: nodejsRawSample(testNodejsEventLoopValues()),
	}, fakeRuntimeServiceFilter{}, nil)

	require.NoError(t, err)
	assert.True(t, handled)
	assert.Empty(t, sender.nodejsEvents)
}
