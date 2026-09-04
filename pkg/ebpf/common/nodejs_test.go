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

// Guards the manual mirror of struct nodejs_gc_event in
// bpf/generictracer/types/nodejs.h.
func TestNodejsGCRawABI(t *testing.T) {
	var raw nodejsGCRawEvent
	assert.Equal(t, uintptr(48), unsafe.Sizeof(raw))
	assert.Equal(t, uintptr(0), unsafe.Offsetof(raw.Type))
	assert.Equal(t, uintptr(1), unsafe.Offsetof(raw.Kind))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(raw.Timestamp))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(raw.GlobalPid))
	assert.Equal(t, uintptr(24), unsafe.Offsetof(raw.NsPid))
	assert.Equal(t, uintptr(32), unsafe.Offsetof(raw.PidNsID))
	assert.Equal(t, uintptr(40), unsafe.Offsetof(raw.DurationNs))
}

// Guards the manual mirror of struct nodejs_heap_space_event in
// bpf/generictracer/types/nodejs.h.
func TestNodejsHeapSpaceRawABI(t *testing.T) {
	var raw nodejsHeapSpaceRawEvent
	assert.Equal(t, uintptr(104), unsafe.Sizeof(raw))
	assert.Equal(t, uintptr(0), unsafe.Offsetof(raw.Type))
	assert.Equal(t, uintptr(1), unsafe.Offsetof(raw.NameLen))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(raw.Timestamp))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(raw.GlobalPid))
	assert.Equal(t, uintptr(32), unsafe.Offsetof(raw.PidNsID))
	assert.Equal(t, uintptr(40), unsafe.Offsetof(raw.SpaceSize))
	assert.Equal(t, uintptr(72), unsafe.Offsetof(raw.SpaceName))
}

func nodejsGCRawSample(kind uint8, durationNs uint64) []byte {
	raw := nodejsGCRawEvent{
		Type:       EventTypeNodejsGC,
		Kind:       kind,
		Timestamp:  12345,
		GlobalPid:  10,
		GlobalTid:  11,
		NsPid:      55,
		NsTid:      56,
		PidNsID:    99,
		DurationNs: durationNs,
	}
	size := int(unsafe.Sizeof(raw))
	sample := make([]byte, size)
	copy(sample, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), size))
	return sample
}

func nodejsHeapSpaceRawSample(name string, values nodejsruntime.NodejsHeapSpaceValues) []byte {
	raw := nodejsHeapSpaceRawEvent{
		Type:               EventTypeNodejsHeapSpace,
		NameLen:            uint8(len(name)),
		Timestamp:          12345,
		GlobalPid:          10,
		GlobalTid:          11,
		NsPid:              55,
		NsTid:              56,
		PidNsID:            99,
		SpaceSize:          values.SpaceSize,
		SpaceUsedSize:      values.SpaceUsedSize,
		SpaceAvailableSize: values.SpaceAvailableSize,
		PhysicalSpaceSize:  values.PhysicalSpaceSize,
	}
	copy(raw.SpaceName[:], name)
	size := int(unsafe.Sizeof(raw))
	sample := make([]byte, size)
	copy(sample, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), size))
	return sample
}

func testNodejsHeapSpaceValues() nodejsruntime.NodejsHeapSpaceValues {
	return nodejsruntime.NodejsHeapSpaceValues{
		SpaceSize:          200 << 20,
		SpaceUsedSize:      150 << 20,
		SpaceAvailableSize: 30 << 20,
		PhysicalSpaceSize:  200 << 20,
	}
}

func TestParseNodejsGCRecord(t *testing.T) {
	event, err := ParseNodejsGCRecord(&ringbuf.Record{RawSample: nodejsGCRawSample(2, 350_000_000)})
	require.NoError(t, err)

	assert.Equal(t, app.PID(55), event.PID)
	assert.Equal(t, uint32(99), event.PIDNamespaceID)
	assert.Equal(t, nodejsruntime.NodejsGCTypeMajor, event.GCType)
	assert.Equal(t, uint64(350_000_000), event.DurationNs)
	assert.False(t, event.Time.IsZero())

	// unknown wire codes surface as Unknown; the dispatch layer drops them
	event, err = ParseNodejsGCRecord(&ringbuf.Record{RawSample: nodejsGCRawSample(9, 1)})
	require.NoError(t, err)
	assert.Equal(t, nodejsruntime.NodejsGCTypeUnknown, event.GCType)

	_, err = ParseNodejsGCRecord(&ringbuf.Record{RawSample: []byte{EventTypeNodejsGC}})
	require.Error(t, err, "short sample must be rejected")
}

func TestParseNodejsHeapSpaceRecord(t *testing.T) {
	values := testNodejsHeapSpaceValues()

	event, err := ParseNodejsHeapSpaceRecord(&ringbuf.Record{
		RawSample: nodejsHeapSpaceRawSample("old_space", values),
	})
	require.NoError(t, err)

	assert.Equal(t, app.PID(55), event.PID)
	assert.Equal(t, uint32(99), event.PIDNamespaceID)
	assert.Equal(t, "old_space", event.SpaceName)
	assert.Equal(t, values, event.NodejsHeapSpaceValues)
	assert.False(t, event.Time.IsZero())
}

func TestParseNodejsHeapSpaceRecordRejectsBadNameLength(t *testing.T) {
	values := testNodejsHeapSpaceValues()

	sample := nodejsHeapSpaceRawSample("old_space", values)
	sample[1] = 0 // NameLen: an empty name never comes from the agent
	_, err := ParseNodejsHeapSpaceRecord(&ringbuf.Record{RawSample: sample})
	require.Error(t, err)

	sample = nodejsHeapSpaceRawSample("old_space", values)
	sample[1] = 33 // NameLen beyond the 32-byte buffer
	_, err = ParseNodejsHeapSpaceRecord(&ringbuf.Record{RawSample: sample})
	require.Error(t, err)
}

func TestHandleRuntimeMetricsRecordSendsDecoratedV8Events(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "node-svc"}}
	filter := fakeRuntimeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{
		99: {55: service},
	}}
	sender := &fakeRuntimeMetricsSender{}
	eventCtx := &EBPFEventContext{RuntimeMetrics: sender}

	handled, err := HandleRuntimeMetricsRecord(context.Background(), eventCtx, &ringbuf.Record{
		RawSample: nodejsGCRawSample(2, 350_000_000),
	}, filter, nil)
	require.NoError(t, err)
	assert.True(t, handled)
	require.Len(t, sender.nodejsGCEvents, 1)
	assert.Equal(t, "node-svc", sender.nodejsGCEvents[0].Service.UID.Name)
	assert.Equal(t, nodejsruntime.NodejsGCTypeMajor, sender.nodejsGCEvents[0].GCType)

	handled, err = HandleRuntimeMetricsRecord(context.Background(), eventCtx, &ringbuf.Record{
		RawSample: nodejsHeapSpaceRawSample("old_space", testNodejsHeapSpaceValues()),
	}, filter, nil)
	require.NoError(t, err)
	assert.True(t, handled)
	require.Len(t, sender.nodejsHeapSpaceEvents, 1)
	assert.Equal(t, "node-svc", sender.nodejsHeapSpaceEvents[0].Service.UID.Name)
	assert.Equal(t, "old_space", sender.nodejsHeapSpaceEvents[0].SpaceName)
}

// an unknown GC wire code decodes to Unknown and must be dropped at dispatch,
// not exported as a bogus v8js.gc.type value
func TestHandleRuntimeMetricsRecordDropsUnknownGCKind(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "node-svc"}}
	filter := fakeRuntimeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{
		99: {55: service},
	}}
	sender := &fakeRuntimeMetricsSender{}
	eventCtx := &EBPFEventContext{RuntimeMetrics: sender}

	handled, err := HandleRuntimeMetricsRecord(context.Background(), eventCtx, &ringbuf.Record{
		RawSample: nodejsGCRawSample(9, 1000),
	}, filter, nil)
	require.NoError(t, err)
	assert.True(t, handled)
	assert.Empty(t, sender.nodejsGCEvents)
}

// heap spaces outside the well-known semconv v8js.heap.space.name members
// (e.g. read_only_space on modern V8s) must be dropped at dispatch, never
// exported
func TestHandleRuntimeMetricsRecordDropsNonSemconvHeapSpace(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "node-svc"}}
	filter := fakeRuntimeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{
		99: {55: service},
	}}
	sender := &fakeRuntimeMetricsSender{}
	eventCtx := &EBPFEventContext{RuntimeMetrics: sender}

	handled, err := HandleRuntimeMetricsRecord(context.Background(), eventCtx, &ringbuf.Record{
		RawSample: nodejsHeapSpaceRawSample("read_only_space", testNodejsHeapSpaceValues()),
	}, filter, nil)
	require.NoError(t, err)
	assert.True(t, handled)
	assert.Empty(t, sender.nodejsHeapSpaceEvents)
}

func TestHandleRuntimeMetricsRecordDropsUnmatchedV8Events(t *testing.T) {
	sender := &fakeRuntimeMetricsSender{}
	eventCtx := &EBPFEventContext{RuntimeMetrics: sender}

	handled, err := HandleRuntimeMetricsRecord(context.Background(), eventCtx, &ringbuf.Record{
		RawSample: nodejsGCRawSample(2, 1000),
	}, fakeRuntimeServiceFilter{}, nil)
	require.NoError(t, err)
	assert.True(t, handled)
	assert.Empty(t, sender.nodejsGCEvents)

	handled, err = HandleRuntimeMetricsRecord(context.Background(), eventCtx, &ringbuf.Record{
		RawSample: nodejsHeapSpaceRawSample("old_space", testNodejsHeapSpaceValues()),
	}, fakeRuntimeServiceFilter{}, nil)
	require.NoError(t, err)
	assert.True(t, handled)
	assert.Empty(t, sender.nodejsHeapSpaceEvents)
}

// Guards the manual mirror of struct nodejs_resource_event in
// bpf/generictracer/types/nodejs.h.
func TestNodejsResourceRawABI(t *testing.T) {
	var raw nodejsResourceRawEvent
	assert.Equal(t, uintptr(80), unsafe.Sizeof(raw))
	assert.Equal(t, uintptr(0), unsafe.Offsetof(raw.Type))
	assert.Equal(t, uintptr(1), unsafe.Offsetof(raw.NameLen))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(raw.Timestamp))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(raw.GlobalPid))
	assert.Equal(t, uintptr(32), unsafe.Offsetof(raw.PidNsID))
	assert.Equal(t, uintptr(40), unsafe.Offsetof(raw.Count))
	assert.Equal(t, uintptr(48), unsafe.Offsetof(raw.ResourceType))
}

func nodejsResourceRawSample(resourceType string, count uint64) []byte {
	raw := nodejsResourceRawEvent{
		Type:      EventTypeNodejsResource,
		NameLen:   uint8(len(resourceType)),
		Timestamp: 12345,
		GlobalPid: 10,
		GlobalTid: 11,
		NsPid:     55,
		NsTid:     56,
		PidNsID:   99,
		Count:     count,
	}
	copy(raw.ResourceType[:], resourceType)
	size := int(unsafe.Sizeof(raw))
	sample := make([]byte, size)
	copy(sample, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), size))
	return sample
}

func TestParseNodejsResourceRecord(t *testing.T) {
	event, err := ParseNodejsResourceRecord(&ringbuf.Record{RawSample: nodejsResourceRawSample("Timeout", 5)})
	require.NoError(t, err)

	assert.Equal(t, app.PID(55), event.PID)
	assert.Equal(t, uint32(99), event.PIDNamespaceID)
	assert.Equal(t, "Timeout", event.ResourceType)
	assert.Equal(t, uint64(5), event.Count)
	assert.False(t, event.Time.IsZero())

	// count 0 is a valid record: the explicit zero for a type that vanished
	// since the previous sampling interval
	event, err = ParseNodejsResourceRecord(&ringbuf.Record{RawSample: nodejsResourceRawSample("Timeout", 0)})
	require.NoError(t, err)
	assert.Equal(t, uint64(0), event.Count)

	_, err = ParseNodejsResourceRecord(&ringbuf.Record{RawSample: []byte{EventTypeNodejsResource}})
	require.Error(t, err, "short sample must be rejected")
}

func TestParseNodejsResourceRecordRejectsBadNameLength(t *testing.T) {
	sample := nodejsResourceRawSample("Timeout", 1)
	sample[1] = 0 // NameLen: an empty type name never comes from the agent
	_, err := ParseNodejsResourceRecord(&ringbuf.Record{RawSample: sample})
	require.Error(t, err)

	sample = nodejsResourceRawSample("Timeout", 1)
	sample[1] = 33 // NameLen beyond the 32-byte buffer
	_, err = ParseNodejsResourceRecord(&ringbuf.Record{RawSample: sample})
	require.Error(t, err)
}

func TestHandleRuntimeMetricsRecordSendsDecoratedResourceEvent(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "node-svc"}}
	filter := fakeRuntimeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{
		99: {55: service},
	}}
	sender := &fakeRuntimeMetricsSender{}
	eventCtx := &EBPFEventContext{RuntimeMetrics: sender}

	handled, err := HandleRuntimeMetricsRecord(context.Background(), eventCtx, &ringbuf.Record{
		RawSample: nodejsResourceRawSample("Timeout", 5),
	}, filter, nil)
	require.NoError(t, err)
	assert.True(t, handled)
	require.Len(t, sender.nodejsResourceEvents, 1)
	assert.Equal(t, "node-svc", sender.nodejsResourceEvents[0].Service.UID.Name)
	assert.Equal(t, "Timeout", sender.nodejsResourceEvents[0].ResourceType)
	assert.Equal(t, uint64(5), sender.nodejsResourceEvents[0].Count)

	// the runtime spelling for TCP connections is canonicalized to the
	// semconv member and must survive the well-known filter
	handled, err = HandleRuntimeMetricsRecord(context.Background(), eventCtx, &ringbuf.Record{
		RawSample: nodejsResourceRawSample("TCPSocketWrap", 2),
	}, filter, nil)
	require.NoError(t, err)
	assert.True(t, handled)
	require.Len(t, sender.nodejsResourceEvents, 2)
	assert.Equal(t, "TCPWrap", sender.nodejsResourceEvents[1].ResourceType)
	assert.Equal(t, uint64(2), sender.nodejsResourceEvents[1].Count)
}

// resource types outside the well-known semconv v8js.resource.type members
// (e.g. FSReqCallback) must be dropped at dispatch, never exported
func TestHandleRuntimeMetricsRecordDropsNonSemconvResourceType(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "node-svc"}}
	filter := fakeRuntimeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{
		99: {55: service},
	}}
	sender := &fakeRuntimeMetricsSender{}
	eventCtx := &EBPFEventContext{RuntimeMetrics: sender}

	handled, err := HandleRuntimeMetricsRecord(context.Background(), eventCtx, &ringbuf.Record{
		RawSample: nodejsResourceRawSample("FSReqCallback", 3),
	}, filter, nil)
	require.NoError(t, err)
	assert.True(t, handled)
	assert.Empty(t, sender.nodejsResourceEvents)
}

func TestHandleRuntimeMetricsRecordDropsUnmatchedResourceEvent(t *testing.T) {
	sender := &fakeRuntimeMetricsSender{}
	eventCtx := &EBPFEventContext{RuntimeMetrics: sender}

	handled, err := HandleRuntimeMetricsRecord(context.Background(), eventCtx, &ringbuf.Record{
		RawSample: nodejsResourceRawSample("Timeout", 5),
	}, fakeRuntimeServiceFilter{}, nil)
	require.NoError(t, err)
	assert.True(t, handled)
	assert.Empty(t, sender.nodejsResourceEvents)
}

func TestDecorateNodejsResourceEvent(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "node-svc"}}
	filter := fakeRuntimeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{
		99: {55: service},
	}}

	event, err := ParseNodejsResourceRecord(&ringbuf.Record{RawSample: nodejsResourceRawSample("Timeout", 5)})
	require.NoError(t, err)
	require.True(t, DecorateNodejsResourceEvent(filter, &event))
	assert.Equal(t, "node-svc", event.Service.UID.Name)
	require.False(t, DecorateNodejsResourceEvent(fakeRuntimeServiceFilter{}, &event))
}

func TestDecorateNodejsV8Events(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "node-svc"}}
	filter := fakeRuntimeServiceFilter{current: map[uint32]map[app.PID]svc.Attrs{
		99: {55: service},
	}}

	gcEvent, err := ParseNodejsGCRecord(&ringbuf.Record{RawSample: nodejsGCRawSample(1, 1000)})
	require.NoError(t, err)
	require.True(t, DecorateNodejsGCEvent(filter, &gcEvent))
	assert.Equal(t, "node-svc", gcEvent.Service.UID.Name)
	require.False(t, DecorateNodejsGCEvent(fakeRuntimeServiceFilter{}, &gcEvent))

	heapEvent, err := ParseNodejsHeapSpaceRecord(&ringbuf.Record{
		RawSample: nodejsHeapSpaceRawSample("old_space", testNodejsHeapSpaceValues()),
	})
	require.NoError(t, err)
	require.True(t, DecorateNodejsHeapSpaceEvent(filter, &heapEvent))
	assert.Equal(t, "node-svc", heapEvent.Service.UID.Name)
	require.False(t, DecorateNodejsHeapSpaceEvent(fakeRuntimeServiceFilter{}, &heapEvent))
}
