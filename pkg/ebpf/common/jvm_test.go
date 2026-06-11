// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func TestHandleJVMRuntimeMetricRecordForwardsHeapSummaryEvent(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders", Namespace: "prod"}}
	events := msg.NewQueue[[]jvmruntime.JVMRuntimeEvent](msg.ChannelBufferLen(1))
	received := events.Subscribe(msg.SubscriberName("jvm-common-test"))
	ctx := &EBPFEventContext{JVMRuntimeEvents: events}

	handled, err := HandleJVMRuntimeMetricRecord(context.Background(), ctx, &ringbuf.Record{
		RawSample: jvmBinaryPayload(t, jvmruntime.RawJVMGCHeapSummaryEvent{
			Type:           EventTypeJVMGCHeapSummary,
			Timestamp:      100,
			NsPID:          1234,
			PIDNamespaceID: 42,
			GCWhenType:     jvmruntime.RawJVMGCWhenAfter,
			Used:           2048,
		}),
	}, fakeJVMServiceFilter{
		current: map[uint32]map[app.PID]svc.Attrs{
			42: {1234: service},
		},
	}, nil)

	require.NoError(t, err)
	assert.True(t, handled)

	select {
	case batch := <-received:
		require.Len(t, batch, 1)
		assert.Equal(t, service, batch[0].Service)
		assert.Equal(t, jvmruntime.JVMMetricBeylaHeapUsed, batch[0].Kind)
		assert.Equal(t, uint64(2048), batch[0].ValueBytes)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for JVM runtime event")
	}
}

func TestHandleJVMRuntimeMetricRecordConsumesEventsWithoutQueue(t *testing.T) {
	handled, err := HandleJVMRuntimeMetricRecord(context.Background(), nil, &ringbuf.Record{
		RawSample: []byte{EventTypeJVMMemoryPoolGC},
	}, nil, nil)

	require.NoError(t, err)
	assert.True(t, handled)
}

func TestHandleJVMRuntimeMetricRecordIgnoresUnknownEventTypes(t *testing.T) {
	handled, err := HandleJVMRuntimeMetricRecord(context.Background(), nil, &ringbuf.Record{
		RawSample: []byte{EventTypeDNS},
	}, nil, nil)

	require.NoError(t, err)
	assert.False(t, handled)
}

func jvmBinaryPayload(t *testing.T, raw any) []byte {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, raw))
	return buf.Bytes()
}

type fakeJVMServiceFilter struct {
	current map[uint32]map[app.PID]svc.Attrs
}

func (f fakeJVMServiceFilter) AllowPID(app.PID, uint32, *exec.FileInfo, PIDType) {}
func (f fakeJVMServiceFilter) BlockPID(app.PID, uint32)                          {}
func (f fakeJVMServiceFilter) ValidPID(app.PID, uint32, PIDType) bool            { return false }
func (f fakeJVMServiceFilter) Filter(inputSpans []request.Span) []request.Span   { return inputSpans }
func (f fakeJVMServiceFilter) CurrentPIDs(PIDType) map[uint32]map[app.PID]svc.Attrs {
	return f.current
}
