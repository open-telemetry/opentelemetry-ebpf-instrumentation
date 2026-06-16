// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func TestHandleRuntimeMetricsRecordForwardsHeapSummaryRuntimeMetric(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders", Namespace: "prod"}}
	runtimeMetrics := &fakeRuntimeMetricsSender{}
	ctx := &EBPFEventContext{RuntimeMetrics: runtimeMetrics}

	handled, err := HandleRuntimeMetricsRecord(context.Background(), ctx, &ringbuf.Record{
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

	require.Len(t, runtimeMetrics.events, 1)
	assert.Equal(t, service, runtimeMetrics.events[0].Service)
	assert.Equal(t, jvmruntime.JVMMetricObiHeapUsed, runtimeMetrics.events[0].Kind)
	assert.Equal(t, uint64(2048), runtimeMetrics.events[0].ValueBytes)
}

func TestHandleRuntimeMetricsRecordForwardsGoRuntimeMetricRecord(t *testing.T) {
	runtimeMetrics := &fakeRuntimeMetricsSender{}
	ctx := &EBPFEventContext{RuntimeMetrics: runtimeMetrics}
	filter := fakeJVMServiceFilter{}

	handled, err := HandleRuntimeMetricsRecord(context.Background(), ctx, &ringbuf.Record{
		RawSample: []byte{EventTypeGoRuntimeMetric},
	}, filter, nil)

	require.NoError(t, err)
	assert.True(t, handled)
	assert.Equal(t, 1, runtimeMetrics.goRecords)
	assert.Equal(t, filter, runtimeMetrics.goFilter)
}

func TestHandleRuntimeMetricsRecordConsumesEventsWithoutQueue(t *testing.T) {
	for _, eventType := range []byte{EventTypeGoRuntimeMetric, EventTypeJVMMemoryPoolGC} {
		handled, err := HandleRuntimeMetricsRecord(context.Background(), nil, &ringbuf.Record{
			RawSample: []byte{eventType},
		}, nil, nil)

		require.NoError(t, err)
		assert.True(t, handled)
	}
}

func TestHandleRuntimeMetricsRecordIgnoresUnknownEventTypes(t *testing.T) {
	handled, err := HandleRuntimeMetricsRecord(context.Background(), nil, &ringbuf.Record{
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

type fakeRuntimeMetricsSender struct {
	events    []jvmruntime.JVMRuntimeEvent
	goRecords int
	goFilter  ServiceFilter
}

func (s *fakeRuntimeMetricsSender) SendGoRuntimeMetricRecord(_ context.Context, _ *ringbuf.Record, filter ServiceFilter) error {
	s.goRecords++
	s.goFilter = filter
	return nil
}

func (s *fakeRuntimeMetricsSender) SendJVMRuntimeMetrics(_ context.Context, events []jvmruntime.JVMRuntimeEvent) {
	s.events = append(s.events, events...)
}
