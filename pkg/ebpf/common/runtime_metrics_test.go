// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	appruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func TestRuntimeMetricEventTypeABI(t *testing.T) {
	assert.Equal(t, byte(17), byte(EventTypeGoRuntimeMetric))
	assert.Equal(t, byte(19), byte(EventTypeJVMMemoryPoolGC))
	assert.Equal(t, byte(21), byte(EventTypeGoRuntimeHistogram))
}

func TestIsGoRuntimeMetricRecordRecognizesGoRuntimeEvents(t *testing.T) {
	for _, tc := range []struct {
		name     string
		record   *ringbuf.Record
		expected bool
	}{
		{name: "nil record", record: nil},
		{name: "empty record", record: &ringbuf.Record{}},
		{name: "scalar", record: &ringbuf.Record{RawSample: []byte{EventTypeGoRuntimeMetric}}, expected: true},
		{name: "histogram", record: &ringbuf.Record{RawSample: []byte{EventTypeGoRuntimeHistogram}}, expected: true},
		{name: "JVM", record: &ringbuf.Record{RawSample: []byte{EventTypeJVMMemoryPoolGC}}},
		{name: "unknown", record: &ringbuf.Record{RawSample: []byte{EventTypeDNS}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsGoRuntimeMetricRecord(tc.record))
		})
	}
}

func TestHandleRuntimeMetricsRecordForwardsGoRuntimeMetricRecords(t *testing.T) {
	for _, tc := range []struct {
		name      string
		eventType byte
	}{
		{name: "scalar", eventType: EventTypeGoRuntimeMetric},
		{name: "histogram", eventType: EventTypeGoRuntimeHistogram},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtimeMetrics := &fakeRuntimeMetricsSender{}
			ctx := &EBPFEventContext{RuntimeMetrics: runtimeMetrics}
			filter := fakeRuntimeServiceFilter{}

			handled, err := HandleRuntimeMetricsRecord(context.Background(), ctx, &ringbuf.Record{
				RawSample: []byte{tc.eventType},
			}, filter, nil)

			require.NoError(t, err)
			assert.True(t, handled)
			assert.Equal(t, 1, runtimeMetrics.goRecords)
			assert.Equal(t, filter, runtimeMetrics.goFilter)
		})
	}
}

func TestHandleRuntimeMetricsRecordConsumesKnownRuntimeMetricRecords(t *testing.T) {
	for _, eventType := range []byte{
		EventTypeGoRuntimeMetric,
		EventTypeGoRuntimeHistogram,
		EventTypeJVMMemoryPoolGC,
	} {
		runtimeMetrics := &fakeRuntimeMetricsSender{}
		ctx := &EBPFEventContext{RuntimeMetrics: runtimeMetrics}

		handled, err := HandleRuntimeMetricsRecord(context.Background(), nil, &ringbuf.Record{
			RawSample: []byte{eventType},
		}, nil, nil)

		require.NoError(t, err)
		assert.True(t, handled)

		handled, err = HandleRuntimeMetricsRecord(context.Background(), ctx, &ringbuf.Record{
			RawSample: []byte{eventType},
		}, nil, nil)
		require.NoError(t, err)
		assert.True(t, handled)

		if eventType == EventTypeGoRuntimeMetric || eventType == EventTypeGoRuntimeHistogram {
			assert.Equal(t, 1, runtimeMetrics.goRecords)
		} else {
			assert.Zero(t, runtimeMetrics.goRecords)
		}
		assert.Empty(t, runtimeMetrics.events)
	}
}

func TestHandleRuntimeMetricsRecordUsesCustomRuntimeMetricHandler(t *testing.T) {
	expectedErr := errors.New("handler failed")
	called := 0

	handled, err := HandleRuntimeMetricsRecord(context.Background(), nil, &ringbuf.Record{
		RawSample: []byte{EventTypeJVMMemoryPoolGC},
	}, nil, nil, func(_ context.Context, record *ringbuf.Record) (bool, error) {
		called++
		assert.Equal(t, byte(EventTypeJVMMemoryPoolGC), record.RawSample[0])
		return true, expectedErr
	})

	require.ErrorIs(t, err, expectedErr)
	assert.True(t, handled)
	assert.Equal(t, 1, called)
}

func TestHandleRuntimeMetricsRecordIgnoresUnknownEventTypes(t *testing.T) {
	handled, err := HandleRuntimeMetricsRecord(context.Background(), nil, &ringbuf.Record{
		RawSample: []byte{EventTypeDNS},
	}, nil, nil)

	require.NoError(t, err)
	assert.False(t, handled)
}

type fakeRuntimeServiceFilter struct {
	current map[uint32]map[app.PID]svc.Attrs
}

func (f fakeRuntimeServiceFilter) AllowPID(app.PID, uint32, *exec.FileInfo, PIDType) {}
func (f fakeRuntimeServiceFilter) BlockPID(app.PID, uint32)                          {}
func (f fakeRuntimeServiceFilter) ValidPID(app.PID, uint32, PIDType) bool            { return false }

func (f fakeRuntimeServiceFilter) Filter(inputSpans []request.Span) []request.Span { return inputSpans }

func (f fakeRuntimeServiceFilter) CurrentPIDs(PIDType) map[uint32]map[app.PID]svc.Attrs {
	return f.current
}

type fakeRuntimeMetricsSender struct {
	events       []appruntime.JVMRuntimeEvent
	nodejsEvents []appruntime.NodejsRuntimeEvent
	goRecords    int
	goFilter     ServiceFilter
}

func (s *fakeRuntimeMetricsSender) SendNodejsRuntimeMetrics(_ context.Context, events []appruntime.NodejsRuntimeEvent) {
	s.nodejsEvents = append(s.nodejsEvents, events...)
}

func (s *fakeRuntimeMetricsSender) SendGoRuntimeMetricRecord(_ context.Context, _ *ringbuf.Record, filter ServiceFilter) error {
	s.goRecords++
	s.goFilter = filter
	return nil
}

func (s *fakeRuntimeMetricsSender) SendJVMRuntimeMetrics(_ context.Context, events []appruntime.JVMRuntimeEvent) {
	s.events = append(s.events, events...)
}
