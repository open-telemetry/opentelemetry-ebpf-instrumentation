// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"math"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

const (
	testAutoSpanStart = pcommon.Timestamp(946684800000000000)
	testAutoSpanEnd   = pcommon.Timestamp(946684801000000000)
)

var (
	testAutoTraceID  = pcommon.TraceID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	testAutoSpanID   = pcommon.SpanID{0, 0, 0, 0, 0, 0, 0, 2}
	testAutoParentID = pcommon.SpanID{0, 0, 0, 0, 0, 0, 0, 3}
)

func TestReadBPFTraceAsSpanGoAutoSpan(t *testing.T) {
	assert.Equal(t, uint8(20), EventTypeGoAutoSpan)
	assert.Equal(t, 20, int(unsafe.Offsetof(GoAutoSpanTrace{}.Buf)))
	assert.Equal(t, 16*1024, goAutoSpanJSONMaxLen)
	assert.NotEqual(t, EventTypeGoRuntimeMetric, EventTypeGoAutoSpan)
	assert.NotEqual(t, EventTypeGoChannelLink, EventTypeGoAutoSpan)
	assert.NotEqual(t, EventTypeJVMMemoryPoolGC, EventTypeGoAutoSpan)

	payload := marshalAutoSpanPayload(t, validAutoSpanTraces())
	record := goAutoSpanRecord(payload, uint32(len(payload)))

	span, ignore, err := ReadBPFTraceAsSpan(nil, nil, record, nil)
	require.NoError(t, err)
	assert.False(t, ignore)
	assert.Equal(t, request.EventTypeManualSpan, span.Type)
	assert.Equal(t, trace.SpanKindServer, span.SpanKind)
	assert.Equal(t, "manual-json", span.Method)
	assert.Equal(t, "boom", span.Path)
	assert.Equal(t, trace.TraceID(testAutoTraceID), span.TraceID)
	assert.Equal(t, trace.SpanID(testAutoSpanID), span.SpanID)
	assert.Equal(t, trace.SpanID(testAutoParentID), span.ParentSpanID)
	assert.Equal(t, uint8(TPFlagSampled), span.TraceFlags)
	assert.Equal(t, int(codes.Error), span.Status)
	assert.Equal(t, request.PidInfo{
		HostPID:   app.PID(123),
		UserPID:   app.PID(456),
		Namespace: 789,
	}, span.Pid)
	assert.Equal(t, span.RequestStart, span.Start)
	assert.Equal(t, int64(testAutoSpanEnd-testAutoSpanStart), span.End-span.Start)
	timings := span.Timings()
	assert.WithinDuration(t, time.Unix(0, int64(testAutoSpanStart)), timings.Start, 100*time.Millisecond)
	assert.WithinDuration(t, time.Unix(0, int64(testAutoSpanEnd)), timings.End, 100*time.Millisecond)
	assert.Equal(t, "SPAN_KIND_SERVER", span.ServiceGraphKind())
	assert.False(t, span.IsClientSpan())
	assert.Equal(t, payload, span.ManualOTelJSON)

	for i := range record.RawSample {
		record.RawSample[i] = 0
	}
	assert.Equal(t, payload, span.ManualOTelJSON)
}

func TestReadGoAutoSpanEventRejectsMalformedRecords(t *testing.T) {
	validPayload := marshalAutoSpanPayload(t, validAutoSpanTraces())
	headerSize := int(unsafe.Offsetof(GoAutoSpanTrace{}.Buf))

	tests := []struct {
		name    string
		record  *ringbuf.Record
		wantErr string
	}{
		{
			name:    "nil record",
			wantErr: "nil Go Auto SDK span record",
		},
		{
			name:    "short header",
			record:  &ringbuf.Record{RawSample: make([]byte, headerSize-1)},
			wantErr: "shorter than its header",
		},
		{
			name:    "empty payload",
			record:  goAutoSpanRecord(nil, 0),
			wantErr: "payload: empty",
		},
		{
			name:    "payload over limit",
			record:  goAutoSpanRecord(make([]byte, goAutoSpanJSONMaxLen+1), goAutoSpanJSONMaxLen+1),
			wantErr: "exceeds the size limit",
		},
		{
			name:    "declared payload truncated",
			record:  goAutoSpanRecord(validPayload, uint32(len(validPayload)+1)),
			wantErr: "size does not match",
		},
		{
			name:    "record has trailing bytes",
			record:  goAutoSpanRecord(validPayload, uint32(len(validPayload)-1)),
			wantErr: "size does not match",
		},
		{
			name:    "invalid JSON",
			record:  goAutoSpanRecord([]byte("{"), 1),
			wantErr: "invalid Go Auto SDK span payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span, ignore, err := ReadGoAutoSpanEventIntoSpan(tt.record)
			require.ErrorContains(t, err, tt.wantErr)
			assert.True(t, ignore)
			assert.Equal(t, request.Span{}, span)
		})
	}
}

func TestReadAutoSpanPayloadRejectsInvalidSpanData(t *testing.T) {
	tests := []struct {
		name    string
		traces  func() ptrace.Traces
		wantErr string
	}{
		{
			name:    "no resource spans",
			traces:  ptrace.NewTraces,
			wantErr: "exactly one resource span",
		},
		{
			name: "multiple resource spans",
			traces: func() ptrace.Traces {
				traces := validAutoSpanTraces()
				traces.ResourceSpans().AppendEmpty()
				return traces
			},
			wantErr: "exactly one resource span",
		},
		{
			name: "no scope spans",
			traces: func() ptrace.Traces {
				traces := ptrace.NewTraces()
				traces.ResourceSpans().AppendEmpty()
				return traces
			},
			wantErr: "exactly one scope span",
		},
		{
			name: "multiple scope spans",
			traces: func() ptrace.Traces {
				traces := validAutoSpanTraces()
				traces.ResourceSpans().At(0).ScopeSpans().AppendEmpty()
				return traces
			},
			wantErr: "exactly one scope span",
		},
		{
			name: "no spans",
			traces: func() ptrace.Traces {
				traces := ptrace.NewTraces()
				traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty()
				return traces
			},
			wantErr: "exactly one span",
		},
		{
			name: "multiple spans",
			traces: func() ptrace.Traces {
				traces := validAutoSpanTraces()
				traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().AppendEmpty()
				return traces
			},
			wantErr: "exactly one span",
		},
		{
			name: "invalid trace ID",
			traces: func() ptrace.Traces {
				traces := validAutoSpanTraces()
				traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).SetTraceID(pcommon.TraceID{})
				return traces
			},
			wantErr: "invalid trace ID",
		},
		{
			name: "invalid span ID",
			traces: func() ptrace.Traces {
				traces := validAutoSpanTraces()
				traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).SetSpanID(pcommon.SpanID{})
				return traces
			},
			wantErr: "invalid span ID",
		},
		{
			name: "zero start timestamp",
			traces: func() ptrace.Traces {
				traces := validAutoSpanTraces()
				traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).SetStartTimestamp(0)
				return traces
			},
			wantErr: "invalid span timestamps",
		},
		{
			name: "end before start",
			traces: func() ptrace.Traces {
				traces := validAutoSpanTraces()
				traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).SetEndTimestamp(testAutoSpanStart - 1)
				return traces
			},
			wantErr: "invalid span timestamps",
		},
		{
			name: "duration over limit",
			traces: func() ptrace.Traces {
				traces := validAutoSpanTraces()
				span := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
				span.SetStartTimestamp(1)
				span.SetEndTimestamp(pcommon.Timestamp(math.MaxUint64))
				return traces
			},
			wantErr: "duration: too large",
		},
		{
			name: "invalid status",
			traces: func() ptrace.Traces {
				traces := validAutoSpanTraces()
				traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Status().SetCode(99)
				return traces
			},
			wantErr: "invalid span status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := marshalAutoSpanPayload(t, tt.traces())
			span, err := readAutoSpanPayload(payload)
			require.ErrorContains(t, err, tt.wantErr)
			assert.Equal(t, request.Span{}, span)
		})
	}
}

func TestAutoSpanStatus(t *testing.T) {
	tests := []struct {
		status ptrace.StatusCode
		want   codes.Code
	}{
		{status: ptrace.StatusCodeUnset, want: codes.Unset},
		{status: ptrace.StatusCodeOk, want: codes.Ok},
		{status: ptrace.StatusCodeError, want: codes.Error},
	}

	for _, tt := range tests {
		got, err := autoSpanStatus(tt.status)
		require.NoError(t, err)
		assert.Equal(t, int(tt.want), got)
	}
}

func TestReadAutoSpanPayloadNormalizesSpanKind(t *testing.T) {
	tests := []struct {
		name string
		kind ptrace.SpanKind
		want trace.SpanKind
	}{
		{name: "unspecified", kind: ptrace.SpanKindUnspecified, want: trace.SpanKindInternal},
		{name: "unknown", kind: ptrace.SpanKind(99), want: trace.SpanKindInternal},
		{name: "client", kind: ptrace.SpanKindClient, want: trace.SpanKindClient},
		{name: "producer", kind: ptrace.SpanKindProducer, want: trace.SpanKindProducer},
		{name: "consumer", kind: ptrace.SpanKindConsumer, want: trace.SpanKindConsumer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			traces := validAutoSpanTraces()
			traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).SetKind(tt.kind)
			span, err := readAutoSpanPayload(marshalAutoSpanPayload(t, traces))
			require.NoError(t, err)
			assert.Equal(t, tt.want, span.SpanKind)
		})
	}
}

func validAutoSpanTraces() ptrace.Traces {
	traces := ptrace.NewTraces()
	span := traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetTraceID(testAutoTraceID)
	span.SetSpanID(testAutoSpanID)
	span.SetParentSpanID(testAutoParentID)
	span.SetFlags(TPFlagSampled)
	span.SetName("manual-json")
	span.SetKind(ptrace.SpanKindServer)
	span.SetStartTimestamp(testAutoSpanStart)
	span.SetEndTimestamp(testAutoSpanEnd)
	span.Status().SetCode(ptrace.StatusCodeError)
	span.Status().SetMessage("boom")
	return traces
}

func marshalAutoSpanPayload(t *testing.T, traces ptrace.Traces) []byte {
	t.Helper()

	var marshaler ptrace.JSONMarshaler
	payload, err := marshaler.MarshalTraces(traces)
	require.NoError(t, err)
	return payload
}

func goAutoSpanRecord(payload []byte, size uint32) *ringbuf.Record {
	headerSize := int(unsafe.Offsetof(GoAutoSpanTrace{}.Buf))
	event := GoAutoSpanTrace{Type: EventTypeGoAutoSpan, Size: size}
	event.Pid.HostPid = 123
	event.Pid.UserPid = 456
	event.Pid.Ns = 789

	header := unsafe.Slice((*byte)(unsafe.Pointer(&event)), headerSize)
	raw := make([]byte, 0, headerSize+len(payload))
	raw = append(raw, header...)
	raw = append(raw, payload...)
	return &ringbuf.Record{RawSample: raw}
}
