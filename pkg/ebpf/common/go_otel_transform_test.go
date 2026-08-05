// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/json"
	"math"
	"testing"
	"time"
	"unsafe"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"go.opentelemetry.io/otel/trace"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
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

func TestReadGoOTelEventPreservesTraceFlags(t *testing.T) {
	event := GoOTelSpanTrace{
		Type:      uint8(EventOTelSDKGo),
		StartTime: 10,
		EndTime:   20,
		Status:    uint32(codes.Error),
	}
	event.Tp.TraceId = [16]uint8{1}
	event.Tp.SpanId = [8]uint8{2}
	event.Tp.ParentId = [8]uint8{3}
	event.Tp.Flags = TPFlagRandom
	event.Tp.SamplingDecision = 1
	event.Pid.HostPid = 123
	event.SpanKind = uint8(trace.SpanKindClient)
	copy(event.SpanName.Buf[:], "compact")
	copy(event.SpanAttrs.Attrs[0].Key[:], string(semconv.HTTPRouteKey))
	copy(event.SpanAttrs.Attrs[0].Value[:], "/users/{id}")
	event.SpanAttrs.Attrs[0].Vtype = uint8(attribute.STRING)
	copy(event.SpanAttrs.Attrs[1].Key[:], string(semconv.ServerAddressKey))
	copy(event.SpanAttrs.Attrs[1].Value[:], "remote-address")
	event.SpanAttrs.Attrs[1].Vtype = uint8(attribute.STRING)
	copy(event.SpanAttrs.Attrs[2].Key[:], string(semconv.ServicePeerNameKey))
	copy(event.SpanAttrs.Attrs[2].Value[:], "remote-service")
	event.SpanAttrs.Attrs[2].Vtype = uint8(attribute.STRING)
	event.SpanAttrs.ValidAttrs = 3

	raw := unsafe.Slice((*byte)(unsafe.Pointer(&event)), int(unsafe.Sizeof(event)))
	span, ignore, err := ReadGoOTelEventIntoSpan(&ringbuf.Record{RawSample: append([]byte(nil), raw...)})
	require.NoError(t, err)
	assert.False(t, ignore)
	assert.Equal(t, uint8(TPFlagRandom), span.TraceFlags)
	assert.True(t, span.BPFDecision)
	assert.Equal(t, trace.SpanKindClient, span.SpanKind)
	assert.Equal(t, "compact", span.Method)
	assert.Equal(t, "/users/{id}", span.Route)
	assert.Equal(t, "remote-address", span.Host)
	assert.Equal(t, "remote-service", span.HostName)
	assert.Equal(t, int64(10), span.Start)
	assert.Equal(t, int64(20), span.End)
	assert.Equal(t, app.PID(123), span.Pid.HostPID)
}

func TestCompactSpanRouteUsesLatestAttribute(t *testing.T) {
	event := GoOTelSpanTrace{}
	for i, route := range []string{"/old", "/new"} {
		copy(event.SpanAttrs.Attrs[i].Key[:], string(semconv.HTTPRouteKey))
		copy(event.SpanAttrs.Attrs[i].Value[:], route)
		event.SpanAttrs.Attrs[i].Vtype = uint8(attribute.STRING)
	}
	event.SpanAttrs.ValidAttrs = 2

	assert.Equal(t, "/new", compactSpanRoute(&event))
}

func TestCompactSpanRoutePrefersDedicatedRoute(t *testing.T) {
	event := GoOTelSpanTrace{}
	event.RouteState = goOTelSpecialAttrValid
	copy(event.Route[:], "/after-capacity")
	copy(event.SpanAttrs.Attrs[0].Key[:], string(semconv.HTTPRouteKey))
	copy(event.SpanAttrs.Attrs[0].Value[:], "/buffered")
	event.SpanAttrs.Attrs[0].Vtype = uint8(attribute.STRING)
	event.SpanAttrs.ValidAttrs = 1

	assert.Equal(t, "/after-capacity", compactSpanRoute(&event))

	rawAttrs, err := encodedAttrs(&event)
	require.NoError(t, err)
	var attrs []goOTelEncodedAttribute
	require.NoError(t, json.Unmarshal(rawAttrs, &attrs))
	require.Len(t, attrs, 1)
	assert.Equal(t, string(semconv.HTTPRouteKey), cstr(attrs[0].Key[:]))
	assert.Equal(t, "/after-capacity", cstr(attrs[0].Value[:]))
}

func TestCompactSpanInvalidDedicatedRouteClearsBufferedValue(t *testing.T) {
	event := GoOTelSpanTrace{}
	event.RouteState = goOTelSpecialAttrInvalid
	copy(event.SpanAttrs.Attrs[0].Key[:], string(semconv.HTTPRouteKey))
	copy(event.SpanAttrs.Attrs[0].Value[:], "/buffered")
	event.SpanAttrs.Attrs[0].Vtype = uint8(attribute.STRING)
	event.SpanAttrs.ValidAttrs = 1

	assert.Empty(t, compactSpanRoute(&event))
	rawAttrs, err := encodedAttrs(&event)
	require.NoError(t, err)
	assert.Empty(t, rawAttrs)
}

func TestCompactSpanPreservesEmptyDedicatedRoute(t *testing.T) {
	event := GoOTelSpanTrace{}
	event.RouteState = goOTelSpecialAttrValid
	copy(event.SpanAttrs.Attrs[0].Key[:], string(semconv.HTTPRouteKey))
	copy(event.SpanAttrs.Attrs[0].Value[:], "/buffered")
	event.SpanAttrs.Attrs[0].Vtype = uint8(attribute.STRING)
	event.SpanAttrs.ValidAttrs = 1

	rawAttrs, err := encodedAttrs(&event)
	require.NoError(t, err)
	var attrs []goOTelEncodedAttribute
	require.NoError(t, json.Unmarshal(rawAttrs, &attrs))
	require.Len(t, attrs, 1)
	assert.Equal(t, string(semconv.HTTPRouteKey), cstr(attrs[0].Key[:]))
	assert.Empty(t, cstr(attrs[0].Value[:]))
}

func TestCompactSpanEndpointsPreferDedicatedValues(t *testing.T) {
	event := GoOTelSpanTrace{SpanKind: uint8(trace.SpanKindClient)}
	copy(event.SpanAttrs.Attrs[0].Key[:], string(semconv.ServerAddressKey))
	copy(event.SpanAttrs.Attrs[0].Value[:], "buffered-address")
	event.SpanAttrs.Attrs[0].Vtype = uint8(attribute.STRING)
	copy(event.SpanAttrs.Attrs[1].Key[:], string(semconv.ServicePeerNameKey))
	copy(event.SpanAttrs.Attrs[1].Value[:], "buffered-service")
	event.SpanAttrs.Attrs[1].Vtype = uint8(attribute.STRING)
	event.SpanAttrs.ValidAttrs = 2
	event.RemoteAddressState = goOTelSpecialAttrValid
	event.ServicePeerNameState = goOTelSpecialAttrValid
	copy(event.RemoteAddress[:], "dedicated-address")
	copy(event.ServicePeerName[:], "dedicated-service")

	_, _, host, hostName := manualSpanEndpoints(
		trace.SpanKindClient,
		func(key attribute.Key) (string, bool) {
			return compactStringAttribute(&event, key)
		},
	)

	assert.Equal(t, "dedicated-address", host)
	assert.Equal(t, "dedicated-service", hostName)

	rawAttrs, err := encodedAttrs(&event)
	require.NoError(t, err)
	var attrs []goOTelEncodedAttribute
	require.NoError(t, json.Unmarshal(rawAttrs, &attrs))
	require.Len(t, attrs, 2)
	exported := map[string]string{}
	for i := range attrs {
		exported[cstr(attrs[i].Key[:])] = cstr(attrs[i].Value[:])
	}
	assert.Equal(t, "dedicated-address", exported[string(semconv.ServerAddressKey)])
	assert.Equal(t, "dedicated-service", exported[string(semconv.ServicePeerNameKey)])

	event.RemoteAddress = [128]uint8{}
	event.RemoteAddressState = goOTelSpecialAttrInvalid
	_, _, host, _ = manualSpanEndpoints(
		trace.SpanKindClient,
		func(key attribute.Key) (string, bool) {
			return compactStringAttribute(&event, key)
		},
	)
	assert.Empty(t, host)
}

func TestCompactSpanTimestampsTranslateWallClock(t *testing.T) {
	start := time.Now().Add(-time.Millisecond).UnixNano()
	const duration = 100 * time.Microsecond
	event := GoOTelSpanTrace{
		StartTime:     uint64(start),
		EndTime:       uint64(start + duration.Nanoseconds()),
		StartTimeWall: 1,
		EndTimeWall:   1,
	}

	gotStart, gotEnd, err := compactSpanTimestamps(&event)
	require.NoError(t, err)
	assert.Equal(t, duration.Nanoseconds(), gotEnd-gotStart)
}

func TestReadBPFTraceAsSpanGoAutoSpan(t *testing.T) {
	assert.Equal(t, uint8(20), uint8(EventTypeGoAutoSpan))
	assert.Equal(t, 1, goAutoSpanParentRemoteOffset)
	assert.Equal(t, 20, int(unsafe.Offsetof(GoAutoSpanTrace{}.Buf)))
	assert.Equal(t, 16*1024, goAutoSpanJSONMaxLen)
	assert.NotEqual(t, EventTypeGoRuntimeMetric, EventTypeGoAutoSpan)
	assert.NotEqual(t, EventTypeGoChannelLink, EventTypeGoAutoSpan)
	assert.NotEqual(t, EventTypeJVMMemoryPoolGC, EventTypeGoAutoSpan)

	payload := marshalAutoSpanPayload(t, validAutoSpanTraces())
	record := goAutoSpanRecord(payload, uint32(len(payload)), true)

	span, ignore, err := ReadBPFTraceAsSpan(nil, nil, record, nil)
	require.NoError(t, err)
	assert.False(t, ignore)
	assert.Equal(t, request.EventTypeManualSpan, span.Type)
	assert.Equal(t, trace.SpanKindServer, span.SpanKind)
	assert.Equal(t, "manual-json", span.Method)
	assert.Equal(t, "/users/{id}", span.Route)
	assert.Equal(t, "boom", span.Path)
	assert.Equal(t, trace.TraceID(testAutoTraceID), span.TraceID)
	assert.Equal(t, trace.SpanID(testAutoSpanID), span.SpanID)
	assert.Equal(t, trace.SpanID(testAutoParentID), span.ParentSpanID)
	assert.Equal(t, uint8(TPFlagSampled|TPFlagRandom), span.TraceFlags)
	assert.True(t, span.ParentRemote)
	assert.True(t, span.BPFDecision)
	assert.Equal(t, "remote-address", span.Peer)
	assert.Equal(t, "remote-service", span.PeerName)
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

func TestReadGoAutoSpanEventUsesParentRemotenessMetadata(t *testing.T) {
	tests := []struct {
		name         string
		parentSpanID pcommon.SpanID
		flags        uint32
		parentRemote bool
		wantRemote   bool
		wantFlags    uint32
	}{
		{
			name: "root ignores remote metadata",
			flags: TPFlagSampled |
				uint32(tracepb.SpanFlags_SPAN_FLAGS_CONTEXT_HAS_IS_REMOTE_MASK) |
				uint32(tracepb.SpanFlags_SPAN_FLAGS_CONTEXT_IS_REMOTE_MASK),
			parentRemote: true,
			wantFlags:    TPFlagSampled,
		},
		{
			name:         "local parent overrides JSON remote bits",
			parentSpanID: testAutoParentID,
			flags: TPFlagSampled |
				uint32(tracepb.SpanFlags_SPAN_FLAGS_CONTEXT_HAS_IS_REMOTE_MASK) |
				uint32(tracepb.SpanFlags_SPAN_FLAGS_CONTEXT_IS_REMOTE_MASK),
			wantFlags: TPFlagSampled |
				uint32(tracepb.SpanFlags_SPAN_FLAGS_CONTEXT_HAS_IS_REMOTE_MASK),
		},
		{
			name:         "remote parent does not depend on JSON remote bits",
			parentSpanID: testAutoParentID,
			flags:        TPFlagSampled,
			parentRemote: true,
			wantRemote:   true,
			wantFlags: TPFlagSampled |
				uint32(tracepb.SpanFlags_SPAN_FLAGS_CONTEXT_HAS_IS_REMOTE_MASK) |
				uint32(tracepb.SpanFlags_SPAN_FLAGS_CONTEXT_IS_REMOTE_MASK),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			traces := validAutoSpanTraces()
			otelSpan := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
			otelSpan.SetParentSpanID(tt.parentSpanID)
			otelSpan.SetFlags(tt.flags)
			payload := marshalAutoSpanPayload(t, traces)

			span, ignore, err := ReadGoAutoSpanEventIntoSpan(
				goAutoSpanRecord(payload, uint32(len(payload)), tt.parentRemote),
			)
			require.NoError(t, err)
			assert.False(t, ignore)
			assert.Equal(t, trace.SpanID(tt.parentSpanID), span.ParentSpanID)
			assert.Equal(t, uint8(TPFlagSampled), span.TraceFlags)
			assert.Equal(t, tt.wantRemote, span.ParentRemote)

			cache := expirable2.NewLRU[svc.UID, []attribute.KeyValue](10, nil, 0)
			exported := tracesgen.GenerateTracesWithAttributes(
				cache,
				&span.Service,
				nil,
				&meta.NodeMeta{},
				[]tracesgen.TraceSpanAndAttributes{{Span: &span}},
				"obi",
			)
			exportedSpans := exported.ResourceSpans().At(0).ScopeSpans().At(0).Spans()
			require.Equal(t, 1, exportedSpans.Len())
			assert.Equal(t, tt.wantFlags, exportedSpans.At(0).Flags())
		})
	}
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
			record:  goAutoSpanRecord(nil, 0, false),
			wantErr: "payload: empty",
		},
		{
			name:    "payload over limit",
			record:  goAutoSpanRecord(make([]byte, goAutoSpanJSONMaxLen+1), goAutoSpanJSONMaxLen+1, false),
			wantErr: "exceeds the size limit",
		},
		{
			name:    "declared payload truncated",
			record:  goAutoSpanRecord(validPayload, uint32(len(validPayload)+1), false),
			wantErr: "size does not match",
		},
		{
			name:    "record has trailing bytes",
			record:  goAutoSpanRecord(validPayload, uint32(len(validPayload)-1), false),
			wantErr: "size does not match",
		},
		{
			name:    "invalid JSON",
			record:  goAutoSpanRecord([]byte("{"), 1, false),
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
			span, err := readAutoSpanPayload(payload, false)
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
			span, err := readAutoSpanPayload(marshalAutoSpanPayload(t, traces), false)
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
	span.SetFlags(TPFlagSampled | TPFlagRandom)
	span.SetName("manual-json")
	span.SetKind(ptrace.SpanKindServer)
	span.SetStartTimestamp(testAutoSpanStart)
	span.SetEndTimestamp(testAutoSpanEnd)
	span.Status().SetCode(ptrace.StatusCodeError)
	span.Status().SetMessage("boom")
	span.Attributes().PutStr(string(semconv.HTTPRouteKey), "/users/{id}")
	span.Attributes().PutStr(string(semconv.ClientAddressKey), "remote-address")
	span.Attributes().PutStr(string(semconv.ServicePeerNameKey), "remote-service")
	return traces
}

func marshalAutoSpanPayload(t *testing.T, traces ptrace.Traces) []byte {
	t.Helper()

	var marshaler ptrace.JSONMarshaler
	payload, err := marshaler.MarshalTraces(traces)
	require.NoError(t, err)
	return payload
}

func goAutoSpanRecord(payload []byte, size uint32, parentRemote bool) *ringbuf.Record {
	headerSize := int(unsafe.Offsetof(GoAutoSpanTrace{}.Buf))
	event := GoAutoSpanTrace{Type: EventTypeGoAutoSpan, Size: size}
	event.Pid.HostPid = 123
	event.Pid.UserPid = 456
	event.Pid.Ns = 789

	header := unsafe.Slice((*byte)(unsafe.Pointer(&event)), headerSize)
	raw := make([]byte, 0, headerSize+len(payload))
	raw = append(raw, header...)
	if parentRemote {
		raw[goAutoSpanParentRemoteOffset] = 1
	}
	raw = append(raw, payload...)
	return &ringbuf.Record{RawSample: raw}
}
