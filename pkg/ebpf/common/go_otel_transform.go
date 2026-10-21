// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
	"unsafe"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
)

const goAutoSpanJSONMaxLen = 16 * 1024

var errInvalidGoOTelSpanAttributeCount = errors.New("invalid Go OTel span attribute count")

func ReadGoOTelEventIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[GoOTelSpanTrace](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	name := cstr(event.SpanName.Buf[:])
	descr := cstr(event.SpanDescription.Buf[:])

	attrs, err := encodedAttrs(event)
	if errors.Is(err, errInvalidGoOTelSpanAttributeCount) {
		return request.Span{}, true, err
	}

	return request.Span{
		Type:          request.EventTypeManualSpan,
		Method:        name,
		Statement:     string(attrs),
		Path:          descr,
		Peer:          "",
		PeerPort:      0,
		Host:          "",
		HostPort:      0,
		ContentLength: 0,
		RequestStart:  int64(event.StartTime),
		Start:         int64(event.StartTime),
		End:           int64(event.EndTime),
		TraceID:       trace.TraceID(event.Tp.TraceId),
		SpanID:        trace.SpanID(event.Tp.SpanId),
		ParentSpanID:  trace.SpanID(event.Tp.ParentId),
		Status:        int(event.Status),
		Pid: request.PidInfo{
			HostPID:   app.PID(event.Pid.HostPid),
			UserPID:   app.PID(event.Pid.UserPid),
			Namespace: event.Pid.Ns,
		},
	}, false, nil
}

func ReadGoAutoSpanEventIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	return readJSONSpanEvent(record, EventTypeGoAutoSpan, "Go Auto SDK")
}

func ReadCustomSpanEventIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	return readJSONSpanEvent(record, EventTypeCustomSpan, "custom span")
}

func readJSONSpanEvent(record *ringbuf.Record, expectedType uint8, name string) (request.Span, bool, error) {
	if record == nil {
		return request.Span{}, true, fmt.Errorf("nil %s span record", name)
	}

	headerSize := int(unsafe.Offsetof(GoAutoSpanTrace{}.Buf))
	if len(record.RawSample) < headerSize {
		return request.Span{}, true, fmt.Errorf("invalid %s span record: shorter than its header", name)
	}

	event := (*GoAutoSpanTrace)(unsafe.Pointer(unsafe.SliceData(record.RawSample)))
	if event.Type != expectedType {
		return request.Span{}, true, fmt.Errorf("invalid %s span record: unexpected event type %d", name, event.Type)
	}
	size := int(event.Size)
	if size == 0 {
		return request.Span{}, true, fmt.Errorf("invalid %s span payload: empty", name)
	}
	if size > goAutoSpanJSONMaxLen {
		return request.Span{}, true, fmt.Errorf("invalid %s span payload: exceeds the size limit", name)
	}
	if size != len(record.RawSample)-headerSize {
		return request.Span{}, true, fmt.Errorf("invalid %s span payload: size does not match the record", name)
	}

	payload := record.RawSample[headerSize:]
	span, err := readSingleOTLPSpanPayload(payload, name)
	if err != nil {
		return request.Span{}, true, fmt.Errorf("invalid %s span payload: %w", name, err)
	}

	span.ManualOTelJSON = bytes.Clone(payload)
	span.Pid = request.PidInfo{
		HostPID:   app.PID(event.Pid.HostPid),
		UserPID:   app.PID(event.Pid.UserPid),
		Namespace: event.Pid.Ns,
	}

	return span, false, nil
}

func readAutoSpanPayload(payload []byte) (request.Span, error) {
	return readSingleOTLPSpanPayload(payload, "Go Auto SDK")
}

func readSingleOTLPSpanPayload(payload []byte, producer string) (request.Span, error) {
	var unmarshaler ptrace.JSONUnmarshaler
	traces, err := unmarshaler.UnmarshalTraces(payload)
	if err != nil {
		return request.Span{}, fmt.Errorf("invalid %s span payload: %w", producer, err)
	}

	resourceSpans := traces.ResourceSpans()
	if resourceSpans.Len() != 1 {
		return request.Span{}, fmt.Errorf("invalid %s payload: expected exactly one resource span", producer)
	}

	scopeSpans := resourceSpans.At(0).ScopeSpans()
	if scopeSpans.Len() != 1 {
		return request.Span{}, fmt.Errorf("invalid %s payload: expected exactly one scope span", producer)
	}

	spans := scopeSpans.At(0).Spans()
	if spans.Len() != 1 {
		return request.Span{}, fmt.Errorf("invalid %s payload: expected exactly one span", producer)
	}

	otelSpan := spans.At(0)
	traceID := trace.TraceID(otelSpan.TraceID())
	if !traceID.IsValid() {
		return request.Span{}, fmt.Errorf("invalid %s payload: invalid trace ID", producer)
	}

	spanID := trace.SpanID(otelSpan.SpanID())
	if !spanID.IsValid() {
		return request.Span{}, fmt.Errorf("invalid %s payload: invalid span ID", producer)
	}

	start := otelSpan.StartTimestamp()
	end := otelSpan.EndTimestamp()
	if start == 0 || end == 0 || end < start {
		return request.Span{}, fmt.Errorf("invalid %s payload: invalid span timestamps", producer)
	}

	duration := uint64(end - start)
	if duration > math.MaxInt64 {
		return request.Span{}, fmt.Errorf("invalid %s span duration: too large", producer)
	}
	if start > math.MaxInt64 || end > math.MaxInt64 {
		return request.Span{}, fmt.Errorf("invalid %s span timestamp: outside the supported range", producer)
	}

	wallNow := time.Now().UnixNano()
	monoNow := int64(timing.MonoTimeNow())
	startMonotime, ok := translateAutoSpanTimestamp(int64(start), wallNow, monoNow)
	if !ok {
		return request.Span{}, fmt.Errorf("invalid %s span start timestamp: overflows monotonic time", producer)
	}
	endMonotime, ok := translateAutoSpanTimestamp(int64(end), wallNow, monoNow)
	if !ok {
		return request.Span{}, fmt.Errorf("invalid %s span end timestamp: overflows monotonic time", producer)
	}

	status, err := autoSpanStatus(otelSpan.Status().Code())
	if err != nil {
		return request.Span{}, err
	}

	return request.Span{
		Type:         request.EventTypeManualSpan,
		SpanKind:     trace.ValidateSpanKind(trace.SpanKind(otelSpan.Kind())),
		Method:       otelSpan.Name(),
		Path:         otelSpan.Status().Message(),
		RequestStart: startMonotime,
		Start:        startMonotime,
		End:          endMonotime,
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: trace.SpanID(otelSpan.ParentSpanID()),
		TraceFlags:   uint8(otelSpan.Flags() & TPFlagSampled),
		Status:       status,
	}, nil
}

func translateAutoSpanTimestamp(timestamp, wallNow, monoNow int64) (int64, bool) {
	delta := timestamp - wallNow
	if delta > 0 && monoNow > math.MaxInt64-delta {
		return 0, false
	}
	if delta < 0 && monoNow < math.MinInt64-delta {
		return 0, false
	}
	return monoNow + delta, true
}

func autoSpanStatus(status ptrace.StatusCode) (int, error) {
	switch status {
	case ptrace.StatusCodeUnset:
		return int(codes.Unset), nil
	case ptrace.StatusCodeOk:
		return int(codes.Ok), nil
	case ptrace.StatusCodeError:
		return int(codes.Error), nil
	default:
		return 0, errors.New("invalid Go Auto SDK payload: invalid span status")
	}
}

func encodedAttrs(event *GoOTelSpanTrace) ([]byte, error) {
	size := int(event.SpanAttrs.ValidAttrs)
	if size > len(event.SpanAttrs.Attrs) {
		return nil, fmt.Errorf("%w: %d exceeds %d", errInvalidGoOTelSpanAttributeCount, size, len(event.SpanAttrs.Attrs))
	}
	if size == 0 {
		return nil, nil
	}
	attrs := event.SpanAttrs.Attrs[:size]
	return json.Marshal(attrs)
}
