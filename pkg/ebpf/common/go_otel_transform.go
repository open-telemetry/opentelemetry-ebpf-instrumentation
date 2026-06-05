// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"encoding/json"
	"errors"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

func ReadGoOTelEventIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[GoOTelSpanTrace](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	name := cstr(event.SpanName.Buf[:])
	descr := cstr(event.SpanDescription.Buf[:])

	attrs := ""
	if a, err := encodedAttrs(event); err == nil {
		attrs = string(a)
	}

	return request.Span{
		Type:          request.EventTypeManualSpan,
		Method:        name,
		Statement:     attrs,
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
	event, err := ReinterpretCast[GoAutoSpanTrace](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	size := int(event.Size)
	if size <= 0 || size > len(event.Buf) {
		return request.Span{}, true, errors.New("invalid Go Auto SDK span payload size")
	}

	payload := bytes.Clone(event.Buf[:size])
	span, err := readAutoSpanPayload(payload)
	if err != nil {
		return request.Span{}, true, err
	}

	span.ManualOTelJSON = payload
	span.Pid = request.PidInfo{
		HostPID:   app.PID(event.Pid.HostPid),
		UserPID:   app.PID(event.Pid.UserPid),
		Namespace: event.Pid.Ns,
	}

	return span, false, nil
}

func readAutoSpanPayload(payload []byte) (request.Span, error) {
	var unmarshaler ptrace.JSONUnmarshaler
	traces, err := unmarshaler.UnmarshalTraces(payload)
	if err != nil {
		return request.Span{}, err
	}

	resourceSpans := traces.ResourceSpans()
	for i := 0; i < resourceSpans.Len(); i++ {
		scopeSpans := resourceSpans.At(i).ScopeSpans()
		for j := 0; j < scopeSpans.Len(); j++ {
			spans := scopeSpans.At(j).Spans()
			if spans.Len() == 0 {
				continue
			}

			otelSpan := spans.At(0)
			return request.Span{
				Type:         request.EventTypeManualSpan,
				Method:       otelSpan.Name(),
				TraceID:      trace.TraceID(otelSpan.TraceID()),
				SpanID:       trace.SpanID(otelSpan.SpanID()),
				ParentSpanID: trace.SpanID(otelSpan.ParentSpanID()),
				TraceFlags:   uint8(otelSpan.Flags() & TPFlagSampled),
				Status:       int(otelSpan.Status().Code()),
			}, nil
		}
	}

	return request.Span{}, errors.New("auto SDK span payload contained no spans")
}

func encodedAttrs(event *GoOTelSpanTrace) ([]byte, error) {
	size := int(event.SpanAttrs.ValidAttrs)
	if size == 0 {
		return nil, nil
	}
	attrs := event.SpanAttrs.Attrs[:size]
	return json.Marshal(attrs)
}
