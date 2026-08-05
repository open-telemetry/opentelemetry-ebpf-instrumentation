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

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
)

const goAutoSpanJSONMaxLen = 16 * 1024

type goAutoSpanMetadata struct {
	Type         uint8
	ParentRemote uint8
}

const goAutoSpanParentRemoteOffset = int(unsafe.Offsetof(goAutoSpanMetadata{}.ParentRemote))

const (
	goOTelSpecialAttrUnset uint8 = iota
	goOTelSpecialAttrInvalid
	goOTelSpecialAttrValid
)

type goOTelEncodedAttribute struct {
	ValLength uint16
	Vtype     uint8
	Reserved  uint8
	Key       [32]uint8
	Value     [128]uint8
}

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

	start, end, err := compactSpanTimestamps(event)
	if err != nil {
		return request.Span{}, true, err
	}
	spanKind := trace.ValidateSpanKind(trace.SpanKind(event.SpanKind))
	peer, peerName, host, hostName := manualSpanEndpoints(
		spanKind,
		func(key attribute.Key) (string, bool) {
			return compactStringAttribute(event, key)
		},
	)

	return request.Span{
		Type:          request.EventTypeManualSpan,
		SpanKind:      spanKind,
		Method:        name,
		Statement:     attrs,
		Path:          descr,
		Route:         compactSpanRoute(event),
		Peer:          peer,
		PeerName:      peerName,
		PeerPort:      0,
		Host:          host,
		HostName:      hostName,
		HostPort:      0,
		ContentLength: 0,
		RequestStart:  start,
		Start:         start,
		End:           end,
		TraceID:       trace.TraceID(event.Tp.TraceId),
		SpanID:        trace.SpanID(event.Tp.SpanId),
		ParentSpanID:  trace.SpanID(event.Tp.ParentId),
		TraceFlags:    event.Tp.Flags,
		ParentRemote:  event.Tp.ParentRemote != 0,
		BPFDecision:   event.Tp.SamplingDecision != 0,
		Status:        int(event.Status),
		Pid: request.PidInfo{
			HostPID:   app.PID(event.Pid.HostPid),
			UserPID:   app.PID(event.Pid.UserPid),
			Namespace: event.Pid.Ns,
		},
	}, false, nil
}

func compactSpanTimestamps(event *GoOTelSpanTrace) (int64, int64, error) {
	start := int64(event.StartTime)
	end := int64(event.EndTime)
	if event.StartTimeWall == 0 && event.EndTimeWall == 0 {
		return start, end, nil
	}

	wallNow := time.Now().UnixNano()
	monoNow := int64(timing.MonoTimeNow())
	if event.StartTimeWall != 0 {
		var ok bool
		start, ok = translateAutoSpanTimestamp(start, wallNow, monoNow)
		if !ok {
			return 0, 0, errors.New("invalid Go OTel span start timestamp: overflows monotonic time")
		}
	}
	if event.EndTimeWall != 0 {
		var ok bool
		end, ok = translateAutoSpanTimestamp(end, wallNow, monoNow)
		if !ok {
			return 0, 0, errors.New("invalid Go OTel span end timestamp: overflows monotonic time")
		}
	}

	return start, end, nil
}

func ReadGoAutoSpanEventIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	if record == nil {
		return request.Span{}, true, errors.New("nil Go Auto SDK span record")
	}

	headerSize := int(unsafe.Offsetof(GoAutoSpanTrace{}.Buf))
	if len(record.RawSample) < headerSize {
		return request.Span{}, true, errors.New("invalid Go Auto SDK span record: shorter than its header")
	}

	event := (*GoAutoSpanTrace)(unsafe.Pointer(unsafe.SliceData(record.RawSample)))
	size := int(event.Size)
	if size == 0 {
		return request.Span{}, true, errors.New("invalid Go Auto SDK span payload: empty")
	}
	if size > goAutoSpanJSONMaxLen {
		return request.Span{}, true, errors.New("invalid Go Auto SDK span payload: exceeds the size limit")
	}
	if size != len(record.RawSample)-headerSize {
		return request.Span{}, true, errors.New("invalid Go Auto SDK span payload: size does not match the record")
	}

	payload := record.RawSample[headerSize:]
	span, err := readAutoSpanPayload(
		payload,
		record.RawSample[goAutoSpanParentRemoteOffset] != 0,
	)
	if err != nil {
		return request.Span{}, true, err
	}

	span.ManualOTelJSON = bytes.Clone(payload)
	span.Pid = request.PidInfo{
		HostPID:   app.PID(event.Pid.HostPid),
		UserPID:   app.PID(event.Pid.UserPid),
		Namespace: event.Pid.Ns,
	}

	return span, false, nil
}

func readAutoSpanPayload(payload []byte, parentRemote bool) (request.Span, error) {
	var unmarshaler ptrace.JSONUnmarshaler
	traces, err := unmarshaler.UnmarshalTraces(payload)
	if err != nil {
		return request.Span{}, fmt.Errorf("invalid Go Auto SDK span payload: %w", err)
	}

	resourceSpans := traces.ResourceSpans()
	if resourceSpans.Len() != 1 {
		return request.Span{}, errors.New("invalid Go Auto SDK payload: expected exactly one resource span")
	}

	scopeSpans := resourceSpans.At(0).ScopeSpans()
	if scopeSpans.Len() != 1 {
		return request.Span{}, errors.New("invalid Go Auto SDK payload: expected exactly one scope span")
	}

	spans := scopeSpans.At(0).Spans()
	if spans.Len() != 1 {
		return request.Span{}, errors.New("invalid Go Auto SDK payload: expected exactly one span")
	}

	otelSpan := spans.At(0)
	traceID := trace.TraceID(otelSpan.TraceID())
	if !traceID.IsValid() {
		return request.Span{}, errors.New("invalid Go Auto SDK payload: invalid trace ID")
	}

	spanID := trace.SpanID(otelSpan.SpanID())
	if !spanID.IsValid() {
		return request.Span{}, errors.New("invalid Go Auto SDK payload: invalid span ID")
	}

	start := otelSpan.StartTimestamp()
	end := otelSpan.EndTimestamp()
	if start == 0 || end == 0 || end < start {
		return request.Span{}, errors.New("invalid Go Auto SDK payload: invalid span timestamps")
	}

	duration := uint64(end - start)
	if duration > math.MaxInt64 {
		return request.Span{}, errors.New("invalid Go Auto SDK span duration: too large")
	}
	if start > math.MaxInt64 || end > math.MaxInt64 {
		return request.Span{}, errors.New("invalid Go Auto SDK span timestamp: outside the supported range")
	}

	wallNow := time.Now().UnixNano()
	monoNow := int64(timing.MonoTimeNow())
	startMonotime, ok := translateAutoSpanTimestamp(int64(start), wallNow, monoNow)
	if !ok {
		return request.Span{}, errors.New("invalid Go Auto SDK span start timestamp: overflows monotonic time")
	}
	endMonotime, ok := translateAutoSpanTimestamp(int64(end), wallNow, monoNow)
	if !ok {
		return request.Span{}, errors.New("invalid Go Auto SDK span end timestamp: overflows monotonic time")
	}

	status, err := autoSpanStatus(otelSpan.Status().Code())
	if err != nil {
		return request.Span{}, err
	}

	spanKind := trace.ValidateSpanKind(trace.SpanKind(otelSpan.Kind()))
	peer, peerName, host, hostName := manualSpanEndpoints(
		spanKind,
		func(key attribute.Key) (string, bool) {
			value, ok := otelSpan.Attributes().Get(string(key))
			if !ok || value.Type() != pcommon.ValueTypeStr {
				return "", false
			}
			return value.Str(), true
		},
	)

	parentSpanID := trace.SpanID(otelSpan.ParentSpanID())
	flags := otelSpan.Flags()

	return request.Span{
		Type:         request.EventTypeManualSpan,
		SpanKind:     spanKind,
		Method:       otelSpan.Name(),
		Path:         otelSpan.Status().Message(),
		Route:        autoSpanRoute(otelSpan),
		Peer:         peer,
		PeerName:     peerName,
		Host:         host,
		HostName:     hostName,
		RequestStart: startMonotime,
		Start:        startMonotime,
		End:          endMonotime,
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: parentSpanID,
		TraceFlags:   uint8(flags),
		ParentRemote: parentSpanID.IsValid() && parentRemote,
		BPFDecision:  true,
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
		return nil, errors.New("invalid Go OTel attribute count")
	}

	specialAttrs := compactSpecialAttributes(event)
	attrs := make([]goOTelEncodedAttribute, 0, size+len(specialAttrs))
	for i := range event.SpanAttrs.Attrs[:size] {
		current := &event.SpanAttrs.Attrs[i]
		if compactAttributeOverridden(event, cstr(current.Key[:])) {
			continue
		}
		attrs = append(attrs, goOTelEncodedAttribute{
			ValLength: current.ValLength,
			Vtype:     current.Vtype,
			Reserved:  current.Reserved,
			Key:       current.Key,
			Value:     current.Value,
		})
	}
	attrs = append(attrs, specialAttrs...)
	if len(attrs) == 0 {
		return nil, nil
	}
	return json.Marshal(attrs)
}

func compactSpecialAttributes(event *GoOTelSpanTrace) []goOTelEncodedAttribute {
	attrs := make([]goOTelEncodedAttribute, 0, 4)
	appendStringAttr := func(state uint8, key attribute.Key, value []uint8) {
		if state != goOTelSpecialAttrValid {
			return
		}
		encoded := goOTelEncodedAttribute{Vtype: uint8(attribute.STRING)}
		copy(encoded.Key[:], string(key))
		encoded.ValLength = uint16(copy(encoded.Value[:], cstr(value)))
		attrs = append(attrs, encoded)
	}

	appendStringAttr(event.RouteState, semconv.HTTPRouteKey, event.Route[:])
	kind := trace.ValidateSpanKind(trace.SpanKind(event.SpanKind))
	if kind == trace.SpanKindInternal {
		return attrs
	}
	appendStringAttr(
		event.ServicePeerNameState,
		semconv.ServicePeerNameKey,
		event.ServicePeerName[:],
	)
	appendStringAttr(
		event.NetworkPeerAddressState,
		semconv.NetworkPeerAddressKey,
		event.NetworkPeerAddress[:],
	)
	switch kind {
	case trace.SpanKindClient, trace.SpanKindProducer:
		appendStringAttr(
			event.RemoteAddressState,
			semconv.ServerAddressKey,
			event.RemoteAddress[:],
		)
	case trace.SpanKindServer, trace.SpanKindConsumer:
		appendStringAttr(
			event.RemoteAddressState,
			semconv.ClientAddressKey,
			event.RemoteAddress[:],
		)
	}
	return attrs
}

func compactAttributeOverridden(event *GoOTelSpanTrace, key string) bool {
	_, state := compactDedicatedAttribute(event, attribute.Key(key))
	return state != goOTelSpecialAttrUnset
}

func compactSpanRoute(event *GoOTelSpanTrace) string {
	switch event.RouteState {
	case goOTelSpecialAttrValid:
		return cstr(event.Route[:])
	case goOTelSpecialAttrInvalid:
		return ""
	}
	if route := cstr(event.Route[:]); route != "" {
		return route
	}

	size := min(int(event.SpanAttrs.ValidAttrs), len(event.SpanAttrs.Attrs))
	for i := size; i > 0; i-- {
		current := &event.SpanAttrs.Attrs[i-1]
		if current.Vtype == uint8(attribute.STRING) &&
			cstr(current.Key[:]) == string(semconv.HTTPRouteKey) {
			return cstr(current.Value[:])
		}
	}
	return ""
}

func compactStringAttribute(event *GoOTelSpanTrace, key attribute.Key) (string, bool) {
	dedicated, state := compactDedicatedAttribute(event, key)
	switch state {
	case goOTelSpecialAttrValid:
		return cstr(dedicated), true
	case goOTelSpecialAttrInvalid:
		return "", false
	}

	size := min(int(event.SpanAttrs.ValidAttrs), len(event.SpanAttrs.Attrs))
	for i := size; i > 0; i-- {
		current := &event.SpanAttrs.Attrs[i-1]
		if current.Vtype == uint8(attribute.STRING) &&
			cstr(current.Key[:]) == string(key) {
			return cstr(current.Value[:]), true
		}
	}
	return "", false
}

func compactDedicatedAttribute(event *GoOTelSpanTrace, key attribute.Key) ([]uint8, uint8) {
	var dedicated []uint8
	var state uint8
	switch key {
	case semconv.HTTPRouteKey:
		dedicated = event.Route[:]
		state = event.RouteState
	case semconv.ServicePeerNameKey:
		dedicated = event.ServicePeerName[:]
		state = event.ServicePeerNameState
	case semconv.NetworkPeerAddressKey:
		dedicated = event.NetworkPeerAddress[:]
		state = event.NetworkPeerAddressState
	case semconv.ServerAddressKey:
		if kind := trace.ValidateSpanKind(trace.SpanKind(event.SpanKind)); kind == trace.SpanKindClient ||
			kind == trace.SpanKindProducer {
			dedicated = event.RemoteAddress[:]
			state = event.RemoteAddressState
		}
	case semconv.ClientAddressKey:
		if kind := trace.ValidateSpanKind(trace.SpanKind(event.SpanKind)); kind == trace.SpanKindServer ||
			kind == trace.SpanKindConsumer {
			dedicated = event.RemoteAddress[:]
			state = event.RemoteAddressState
		}
	}
	return dedicated, state
}

func manualSpanEndpoints(
	kind trace.SpanKind,
	lookup func(attribute.Key) (string, bool),
) (peer, peerName, host, hostName string) {
	servicePeer, _ := lookup(semconv.ServicePeerNameKey)
	networkPeer, _ := lookup(semconv.NetworkPeerAddressKey)

	switch kind {
	case trace.SpanKindClient, trace.SpanKindProducer:
		host, _ = lookup(semconv.ServerAddressKey)
		if host == "" {
			host = networkPeer
		}
		hostName = servicePeer
	case trace.SpanKindServer, trace.SpanKindConsumer:
		peer, _ = lookup(semconv.ClientAddressKey)
		if peer == "" {
			peer = networkPeer
		}
		peerName = servicePeer
	}
	return peer, peerName, host, hostName
}

func autoSpanRoute(span ptrace.Span) string {
	value, ok := span.Attributes().Get(string(semconv.HTTPRouteKey))
	if !ok || value.Type() != pcommon.ValueTypeStr {
		return ""
	}
	return value.Str()
}
