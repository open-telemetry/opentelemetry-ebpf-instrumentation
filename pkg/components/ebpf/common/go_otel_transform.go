package ebpfcommon

import (
	"go.opentelemetry.io/otel/trace"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"
)

func ReadGoOTelEventIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[GoOTelSpanTrace](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	name := cstr(event.SpanName.Buf[:])

	return request.Span{
		Type:          request.EventTypeManualSpan,
		Method:        name,
		Statement:     "",
		Path:          "",
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
		Status:        0,
		Pid: request.PidInfo{
			HostPID:   event.Pid.HostPid,
			UserPID:   event.Pid.UserPid,
			Namespace: event.Pid.Ns,
		},
	}, false, nil
}
