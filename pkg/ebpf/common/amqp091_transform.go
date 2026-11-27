// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/amqpparser"
)

// amqpDefaultExchange names the default exchange, which has no name on the wire
const amqpDefaultExchange = "amq.default"

// ReadAMQP091MessageIntoSpan converts a message event of
// bpf/generictracer/protocol_amqp.h into its messaging span.
func ReadAMQP091MessageIntoSpan(record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	event, err := ReinterpretCast[BpfAmqpMsgEventT](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	if !filter.ValidPID(app.PID(event.Pid.UserPid), event.Pid.Ns, PIDTypeKProbes) {
		return request.Span{}, true, nil
	}

	methodLen := min(int(event.MethodLen), len(event.Method))
	msg, err := amqpparser.ParseMethod091(event.Method[:methodLen])
	if errors.Is(err, amqpparser.ErrNotMessage091) {
		return request.Span{}, true, err
	}

	// a method frame longer than the kernel copied keeps the names up to the cut;
	// one cut before them would be reported as the default exchange
	if err != nil && msg.Exchange == "" && msg.RoutingKey == "" {
		return request.Span{}, true, err
	}
	return amqp091MessageToSpan(event, &msg), false, nil
}

func amqp091MessageToSpan(event *BpfAmqpMsgEventT, msg *amqpparser.Message091) request.Span {
	peer, host := (*BPFConnInfo)(&event.ConnInfo).reqHostInfo()

	return request.Span{
		Type:              request.EventTypeAMQPClient,
		SubType:           request.AMQPSubtype091,
		Method:            amqp091Operation(msg.Operation),
		Path:              amqpDestination(msg.Exchange, msg.RoutingKey),
		Peer:              peer,
		PeerPort:          int(event.ConnInfo.S_port),
		Host:              host,
		HostPort:          int(event.ConnInfo.D_port),
		RequestStart:      int64(event.StartMonotimeNs),
		Start:             int64(event.StartMonotimeNs),
		End:               int64(event.EndMonotimeNs),
		TraceID:           event.Tp.TraceId,
		SpanID:            event.Tp.SpanId,
		ParentSpanID:      event.Tp.ParentId,
		TraceFlags:        event.Tp.Flags,
		ParentConditional: event.ParentStatus == parentStatusConditional,
		Pid: request.PidInfo{
			HostPID:   app.PID(event.Pid.HostPid),
			UserPID:   app.PID(event.Pid.UserPid),
			Namespace: event.Pid.Ns,
		},
		MessagingInfo: &request.MessagingInfo{
			RoutingKey:     msg.RoutingKey,
			DeliveryTag:    msg.DeliveryTag,
			HasDeliveryTag: msg.Operation != amqpparser.Publish091,
		},
	}
}

func amqp091Operation(op amqpparser.Operation091) string {
	switch op {
	case amqpparser.Deliver091:
		return request.MessagingProcess
	case amqpparser.GetOk091:
		return request.MessagingReceive
	default:
		return request.MessagingPublish
	}
}

// amqpDestination names a RabbitMQ destination as semantic conventions do. A
// delivery does not name the queue it came from, so the consumer side omits it.
func amqpDestination(exchange, routingKey string) string {
	switch {
	case exchange != "" && routingKey != "":
		return exchange + ":" + routingKey
	case exchange != "":
		return exchange
	case routingKey != "":
		return routingKey
	}
	return amqpDefaultExchange
}
