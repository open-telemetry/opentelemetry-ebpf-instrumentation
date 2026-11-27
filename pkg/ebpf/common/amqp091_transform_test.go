// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

// amqpMethod091 builds a Basic method frame payload: class 60, the method id, its arguments
func amqpMethod091(methodID uint16, args ...[]byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, 60)
	b = binary.BigEndian.AppendUint16(b, methodID)
	for _, a := range args {
		b = append(b, a...)
	}
	return b
}

func amqpShortStr091(s string) []byte {
	return append([]byte{byte(len(s))}, s...)
}

func amqp091Record(t *testing.T, method []byte, parentStatus uint8) *ringbuf.Record {
	t.Helper()

	event := BpfAmqpMsgEventT{
		Type:            EventTypeAMQPMessage,
		ParentStatus:    parentStatus,
		StartMonotimeNs: 100,
		EndMonotimeNs:   150,
	}
	event.MethodLen = uint16(copy(event.Method[:], method))
	event.ConnInfo.S_addr = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2}
	event.ConnInfo.D_addr = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1}
	event.ConnInfo.S_port = 54321
	event.ConnInfo.D_port = 5672
	event.Pid.HostPid = 1234
	event.Tp.TraceId = [16]uint8{1}
	event.Tp.SpanId = [8]uint8{2}
	event.Tp.ParentId = [8]uint8{3}

	raw := unsafe.Slice((*byte)(unsafe.Pointer(&event)), int(unsafe.Sizeof(event)))
	return &ringbuf.Record{RawSample: append([]byte(nil), raw...)}
}

func TestReadAMQP091MessageIntoSpan(t *testing.T) {
	const publish, deliver, getOk = 40, 60, 71
	ticket, bits := []byte{0, 0}, []byte{0}
	deliveryTag := append(binary.BigEndian.AppendUint64(nil, 9), 0)

	tests := []struct {
		name         string
		method       []byte
		wantMethod   string
		wantPath     string
		wantRouting  string
		wantDelivery bool
	}{
		{
			name:       "publish to a named exchange",
			method:     amqpMethod091(publish, ticket, amqpShortStr091("logs"), amqpShortStr091("warning"), bits),
			wantMethod: request.MessagingPublish, wantPath: "logs:warning", wantRouting: "warning",
		},
		{
			name:       "publish to the default exchange",
			method:     amqpMethod091(publish, ticket, amqpShortStr091(""), amqpShortStr091("tasks"), bits),
			wantMethod: request.MessagingPublish, wantPath: "tasks", wantRouting: "tasks",
		},
		{
			name:       "publish to a fanout exchange",
			method:     amqpMethod091(publish, ticket, amqpShortStr091("events"), amqpShortStr091(""), bits),
			wantMethod: request.MessagingPublish, wantPath: "events",
		},
		{
			name:       "publish without exchange or routing key",
			method:     amqpMethod091(publish, ticket, amqpShortStr091(""), amqpShortStr091(""), bits),
			wantMethod: request.MessagingPublish, wantPath: "amq.default",
		},
		{
			name: "deliver",
			method: amqpMethod091(deliver, amqpShortStr091("ctag1.0"), deliveryTag,
				amqpShortStr091(""), amqpShortStr091("tasks")),
			wantMethod: request.MessagingProcess, wantPath: "tasks", wantRouting: "tasks", wantDelivery: true,
		},
		{
			name: "get-ok",
			method: amqpMethod091(getOk, deliveryTag, amqpShortStr091("logs"),
				amqpShortStr091("warning"), []byte{0, 0, 0, 0}),
			wantMethod: request.MessagingReceive, wantPath: "logs:warning", wantRouting: "warning", wantDelivery: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			span, ignore, err := ReadAMQP091MessageIntoSpan(amqp091Record(t, tt.method, 0), &IdentityPidsFilter{})
			require.NoError(t, err)
			require.False(t, ignore)

			assert.Equal(t, request.EventTypeAMQPClient, span.Type)
			assert.Equal(t, request.AMQPSubtype091, span.SubType)
			assert.Equal(t, tt.wantMethod, span.Method)
			assert.Equal(t, tt.wantPath, span.Path)
			assert.Equal(t, "10.0.0.1", span.Host)
			assert.Equal(t, 5672, span.HostPort)
			assert.Equal(t, "10.0.0.2", span.Peer)
			assert.Equal(t, 54321, span.PeerPort)
			assert.Equal(t, int64(100), span.Start)
			assert.Equal(t, int64(150), span.End)
			assert.Equal(t, [16]uint8{1}, [16]uint8(span.TraceID))
			assert.Equal(t, [8]uint8{3}, [8]uint8(span.ParentSpanID))
			assert.False(t, span.ParentConditional)

			require.NotNil(t, span.MessagingInfo)
			assert.Equal(t, tt.wantRouting, span.MessagingInfo.RoutingKey)
			assert.Equal(t, tt.wantDelivery, span.MessagingInfo.HasDeliveryTag)
			if tt.wantDelivery {
				assert.Equal(t, uint64(9), span.MessagingInfo.DeliveryTag)
			}
		})
	}
}

func TestReadAMQP091MessageIntoSpanParentConditional(t *testing.T) {
	method := amqpMethod091(40, []byte{0, 0}, amqpShortStr091(""), amqpShortStr091("tasks"), []byte{0})
	span, ignore, err := ReadAMQP091MessageIntoSpan(amqp091Record(t, method, parentStatusConditional), &IdentityPidsFilter{})
	require.NoError(t, err)
	require.False(t, ignore)
	assert.True(t, span.ParentConditional)
}

func TestReadAMQP091MessageIntoSpanCutMethod(t *testing.T) {
	method := amqpMethod091(40, []byte{0, 0}, amqpShortStr091("logs"), amqpShortStr091("warning"))
	span, ignore, err := ReadAMQP091MessageIntoSpan(amqp091Record(t, method[:len(method)-len("ning")], 0), &IdentityPidsFilter{})
	require.NoError(t, err)
	require.False(t, ignore)
	assert.Equal(t, "logs:war", span.Path)
}

func TestReadAMQP091MessageIntoSpanCutBeforeDestination(t *testing.T) {
	const publish, deliver, getOk = 40, 60, 71
	deliveryTag := append(binary.BigEndian.AppendUint64(nil, 9), 0)

	for name, method := range map[string][]byte{
		"publish inside the ticket":              amqpMethod091(publish, []byte{0}),
		"publish to the default exchange":        amqpMethod091(publish, []byte{0, 0}, amqpShortStr091("")),
		"publish after the routing key's length": amqpMethod091(publish, []byte{0, 0}, amqpShortStr091(""), []byte{5}),
		"deliver inside the consumer tag":        amqpMethod091(deliver, []byte{7}, []byte("ctag")),
		"deliver inside the delivery tag":        amqpMethod091(deliver, amqpShortStr091("ctag1.0"), deliveryTag[:4]),
		"get-ok before the exchange":             amqpMethod091(getOk, deliveryTag),
	} {
		t.Run(name, func(t *testing.T) {
			_, ignore, err := ReadAMQP091MessageIntoSpan(amqp091Record(t, method, 0), &IdentityPidsFilter{})
			require.Error(t, err)
			assert.True(t, ignore)
		})
	}
}

func TestReadAMQP091MessageIntoSpanIgnoresOtherMethods(t *testing.T) {
	const ack = 80
	method := amqpMethod091(ack, binary.BigEndian.AppendUint64(nil, 1), []byte{0})
	_, ignore, err := ReadAMQP091MessageIntoSpan(amqp091Record(t, method, 0), &IdentityPidsFilter{})
	require.Error(t, err)
	assert.True(t, ignore)
}
