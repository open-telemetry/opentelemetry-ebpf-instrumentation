// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

const (
	testDescriptorFlow     byte = 0x13
	testDescriptorTransfer byte = 0x14
)

func makeAMQP10Header(protocolID byte) []byte {
	return []byte{'A', 'M', 'Q', 'P', protocolID, 1, 0, 0}
}

func makeAMQPSmallPerformativeFrame(descriptor byte) []byte {
	body := []byte{0x00, 0x53, descriptor, 0x45}
	frame := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(frame)))
	frame[4] = 2
	frame[5] = 0x00
	copy(frame[8:], body)
	return frame
}

func TestProcessPossibleAMQPEvent(t *testing.T) {
	t.Run("request with transfer does not reverse", func(t *testing.T) {
		event := &TCPRequestInfo{Direction: directionSend}
		pkt := append(makeAMQP10Header(0), makeAMQPSmallPerformativeFrame(testDescriptorTransfer)...)

		infos, ignore, err := ProcessPossibleAMQPEvent(event, largebuf.NewLargeBufferFrom(pkt), largebuf.NewLargeBuffer())
		require.NoError(t, err)
		assert.False(t, ignore)
		require.Len(t, infos, 1)
		assert.EqualValues(t, directionSend, infos[0].Direction)
		assert.EqualValues(t, directionSend, event.Direction)
	})

	t.Run("malformed request with valid response yields response transfer", func(t *testing.T) {
		// Invariant: a broken request buffer does not discard valid transfers parsed
		// from the response buffer; event direction is preserved.
		event := &TCPRequestInfo{
			Direction: directionSend,
			ConnInfo: BpfConnectionInfoT{
				S_port: 5672,
				D_port: 8080,
			},
		}
		bad := []byte{'A', 'M', 'Q', 'P', 9, 1, 0, 0}
		resp := append(makeAMQP10Header(0), makeAMQPSmallPerformativeFrame(testDescriptorTransfer)...)

		infos, ignore, err := ProcessPossibleAMQPEvent(event, largebuf.NewLargeBufferFrom(bad), largebuf.NewLargeBufferFrom(resp))
		require.NoError(t, err)
		assert.False(t, ignore)
		require.Len(t, infos, 1)
		assert.EqualValues(t, directionRecv, infos[0].Direction)
		assert.EqualValues(t, directionSend, event.Direction)
		assert.Equal(t, uint16(5672), event.ConnInfo.S_port)
		assert.Equal(t, uint16(8080), event.ConnInfo.D_port)
	})

	t.Run("both sides malformed surfaces error", func(t *testing.T) {
		event := &TCPRequestInfo{Direction: directionSend}
		bad := []byte{'A', 'M', 'Q', 'P', 9, 1, 0, 0}

		infos, ignore, err := ProcessPossibleAMQPEvent(event, largebuf.NewLargeBufferFrom(bad), largebuf.NewLargeBufferFrom(bad))
		require.Error(t, err)
		assert.True(t, ignore)
		assert.Empty(t, infos)
	})

	t.Run("request control frame and response transfer do not reverse event", func(t *testing.T) {
		event := &TCPRequestInfo{
			Direction: directionSend,
			ConnInfo: BpfConnectionInfoT{
				S_port: 5672,
				D_port: 8080,
			},
		}
		req := append(makeAMQP10Header(0), makeAMQPSmallPerformativeFrame(testDescriptorFlow)...)
		resp := append(makeAMQP10Header(0), makeAMQPSmallPerformativeFrame(testDescriptorTransfer)...)

		infos, ignore, err := ProcessPossibleAMQPEvent(event, largebuf.NewLargeBufferFrom(req), largebuf.NewLargeBufferFrom(resp))
		require.NoError(t, err)
		assert.False(t, ignore)
		require.Len(t, infos, 1)
		assert.EqualValues(t, directionRecv, infos[0].Direction)
		assert.EqualValues(t, directionSend, event.Direction)
		assert.Equal(t, uint16(5672), event.ConnInfo.S_port)
		assert.Equal(t, uint16(8080), event.ConnInfo.D_port)
	})

	t.Run("response-only transfer preserves event and reports receive direction", func(t *testing.T) {
		event := &TCPRequestInfo{
			Direction: directionSend,
			ConnInfo: BpfConnectionInfoT{
				S_port: 5672,
				D_port: 8080,
			},
		}
		resp := append(makeAMQP10Header(0), makeAMQPSmallPerformativeFrame(testDescriptorTransfer)...)

		// Invariant: an empty or non-AMQP request is not an AMQP-ish violation, so
		// the response side is inspected and, if it carries a transfer, reported as
		// a receive-direction transfer without mutating the event.
		infos, ignore, err := ProcessPossibleAMQPEvent(event, largebuf.NewLargeBufferFrom([]byte{}), largebuf.NewLargeBufferFrom(resp))
		require.NoError(t, err)
		assert.False(t, ignore)
		require.Len(t, infos, 1)
		assert.EqualValues(t, directionRecv, infos[0].Direction)
		assert.EqualValues(t, directionSend, event.Direction)
		assert.Equal(t, uint16(5672), event.ConnInfo.S_port)
		assert.Equal(t, uint16(8080), event.ConnInfo.D_port)
	})

	t.Run("multiple transfers yield multiple infos", func(t *testing.T) {
		event := &TCPRequestInfo{
			Direction: directionSend,
			ConnInfo: BpfConnectionInfoT{
				S_port: 43210,
				D_port: 5672,
			},
		}
		payload := make([]byte, 0)
		payload = append(payload, makeAMQP10Header(0)...)
		payload = append(payload, makeAMQPSmallPerformativeFrame(testDescriptorTransfer)...)
		payload = append(payload, makeAMQPSmallPerformativeFrame(testDescriptorTransfer)...)

		infos, ignore, err := ProcessPossibleAMQPEvent(event, largebuf.NewLargeBufferFrom(payload), largebuf.NewLargeBuffer())
		require.NoError(t, err)
		assert.False(t, ignore)
		require.Len(t, infos, 2)
		for _, info := range infos {
			assert.EqualValues(t, directionSend, info.Direction)
		}
	})
}

func TestProcessAMQPBufferLooksLikeAMQP(t *testing.T) {
	looks, infos, err := processAMQPBuffer(largebuf.NewLargeBufferFrom(makeAMQP10Header(0)), directionSend)
	require.NoError(t, err)
	assert.True(t, looks)
	assert.Empty(t, infos)

	frameOnly := makeAMQPSmallPerformativeFrame(testDescriptorTransfer)
	looks, infos, err = processAMQPBuffer(largebuf.NewLargeBufferFrom(frameOnly), directionSend)
	require.NoError(t, err)
	assert.True(t, looks)
	require.Len(t, infos, 1)

	looks, infos, err = processAMQPBuffer(largebuf.NewLargeBufferFrom([]byte("GET / HTTP/1.1\r\n")), directionSend)
	require.NoError(t, err)
	assert.False(t, looks)
	assert.Empty(t, infos)

	looks, infos, err = processAMQPBuffer(nil, directionSend)
	require.NoError(t, err)
	assert.False(t, looks)
	assert.Empty(t, infos)

	// Regression: a bare frame header for a non-AMQP protocol must NOT look like AMQP.
	// Kafka-style size-prefixed packet with api_key=0 would previously false-positive.
	kafka := []byte{
		0x00, 0x00, 0x00, 0x1c,
		0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x02, 'k', 'p', 0x00, 0x01, 0x00, 0x00, 0x03, 0xe8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	looks, infos, err = processAMQPBuffer(largebuf.NewLargeBufferFrom(kafka), directionSend)
	require.NoError(t, err)
	assert.False(t, looks)
	assert.Empty(t, infos)

	// AMQP-shaped bytes that fail to parse: looks=true, err!=nil. A valid protocol
	// header proves AMQP, and the following malformed frame surfaces the error.
	bad := append(makeAMQP10Header(0), []byte{0x00, 0x00, 0x00, 0x08, 0x02, 0xFF, 0x00, 0x00}...)
	looks, infos, err = processAMQPBuffer(largebuf.NewLargeBufferFrom(bad), directionSend)
	require.Error(t, err)
	assert.True(t, looks)
	assert.Empty(t, infos)
}

func TestTCPToAMQPSpan(t *testing.T) {
	t.Run("publish uses broker as server", func(t *testing.T) {
		trace := &TCPRequestInfo{
			StartMonotimeNs: 100,
			EndMonotimeNs:   200,
			Direction:       directionSend,
			ConnInfo: BpfConnectionInfoT{
				S_port: 54321,
				D_port: 5672,
			},
		}
		trace.Pid.HostPid = 123
		trace.Pid.UserPid = 124
		trace.Pid.Ns = 55

		span := TCPToAMQPToSpan(trace, AMQPInfo{Direction: directionSend})
		assert.Equal(t, request.EventTypeAMQPClient, span.Type)
		assert.Equal(t, request.MessagingPublish, span.Method)
		assert.Empty(t, span.Path)
		assert.Empty(t, span.Statement)
		assert.Equal(t, 54321, span.PeerPort)
		assert.Equal(t, 5672, span.HostPort)
		assert.EqualValues(t, 123, span.Pid.HostPID)
		assert.EqualValues(t, 124, span.Pid.UserPID)
	})

	t.Run("process uses broker as server", func(t *testing.T) {
		trace := &TCPRequestInfo{
			StartMonotimeNs: 100,
			EndMonotimeNs:   200,
			Direction:       directionSend,
			ConnInfo: BpfConnectionInfoT{
				S_port: 54321,
				D_port: 5672,
			},
		}

		span := TCPToAMQPToSpan(trace, AMQPInfo{Direction: directionRecv})
		assert.Equal(t, request.EventTypeAMQPClient, span.Type)
		assert.Equal(t, request.MessagingProcess, span.Method)
		assert.Equal(t, 54321, span.PeerPort)
		assert.Equal(t, 5672, span.HostPort)
	})
}

func TestAMQPOperation(t *testing.T) {
	assert.Equal(t, request.MessagingPublish, amqpOperation(directionSend))
	assert.Equal(t, request.MessagingProcess, amqpOperation(directionRecv))
}

func TestMatchAMQP(t *testing.T) {
	t.Run("valid AMQP transfer matches", func(t *testing.T) {
		event := &TCPRequestInfo{Direction: directionSend}
		payload := append(makeAMQP10Header(0), makeAMQPSmallPerformativeFrame(testDescriptorTransfer)...)

		span, ignore, matched, err := matchAMQP(NewEBPFParseContext(nil, nil, nil), event, largebuf.NewLargeBufferFrom(payload), largebuf.NewLargeBuffer())
		require.NoError(t, err)
		assert.False(t, ignore)
		assert.True(t, matched)
		assert.Equal(t, request.EventTypeAMQPClient, span.Type)
	})

	t.Run("header-only AMQP is dropped rather than reclassified", func(t *testing.T) {
		event := &TCPRequestInfo{Direction: directionSend}
		payload := makeAMQP10Header(0)

		span, ignore, matched, err := matchAMQP(NewEBPFParseContext(nil, nil, nil), event, largebuf.NewLargeBufferFrom(payload), largebuf.NewLargeBuffer())
		require.NoError(t, err)
		assert.True(t, ignore)
		assert.True(t, matched)
		assert.Equal(t, request.Span{}, span)
	})

	t.Run("broken AMQP bytes drop event instead of falling to MQTT/Kafka", func(t *testing.T) {
		event := &TCPRequestInfo{Direction: directionSend}
		// Valid protocol header followed by a frame with an invalid frame type (0xFF).
		// Strongly AMQP-shaped, but the parser rejects it.
		bad := append(makeAMQP10Header(0), []byte{0x00, 0x00, 0x00, 0x08, 0x02, 0xFF, 0x00, 0x00}...)

		span, ignore, matched, err := matchAMQP(NewEBPFParseContext(nil, nil, nil), event, largebuf.NewLargeBufferFrom(bad), largebuf.NewLargeBuffer())
		require.NoError(t, err)
		assert.True(t, ignore)
		assert.True(t, matched)
		assert.Equal(t, request.Span{}, span)
	})

	t.Run("non-AMQP traffic does not match", func(t *testing.T) {
		event := &TCPRequestInfo{Direction: directionSend}
		cases := map[string][]byte{
			"MQTT CONNECT": {
				0x10, 0x0e,
				0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c,
				0x00, 0x02, 'c', '1',
			},
			"Kafka Produce": {
				0x00, 0x00, 0x00, 0x1c,
				0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x02, 'k', 'p', 0x00, 0x01, 0x00, 0x00, 0x03, 0xe8,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			"HTTP/2 preface":  []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
			"Redis INLINE":    []byte("PING\r\n"),
			"TLS ClientHello": {0x16, 0x03, 0x01, 0x00, 0x2e, 0x01, 0x00, 0x00, 0x2a, 0x03, 0x03},
			"HTTP/1.1":        []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		}
		for name, bytes := range cases {
			t.Run(name, func(t *testing.T) {
				_, _, matched, err := matchAMQP(NewEBPFParseContext(nil, nil, nil), event, largebuf.NewLargeBufferFrom(bytes), largebuf.NewLargeBuffer())
				require.NoError(t, err)
				assert.False(t, matched, "matchAMQP must yield on %s so sibling matchers can run", name)
			})
		}
	})

	t.Run("multiple transfers emit extra spans", func(t *testing.T) {
		event := &TCPRequestInfo{
			Direction: directionSend,
			ConnInfo: BpfConnectionInfoT{
				S_port: 43210,
				D_port: 5672,
			},
		}
		payload := append(makeAMQP10Header(0), makeAMQPSmallPerformativeFrame(testDescriptorTransfer)...)
		payload = append(payload, makeAMQPSmallPerformativeFrame(testDescriptorTransfer)...)
		payload = append(payload, makeAMQPSmallPerformativeFrame(testDescriptorTransfer)...)

		ctx := NewEBPFParseContext(nil, nil, nil)
		span, ignore, matched, err := matchAMQP(ctx, event, largebuf.NewLargeBufferFrom(payload), largebuf.NewLargeBuffer())
		require.NoError(t, err)
		assert.False(t, ignore)
		assert.True(t, matched)
		assert.Equal(t, request.EventTypeAMQPClient, span.Type)
		// The first transfer returns synchronously; the remaining two are emitted via emitExtraSpans.
	})
}
