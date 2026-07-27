// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amqpparser

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func makeProtocolHeader(id protocolID) []byte {
	return []byte{'A', 'M', 'Q', 'P', byte(id), 1, 0, 0}
}

// makeFrame builds an AMQP frame with a smallulong descriptor and a single boolean-true field.
func makeFrame(ft frameType, descriptor descriptor) []byte {
	return makeFrameOnChannel(ft, descriptor, 0)
}

func makeFrameOnChannel(ft frameType, descriptor descriptor, channel uint16) []byte {
	body := []byte{describedTypeConstructor, formatCodeSmallULong, byte(descriptor), 0x45}
	frame := make([]byte, frameHeaderSize+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(frame)))
	frame[4] = minDataOffsetWords
	frame[5] = byte(ft)
	binary.BigEndian.PutUint16(frame[6:8], channel)
	copy(frame[frameHeaderSize:], body)
	return frame
}

func makeULongFrame(ft frameType, descriptor descriptor) []byte {
	body := make([]byte, uLongDescriptorSize)
	body[0] = describedTypeConstructor
	body[1] = formatCodeULong
	binary.BigEndian.PutUint64(body[2:], uint64(descriptor))

	frame := make([]byte, frameHeaderSize+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(frame)))
	frame[4] = minDataOffsetWords
	frame[5] = byte(ft)
	copy(frame[frameHeaderSize:], body)
	return frame
}

func makeHeartbeatFrame() []byte {
	frame := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint32(frame[:4], frameHeaderSize)
	frame[4] = minDataOffsetWords
	frame[5] = byte(frameTypeAMQP)
	return frame
}

func newLargeBufferReader(data []byte) *largebuf.LargeBufferReader {
	lb := largebuf.NewLargeBufferFrom(data)
	reader := lb.NewReader()
	return &reader
}

func parseTransferPresence(data []byte) (bool, bool, error) {
	result, err := Parse(newLargeBufferReader(data))
	if err != nil {
		return result.LooksLikeAMQP, false, err
	}
	return result.LooksLikeAMQP, result.TransferCount > 0, nil
}

func TestParseTransferPresenceHappyPath(t *testing.T) {
	t.Run("protocol header plus transfer frame (smallulong)", func(t *testing.T) {
		payload := append(makeProtocolHeader(protocolIDAMQP), makeFrame(frameTypeAMQP, descriptorTransfer)...)
		looks, transfer, err := parseTransferPresence(payload)
		require.NoError(t, err)
		assert.True(t, looks)
		assert.True(t, transfer)
	})

	t.Run("ulong descriptor encoding", func(t *testing.T) {
		payload := append(makeProtocolHeader(protocolIDAMQP), makeULongFrame(frameTypeAMQP, descriptorTransfer)...)
		looks, transfer, err := parseTransferPresence(payload)
		require.NoError(t, err)
		assert.True(t, looks)
		assert.True(t, transfer)
	})

	t.Run("SASL negotiation followed by AMQP transfer", func(t *testing.T) {
		payload := make([]byte, 0)
		payload = append(payload, makeProtocolHeader(protocolIDSASL)...)
		payload = append(payload, makeFrame(frameTypeSASL, descriptorSASLMechanisms)...)
		payload = append(payload, makeFrame(frameTypeSASL, descriptorSASLOutcome)...)
		payload = append(payload, makeProtocolHeader(protocolIDAMQP)...)
		payload = append(payload, makeFrame(frameTypeAMQP, descriptorOpen)...)
		payload = append(payload, makeFrame(frameTypeAMQP, descriptorBegin)...)
		payload = append(payload, makeFrame(frameTypeAMQP, descriptorAttach)...)
		payload = append(payload, makeFrame(frameTypeAMQP, descriptorFlow)...)
		payload = append(payload, makeHeartbeatFrame()...)
		payload = append(payload, makeFrame(frameTypeAMQP, descriptorTransfer)...)

		looks, transfer, err := parseTransferPresence(payload)
		require.NoError(t, err)
		assert.True(t, looks)
		assert.True(t, transfer)
	})

	t.Run("mid-stream capture: frame without protocol header", func(t *testing.T) {
		payload := makeFrame(frameTypeAMQP, descriptorTransfer)
		looks, transfer, err := parseTransferPresence(payload)
		require.NoError(t, err)
		assert.True(t, looks)
		assert.True(t, transfer)
	})

	t.Run("heartbeat frame only is not distinctive enough", func(t *testing.T) {
		looks, transfer, err := parseTransferPresence(makeHeartbeatFrame())
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNotAMQP)
		assert.False(t, looks)
		assert.False(t, transfer)
	})
}

func TestParseTransferCount(t *testing.T) {
	payload := make([]byte, 0)
	payload = append(payload, makeProtocolHeader(protocolIDAMQP)...)
	payload = append(payload, makeFrameOnChannel(frameTypeAMQP, descriptorOpen, 1)...)
	payload = append(payload, makeFrameOnChannel(frameTypeAMQP, descriptorAttach, 1)...)
	payload = append(payload, makeFrameOnChannel(frameTypeAMQP, descriptorTransfer, 2)...)
	payload = append(payload, makeFrameOnChannel(frameTypeAMQP, descriptorTransfer, 3)...)

	result, err := Parse(newLargeBufferReader(payload))
	require.NoError(t, err)
	require.True(t, result.LooksLikeAMQP)
	assert.Equal(t, 2, result.TransferCount)
}

func TestParseAcrossChunks(t *testing.T) {
	payload := append(makeProtocolHeader(protocolIDAMQP), makeFrame(frameTypeAMQP, descriptorTransfer)...)
	lb := largebuf.NewLargeBuffer()
	lb.AppendChunk(payload[:5])
	lb.AppendChunk(payload[5:11])
	lb.AppendChunk(payload[11:])

	reader := lb.NewReader()
	result, err := Parse(&reader)
	require.NoError(t, err)
	assert.True(t, result.LooksLikeAMQP)
	assert.Equal(t, 1, result.TransferCount)
}

func TestParseProtocolHeaderNegotiation(t *testing.T) {
	looks, transfer, err := parseTransferPresence(makeProtocolHeader(protocolIDAMQP))
	require.NoError(t, err)
	assert.True(t, looks)
	assert.False(t, transfer)
}

func TestParseTruncatedTransferBody(t *testing.T) {
	frame := makeFrame(frameTypeAMQP, descriptorTransfer)
	payload := append(makeProtocolHeader(protocolIDAMQP), frame[:len(frame)-1]...)

	looks, transfer, err := parseTransferPresence(payload)
	require.NoError(t, err)
	assert.True(t, looks)
	assert.True(t, transfer)
}

func TestParseTruncatedControlBody(t *testing.T) {
	frame := makeFrame(frameTypeAMQP, descriptorFlow)
	payload := append(makeProtocolHeader(protocolIDAMQP), frame[:len(frame)-1]...)

	looks, transfer, err := parseTransferPresence(payload)
	require.NoError(t, err)
	assert.True(t, looks)
	assert.False(t, transfer)
}

func TestParseAdversarial(t *testing.T) {
	t.Run("MQTT CONNECT bytes are not AMQP", func(t *testing.T) {
		mqttConnect := []byte{
			0x10, 0x0e,
			0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3c,
			0x00, 0x02, 'c', '1',
		}
		looks, transfer, err := parseTransferPresence(mqttConnect)
		require.Error(t, err)
		assert.False(t, looks)
		assert.False(t, transfer)
	})

	t.Run("Kafka Produce request bytes are not AMQP", func(t *testing.T) {
		// size=28, api_key=0 (Produce), api_version=7, correlation_id=1, client_id="kp".
		// api_key=0 places a zero at the doff position; doff < 2 fails, and with no
		// prior AMQP magic the error surfaces as ErrNotAMQP.
		kafka := []byte{
			0x00, 0x00, 0x00, 0x1c,
			0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x02, 'k', 'p', 0x00, 0x01, 0x00, 0x00, 0x03, 0xe8,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
		looks, transfer, err := parseTransferPresence(kafka)
		require.Error(t, err)
		assert.False(t, looks)
		assert.False(t, transfer)
	})

	t.Run("TLS ClientHello bytes are not AMQP", func(t *testing.T) {
		tls := []byte{0x16, 0x03, 0x01, 0x00, 0x2e, 0x01, 0x00, 0x00, 0x2a, 0x03, 0x03}
		looks, _, err := parseTransferPresence(tls)
		require.Error(t, err)
		assert.False(t, looks)
	})

	t.Run("AMQP 0-9-1 handshake is rejected as wrong version", func(t *testing.T) {
		looks, _, err := parseTransferPresence([]byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1})
		require.Error(t, err)
		assert.False(t, looks)
	})

	t.Run("size 0x7FFFFFFF with short buffer does not panic", func(t *testing.T) {
		frame := make([]byte, frameHeaderSize)
		binary.BigEndian.PutUint32(frame[:4], 0x7FFFFFFF)
		frame[4] = minDataOffsetWords
		frame[5] = byte(frameTypeAMQP)

		// Bare frame-header-looking bytes without a parseable descriptor must not
		// look AMQP; the call must not panic and must report not-AMQP.
		looks, transfer, err := parseTransferPresence(frame)
		require.Error(t, err)
		assert.False(t, looks)
		assert.False(t, transfer)
	})
}

func TestParseEmptyBuffer(t *testing.T) {
	looks, transfer, err := parseTransferPresence(nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNotAMQP)
	assert.False(t, looks)
	assert.False(t, transfer)
}

func TestParseShortBufferIsNotAMQP(t *testing.T) {
	looks, transfer, err := parseTransferPresence([]byte{'A'})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNotAMQP)
	assert.False(t, looks)
	assert.False(t, transfer)
}

func TestParseFrameIterationCap(t *testing.T) {
	// Pack more than maxFramesParsed non-transfer frames and assert parsing stops.
	payload := make([]byte, 0)
	for i := 0; i < maxFramesParsed+4; i++ {
		payload = append(payload, makeFrame(frameTypeAMQP, descriptorOpen)...)
	}

	result, err := Parse(newLargeBufferReader(payload))
	require.NoError(t, err)
	assert.True(t, result.LooksLikeAMQP)
	assert.Zero(t, result.TransferCount)
}
