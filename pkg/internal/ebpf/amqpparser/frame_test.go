// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amqpparser

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseTestFrameHeader(frame []byte) (frameHeader, error) {
	return parseFrameHeader(newLargeBufferReader(frame))
}

func parseTestPerformativeDescriptor(frame []byte, header frameHeader) (descriptor, bool, error) {
	return parsePerformativeDescriptor(newLargeBufferReader(frame), 0, header)
}

func TestParseFrameHeader(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		frame := makeFrame(frameTypeAMQP, descriptorOpen)
		h, err := parseTestFrameHeader(frame)
		require.NoError(t, err)
		assert.EqualValues(t, len(frame), h.Size)
		assert.EqualValues(t, minDataOffsetWords, h.DataOffsetWords)
		assert.Equal(t, frameTypeAMQP, h.Type)
		assert.Equal(t, frameHeaderSize, h.bodyOffset())
	})

	t.Run("too-short buffer", func(t *testing.T) {
		_, err := parseTestFrameHeader([]byte{0x00, 0x00, 0x00, 0x08, 0x02})
		require.Error(t, err)
	})

	t.Run("size smaller than header is rejected", func(t *testing.T) {
		frame := make([]byte, frameHeaderSize)
		binary.BigEndian.PutUint32(frame[:4], frameHeaderSize-1)
		frame[4] = minDataOffsetWords
		_, err := parseTestFrameHeader(frame)
		require.Error(t, err)
	})

	t.Run("size larger than buffer returns errIncompleteFrame", func(t *testing.T) {
		frame := make([]byte, frameHeaderSize)
		binary.BigEndian.PutUint32(frame[:4], frameHeaderSize+16)
		frame[4] = minDataOffsetWords
		frame[5] = byte(frameTypeAMQP)
		_, err := parseTestFrameHeader(frame)
		require.Error(t, err)
		assert.ErrorIs(t, err, errIncompleteFrame)
	})

	t.Run("doff=0 is rejected", func(t *testing.T) {
		frame := make([]byte, frameHeaderSize)
		binary.BigEndian.PutUint32(frame[:4], frameHeaderSize)
		frame[4] = 0
		_, err := parseTestFrameHeader(frame)
		require.Error(t, err)
	})

	t.Run("doff=1 is rejected", func(t *testing.T) {
		frame := make([]byte, frameHeaderSize)
		binary.BigEndian.PutUint32(frame[:4], frameHeaderSize)
		frame[4] = 1
		_, err := parseTestFrameHeader(frame)
		require.Error(t, err)
	})

	t.Run("doff=255 with size=12 (body offset > size) is rejected", func(t *testing.T) {
		frame := make([]byte, 12)
		binary.BigEndian.PutUint32(frame[:4], 12)
		frame[4] = 255 // 255 * 4 = 1020 > 12
		frame[5] = byte(frameTypeAMQP)
		_, err := parseTestFrameHeader(frame)
		require.Error(t, err)
	})

	t.Run("size 0x7FFFFFFF with short buffer does not panic", func(t *testing.T) {
		frame := make([]byte, frameHeaderSize)
		binary.BigEndian.PutUint32(frame[:4], 0x7FFFFFFF)
		frame[4] = minDataOffsetWords
		frame[5] = byte(frameTypeAMQP)
		_, err := parseTestFrameHeader(frame)
		require.Error(t, err)
		assert.ErrorIs(t, err, errIncompleteFrame)
	})

	t.Run("every non-AMQP, non-SASL frame type is rejected", func(t *testing.T) {
		for ft := 2; ft <= 0xFF; ft++ {
			frame := make([]byte, frameHeaderSize)
			binary.BigEndian.PutUint32(frame[:4], frameHeaderSize)
			frame[4] = minDataOffsetWords
			frame[5] = byte(ft)
			_, err := parseTestFrameHeader(frame)
			require.Errorf(t, err, "frame type 0x%02X should be rejected", ft)
		}
	})
}

func TestParsePerformativeDescriptor(t *testing.T) {
	// Build a frame whose body we can manipulate for descriptor tests.
	makeFrameWithBody := func(ft frameType, body []byte) []byte {
		frame := make([]byte, frameHeaderSize+len(body))
		binary.BigEndian.PutUint32(frame[:4], uint32(len(frame)))
		frame[4] = minDataOffsetWords
		frame[5] = byte(ft)
		copy(frame[frameHeaderSize:], body)
		return frame
	}

	t.Run("smallulong descriptor happy path", func(t *testing.T) {
		frame := makeFrame(frameTypeAMQP, descriptorTransfer)
		h, err := parseTestFrameHeader(frame)
		require.NoError(t, err)
		descriptor, ok, derr := parseTestPerformativeDescriptor(frame, h)
		require.NoError(t, derr)
		assert.True(t, ok)
		assert.Equal(t, descriptorTransfer, descriptor)
	})

	t.Run("ulong descriptor happy path", func(t *testing.T) {
		frame := makeULongFrame(frameTypeAMQP, descriptorTransfer)
		h, err := parseTestFrameHeader(frame)
		require.NoError(t, err)
		descriptor, ok, derr := parseTestPerformativeDescriptor(frame, h)
		require.NoError(t, derr)
		assert.True(t, ok)
		assert.Equal(t, descriptorTransfer, descriptor)
	})

	t.Run("empty body is heartbeat", func(t *testing.T) {
		frame := makeHeartbeatFrame()
		h, err := parseTestFrameHeader(frame)
		require.NoError(t, err)
		descriptor, ok, derr := parseTestPerformativeDescriptor(frame, h)
		require.NoError(t, derr)
		assert.False(t, ok)
		assert.EqualValues(t, 0, descriptor)
	})

	t.Run("body shorter than descriptor prefix", func(t *testing.T) {
		frame := makeFrameWithBody(frameTypeAMQP, []byte{0x00, 0x53})
		h, err := parseTestFrameHeader(frame)
		require.NoError(t, err)
		_, _, derr := parseTestPerformativeDescriptor(frame, h)
		require.Error(t, derr)
	})

	t.Run("body not described-type (missing 0x00 constructor)", func(t *testing.T) {
		frame := makeFrameWithBody(frameTypeAMQP, []byte{0xA0, 0x53, byte(descriptorOpen)})
		h, err := parseTestFrameHeader(frame)
		require.NoError(t, err)
		_, _, derr := parseTestPerformativeDescriptor(frame, h)
		require.Error(t, derr)
	})

	t.Run("truncated ulong descriptor value", func(t *testing.T) {
		// Full ulong prefix is 10 bytes; supply only 5 (0x00,0x80 + 3 stray bytes).
		frame := makeFrameWithBody(frameTypeAMQP, []byte{0x00, 0x80, 0x00, 0x00, 0x00})
		h, err := parseTestFrameHeader(frame)
		require.NoError(t, err)
		_, _, derr := parseTestPerformativeDescriptor(frame, h)
		require.Error(t, derr)
	})

	t.Run("unsupported descriptor encoding", func(t *testing.T) {
		// Neither 0x53 nor 0x80.
		for _, fc := range []byte{0x54, 0x42, 0xFF} {
			frame := makeFrameWithBody(frameTypeAMQP, []byte{0x00, fc, 0x10})
			h, err := parseTestFrameHeader(frame)
			require.NoError(t, err)
			_, ok, derr := parseTestPerformativeDescriptor(frame, h)
			require.Errorf(t, derr, "format code 0x%02X should be rejected", fc)
			assert.False(t, ok)
		}
	})

	t.Run("known encoding with unknown descriptor code", func(t *testing.T) {
		// Valid smallulong encoding, but 0x99 is not an AMQP-space performative.
		frame := makeFrameWithBody(frameTypeAMQP, []byte{0x00, 0x53, 0x99})
		h, err := parseTestFrameHeader(frame)
		require.NoError(t, err)
		_, ok, derr := parseTestPerformativeDescriptor(frame, h)
		require.Error(t, derr)
		assert.False(t, ok)
	})
}

func TestIsKnownPerformativeDescriptor(t *testing.T) {
	amqpDescriptors := []descriptor{
		descriptorOpen,
		descriptorBegin,
		descriptorAttach,
		descriptorFlow,
		descriptorTransfer,
		descriptorDisposition,
		descriptorDetach,
		descriptorEnd,
		descriptorClose,
	}
	saslDescriptors := []descriptor{
		descriptorSASLMechanisms,
		descriptorSASLInit,
		descriptorSASLChallenge,
		descriptorSASLResponse,
		descriptorSASLOutcome,
	}

	t.Run("every AMQP descriptor is known on AMQP frames", func(t *testing.T) {
		for _, d := range amqpDescriptors {
			assert.Truef(t, isKnownPerformativeDescriptor(frameTypeAMQP, d),
				"AMQP descriptor 0x%02X should be known on AMQP frame", d)
		}
	})

	t.Run("every SASL descriptor is known on SASL frames", func(t *testing.T) {
		for _, d := range saslDescriptors {
			assert.Truef(t, isKnownPerformativeDescriptor(frameTypeSASL, d),
				"SASL descriptor 0x%02X should be known on SASL frame", d)
		}
	})

	t.Run("AMQP descriptors are NOT known on SASL frames", func(t *testing.T) {
		for _, d := range amqpDescriptors {
			assert.Falsef(t, isKnownPerformativeDescriptor(frameTypeSASL, d),
				"AMQP descriptor 0x%02X must not be accepted on SASL frame", d)
		}
	})

	t.Run("SASL descriptors are NOT known on AMQP frames", func(t *testing.T) {
		for _, d := range saslDescriptors {
			assert.Falsef(t, isKnownPerformativeDescriptor(frameTypeAMQP, d),
				"SASL descriptor 0x%02X must not be accepted on AMQP frame", d)
		}
	})

	t.Run("unknown descriptors are rejected on both namespaces", func(t *testing.T) {
		for _, d := range []descriptor{0x00, 0x01, 0x0F, 0x19, 0x45, 0x99, 0xFF, 0xFFFFFFFFFFFFFFFF} {
			assert.Falsef(t, isKnownPerformativeDescriptor(frameTypeAMQP, d),
				"descriptor 0x%X should be unknown on AMQP frame", d)
			assert.Falsef(t, isKnownPerformativeDescriptor(frameTypeSASL, d),
				"descriptor 0x%X should be unknown on SASL frame", d)
		}
	})
}
