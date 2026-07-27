// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amqpparser

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProtocolHeader(t *testing.T) {
	t.Run("protocolIDAMQP happy path", func(t *testing.T) {
		h, err := parseProtocolHeader(newLargeBufferReader(makeProtocolHeader(protocolIDAMQP)))
		require.NoError(t, err)
		assert.Equal(t, protocolIDAMQP, h.ID)
		assert.EqualValues(t, 1, h.Major)
		assert.EqualValues(t, 0, h.Minor)
		assert.EqualValues(t, 0, h.Revision)
	})

	t.Run("protocolIDAMQPTLS is accepted", func(t *testing.T) {
		h, err := parseProtocolHeader(newLargeBufferReader(makeProtocolHeader(protocolIDAMQPTLS)))
		require.NoError(t, err)
		assert.Equal(t, protocolIDAMQPTLS, h.ID)
	})

	t.Run("protocolIDSASL is accepted", func(t *testing.T) {
		h, err := parseProtocolHeader(newLargeBufferReader(makeProtocolHeader(protocolIDSASL)))
		require.NoError(t, err)
		assert.Equal(t, protocolIDSASL, h.ID)
	})

	t.Run("short buffer is rejected", func(t *testing.T) {
		_, err := parseProtocolHeader(newLargeBufferReader([]byte{'A', 'M', 'Q', 'P', 0, 1, 0}))
		require.Error(t, err)
	})

	t.Run("bad magic is rejected", func(t *testing.T) {
		_, err := parseProtocolHeader(newLargeBufferReader([]byte{'H', 'T', 'T', 'P', 0, 1, 0, 0}))
		require.Error(t, err)
	})

	t.Run("invalid protocol id is rejected", func(t *testing.T) {
		for _, id := range []byte{1, 4, 99, 255} {
			bytes := []byte{'A', 'M', 'Q', 'P', id, 1, 0, 0}
			_, err := parseProtocolHeader(newLargeBufferReader(bytes))
			require.Errorf(t, err, "protocol id %d should be rejected", id)
		}
	})

	t.Run("AMQP 0-9-1 handshake bytes are rejected", func(t *testing.T) {
		// 0-9-1 uses version bytes {0, 0, 9, 1}; spec requires {1, 0, 0} for AMQP 1.0.
		_, err := parseProtocolHeader(newLargeBufferReader([]byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}))
		require.Error(t, err)
	})
}

// makeFrameHeader builds a bare 8-byte AMQP frame header with the given size,
// data-offset (in 4-byte words), and frame type. Channel is zero.
func makeFrameHeader(size uint32, doff, ft byte) []byte {
	hdr := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint32(hdr[0:4], size)
	hdr[4] = doff
	hdr[5] = ft
	return hdr
}

func TestIsLikelyAMQP(t *testing.T) {
	likely := func(buf []byte) bool {
		return IsLikelyAMQP(newLargeBufferReader(buf))
	}

	t.Run("accepts AMQP preamble", func(t *testing.T) {
		assert.True(t, likely(makeProtocolHeader(protocolIDAMQP)))
		assert.True(t, likely(makeProtocolHeader(protocolIDAMQPTLS)))
		assert.True(t, likely(makeProtocolHeader(protocolIDSASL)))
	})

	t.Run("accepts preamble even when only the magic is present", func(t *testing.T) {
		// IsLikelyAMQP is a coarse prefilter, so the bare 4-byte magic counts.
		assert.True(t, likely([]byte("AMQP")))
	})

	t.Run("accepts a valid AMQP frame with in-buffer performative", func(t *testing.T) {
		assert.True(t, likely(makeFrame(frameTypeAMQP, descriptorOpen)))
	})

	t.Run("accepts a valid SASL frame with in-buffer performative", func(t *testing.T) {
		assert.True(t, likely(makeFrame(frameTypeSASL, descriptorSASLMechanisms)))
	})

	t.Run("accepts a frame header whose body falls outside the captured buffer", func(t *testing.T) {
		// Real eBPF captures often truncate the payload; a header-only buffer
		// must still pass the prefilter.
		hdr := makeFrameHeader(1024, minDataOffsetWords, byte(frameTypeAMQP))
		assert.True(t, likely(hdr))
	})

	t.Run("accepts a frame header with extended data-offset that overruns buffer", func(t *testing.T) {
		// doff*4 > len(buf), so the constructor check is skipped.
		hdr := makeFrameHeader(64, 4, byte(frameTypeAMQP))
		assert.True(t, likely(hdr))
	})

	t.Run("rejects a nil reader", func(t *testing.T) {
		assert.False(t, IsLikelyAMQP(nil))
	})

	t.Run("rejects buffers shorter than the AMQP magic", func(t *testing.T) {
		assert.False(t, likely(nil))
		assert.False(t, likely([]byte{}))
		assert.False(t, likely([]byte{'A'}))
		assert.False(t, likely([]byte{'A', 'M', 'Q'}))
	})

	t.Run("rejects 4-7 byte buffers that are not AMQP magic", func(t *testing.T) {
		// Too short for a frame header and not the preamble.
		assert.False(t, likely([]byte{'H', 'T', 'T', 'P'}))
		assert.False(t, likely([]byte{0, 0, 0, 8, 2, 0, 0}))
	})

	t.Run("rejects frame size smaller than the header", func(t *testing.T) {
		// size < 8 is structurally impossible per spec.
		hdr := makeFrameHeader(7, minDataOffsetWords, byte(frameTypeAMQP))
		assert.False(t, likely(hdr))
	})

	t.Run("rejects data-offset below the minimum", func(t *testing.T) {
		// doff < 2 means the body would overlap the header.
		hdr := makeFrameHeader(64, 1, byte(frameTypeAMQP))
		assert.False(t, likely(hdr))
		hdr = makeFrameHeader(64, 0, byte(frameTypeAMQP))
		assert.False(t, likely(hdr))
	})

	t.Run("rejects unknown frame types", func(t *testing.T) {
		// Only 0x00 (AMQP) and 0x01 (SASL) are valid.
		for _, ft := range []byte{0x02, 0x10, 0x7f, 0xff} {
			hdr := makeFrameHeader(64, minDataOffsetWords, ft)
			assert.Falsef(t, likely(hdr), "frame type 0x%02X should be rejected", ft)
		}
	})

	t.Run("rejects in-buffer performative not starting with the described-type constructor", func(t *testing.T) {
		frame := makeFrame(frameTypeAMQP, descriptorOpen)
		// Corrupt the body's first byte; everything else stays valid.
		frame[frameHeaderSize] = 0x42
		assert.False(t, likely(frame))
	})

	t.Run("rejects an all-zero buffer", func(t *testing.T) {
		// size=0 fails the >= frameHeaderSize check.
		assert.False(t, likely(make([]byte, 16)))
	})

	t.Run("rejects HTTP request bytes", func(t *testing.T) {
		// Realistic non-AMQP traffic: "GET / HTTP/1.1\r\n".
		assert.False(t, likely([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")))
	})

	t.Run("accepts a bare heartbeat frame", func(t *testing.T) {
		// AMQP 1.0 2.4.5: an empty frame (size == bodyOffset) is the idle
		// heartbeat and must not be rejected.
		assert.True(t, likely(makeHeartbeatFrame()))
	})

	t.Run("accepts a heartbeat frame even when the next frame's bytes follow", func(t *testing.T) {
		// Regression: the prefilter previously inspected buf[bodyOffset] for
		// any frame, which on a heartbeat is actually the next frame's first
		// size byte. The check must skip bodies when size == bodyOffset.
		buf := append(makeHeartbeatFrame(), makeFrame(frameTypeAMQP, descriptorOpen)...)
		assert.True(t, likely(buf))
	})

	t.Run("does not advance the reader cursor on success", func(t *testing.T) {
		// Callers rely on being able to pass the same reader to Parse after
		// the prefilter passes; the cursor must still be at offset 0.
		r := newLargeBufferReader(makeFrame(frameTypeAMQP, descriptorOpen))
		assert.True(t, IsLikelyAMQP(r))
		assert.Equal(t, 0, r.ReadOffset(), "IsLikelyAMQP must be non-destructive")
	})
}
