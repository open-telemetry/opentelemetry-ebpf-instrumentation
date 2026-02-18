// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package couchbasekv

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeRequestHeader(opcode Opcode, keyLen uint16, extrasLen uint8, bodyLen uint32, vbucket uint16, opaque uint32, cas uint64) []byte {
	pkt := make([]byte, HeaderLen)
	pkt[0] = byte(MagicClientRequest)
	pkt[1] = byte(opcode)
	binary.BigEndian.PutUint16(pkt[2:4], keyLen)
	pkt[4] = extrasLen
	pkt[5] = byte(DataTypeRaw)
	binary.BigEndian.PutUint16(pkt[6:8], vbucket)
	binary.BigEndian.PutUint32(pkt[8:12], bodyLen)
	binary.BigEndian.PutUint32(pkt[12:16], opaque)
	binary.BigEndian.PutUint64(pkt[16:24], cas)
	return pkt
}

func makeResponseHeader(opcode Opcode, keyLen uint16, extrasLen uint8, bodyLen uint32, status Status, opaque uint32, cas uint64) []byte {
	pkt := make([]byte, HeaderLen)
	pkt[0] = byte(MagicServerResponse)
	pkt[1] = byte(opcode)
	binary.BigEndian.PutUint16(pkt[2:4], keyLen)
	pkt[4] = extrasLen
	pkt[5] = byte(DataTypeRaw)
	binary.BigEndian.PutUint16(pkt[6:8], uint16(status))
	binary.BigEndian.PutUint32(pkt[8:12], bodyLen)
	binary.BigEndian.PutUint32(pkt[12:16], opaque)
	binary.BigEndian.PutUint64(pkt[16:24], cas)
	return pkt
}

// makeAltRequestHeader creates a flexible framing request header (magic 0x08)
func makeAltRequestHeader(opcode Opcode, framingExtrasLen uint8, keyLen uint8, extrasLen uint8, bodyLen uint32, vbucket uint16, opaque uint32, cas uint64) []byte {
	pkt := make([]byte, HeaderLen)
	pkt[0] = byte(MagicAltClientRequest)
	pkt[1] = byte(opcode)
	pkt[2] = framingExtrasLen
	pkt[3] = keyLen
	pkt[4] = extrasLen
	pkt[5] = byte(DataTypeRaw)
	binary.BigEndian.PutUint16(pkt[6:8], vbucket)
	binary.BigEndian.PutUint32(pkt[8:12], bodyLen)
	binary.BigEndian.PutUint32(pkt[12:16], opaque)
	binary.BigEndian.PutUint64(pkt[16:24], cas)
	return pkt
}

// makeAltResponseHeader creates a flexible framing response header (magic 0x18)
func makeAltResponseHeader(opcode Opcode, framingExtrasLen uint8, keyLen uint8, extrasLen uint8, bodyLen uint32, status Status, opaque uint32, cas uint64) []byte {
	pkt := make([]byte, HeaderLen)
	pkt[0] = byte(MagicAltClientResponse)
	pkt[1] = byte(opcode)
	pkt[2] = framingExtrasLen
	pkt[3] = keyLen
	pkt[4] = extrasLen
	pkt[5] = byte(DataTypeRaw)
	binary.BigEndian.PutUint16(pkt[6:8], uint16(status))
	binary.BigEndian.PutUint32(pkt[8:12], bodyLen)
	binary.BigEndian.PutUint32(pkt[12:16], opaque)
	binary.BigEndian.PutUint64(pkt[16:24], cas)
	return pkt
}

// headerExpected holds expected header field values for test assertions.
type headerExpected struct {
	Magic            Magic
	Opcode           Opcode
	FramingExtrasLen uint8
	KeyLen           uint16
	ExtrasLen        uint8
	Status           Status
	BodyLen          uint32
	Opaque           uint32
}

func TestParseHeader(t *testing.T) {
	tests := []struct {
		name      string
		packet    []byte
		expectErr bool
		expected  *headerExpected
	}{
		{
			name:      "valid GET request",
			packet:    makeRequestHeader(OpcodeGet, 5, 0, 5, 100, 12345, 0),
			expectErr: false,
			expected: &headerExpected{
				Magic:     MagicClientRequest,
				Opcode:    OpcodeGet,
				KeyLen:    5,
				ExtrasLen: 0,
				BodyLen:   5,
				Opaque:    12345,
			},
		},
		{
			name:      "valid SET request with extras",
			packet:    makeRequestHeader(OpcodeSet, 5, 8, 20, 200, 54321, 999),
			expectErr: false,
			expected: &headerExpected{
				Magic:     MagicClientRequest,
				Opcode:    OpcodeSet,
				KeyLen:    5,
				ExtrasLen: 8,
				BodyLen:   20,
				Opaque:    54321,
			},
		},
		{
			name:      "valid response with status",
			packet:    makeResponseHeader(OpcodeGet, 0, 4, 10, StatusSuccess, 12345, 123456789),
			expectErr: false,
			expected: &headerExpected{
				Magic:     MagicServerResponse,
				Opcode:    OpcodeGet,
				KeyLen:    0,
				ExtrasLen: 4,
				Status:    StatusSuccess,
				BodyLen:   10,
				Opaque:    12345,
			},
		},
		{
			name:      "response with key not found status",
			packet:    makeResponseHeader(OpcodeGet, 0, 0, 0, StatusKeyNotFound, 12345, 0),
			expectErr: false,
			expected: &headerExpected{
				Magic:     MagicServerResponse,
				Opcode:    OpcodeGet,
				KeyLen:    0,
				ExtrasLen: 0,
				Status:    StatusKeyNotFound,
				BodyLen:   0,
				Opaque:    12345,
			},
		},
		{
			name:      "packet too short",
			packet:    make([]byte, 10),
			expectErr: true,
			expected:  nil,
		},
		{
			name: "invalid magic byte",
			packet: func() []byte {
				pkt := makeRequestHeader(OpcodeGet, 5, 0, 5, 0, 0, 0)
				pkt[0] = 0xFF // Invalid magic
				return pkt
			}(),
			expectErr: true,
			expected:  nil,
		},
		{
			name: "invalid body length (too small)",
			packet: func() []byte {
				// keyLen=10, extrasLen=5, but bodyLen=10 (should be at least 15)
				return makeRequestHeader(OpcodeSet, 10, 5, 10, 0, 0, 0)
			}(),
			expectErr: true,
			expected:  nil,
		},
		{
			name:      "flexible framing request",
			packet:    makeAltRequestHeader(OpcodeGet, 2, 4, 0, 6, 100, 12345, 42), // 2 framing extras + 4 key = 6
			expectErr: false,
			expected: &headerExpected{
				Magic:            MagicAltClientRequest,
				Opcode:           OpcodeGet,
				FramingExtrasLen: 2,
				KeyLen:           4,
				ExtrasLen:        0,
				BodyLen:          6,
				Opaque:           12345,
			},
		},
		{
			name:      "flexible framing response with status",
			packet:    makeAltResponseHeader(OpcodeGet, 3, 0, 0, 3, StatusKeyNotFound, 12345, 0),
			expectErr: false,
			expected: &headerExpected{
				Magic:            MagicAltClientResponse,
				Opcode:           OpcodeGet,
				FramingExtrasLen: 3,
				KeyLen:           0,
				ExtrasLen:        0,
				Status:           StatusKeyNotFound,
				BodyLen:          3,
				Opaque:           12345,
			},
		},
		{
			name: "flexible framing invalid body length",
			packet: func() []byte {
				// framingExtras=3, key=5, extras=2, but bodyLen=5 (should be at least 10)
				return makeAltRequestHeader(OpcodeSet, 3, 5, 2, 5, 0, 0, 0)
			}(),
			expectErr: true,
			expected:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, err := ParseHeader(tt.packet)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			assert.Equal(t, tt.expected.Magic, header.Magic())
			assert.Equal(t, tt.expected.Opcode, header.Opcode())
			assert.Equal(t, tt.expected.FramingExtrasLen, header.FramingExtrasLen())
			assert.Equal(t, tt.expected.KeyLen, header.KeyLen())
			assert.Equal(t, tt.expected.ExtrasLen, header.ExtrasLen())
			assert.Equal(t, tt.expected.BodyLen, header.BodyLen())
			assert.Equal(t, tt.expected.Opaque, header.Opaque())

			if header.IsResponse() {
				assert.Equal(t, tt.expected.Status, header.Status())
			}
		})
	}
}

func TestParsePacket(t *testing.T) {
	tests := []struct {
		name        string
		packet      []byte
		expectErr   bool
		expectedKey string
	}{
		{
			name: "GET request with key",
			packet: func() []byte {
				pkt := makeRequestHeader(OpcodeGet, 5, 0, 5, 100, 12345, 0)
				return append(pkt, []byte("mykey")...)
			}(),
			expectedKey: "mykey",
		},
		{
			name: "SET request with extras, key, and value",
			packet: func() []byte {
				pkt := makeRequestHeader(OpcodeSet, 5, 8, 18, 100, 12345, 0) // 8 + 5 + 5 = 18
				pkt = append(pkt, make([]byte, 8)...)                        // extras
				pkt = append(pkt, []byte("mykey")...)                        // key
				pkt = append(pkt, []byte("value")...)                        // value
				return pkt
			}(),
			expectedKey: "mykey",
		},
		{
			name: "response without key",
			packet: func() []byte {
				pkt := makeResponseHeader(OpcodeGet, 0, 4, 9, StatusSuccess, 12345, 999) // 4 + 0 + 5 = 9
				pkt = append(pkt, make([]byte, 4)...)                                    // extras
				pkt = append(pkt, []byte("value")...)                                    // value
				return pkt
			}(),
			expectedKey: "",
		},
		{
			name: "truncated key - partial key available",
			packet: func() []byte {
				pkt := makeRequestHeader(OpcodeGet, 5, 0, 5, 100, 12345, 0)
				return append(pkt, []byte("my")...) // Only 2 bytes of key, need 5
			}(),
			expectedKey: "my",
		},
		{
			name: "truncated value - full key, partial value",
			packet: func() []byte {
				pkt := makeRequestHeader(OpcodeSet, 5, 0, 10, 100, 12345, 0) // 5 key + 5 value = 10
				pkt = append(pkt, []byte("mykey")...)                        // full key
				pkt = append(pkt, []byte("va")...)                           // partial value (2 of 5)
				return pkt
			}(),
			expectedKey: "mykey",
		},
		{
			name: "truncated extras - partial extras only",
			packet: func() []byte {
				pkt := makeRequestHeader(OpcodeSet, 5, 8, 18, 100, 12345, 0) // 8 extras + 5 key + 5 value
				pkt = append(pkt, make([]byte, 4)...)                        // only 4 bytes of extras
				return pkt
			}(),
			expectedKey: "",
		},
		{
			name: "header only - no body data",
			packet: func() []byte {
				return makeRequestHeader(OpcodeGet, 5, 0, 5, 100, 12345, 0)
			}(),
			expectedKey: "",
		},
		{
			name: "flexible framing with framing extras, key, and value",
			packet: func() []byte {
				pkt := makeAltRequestHeader(OpcodeGet, 3, 5, 0, 13, 100, 12345, 0)
				pkt = append(pkt, []byte{0x02, 0x00, 0x0f}...) // framing extras
				pkt = append(pkt, []byte("mykey")...)          // key
				pkt = append(pkt, []byte("value")...)          // value
				return pkt
			}(),
			expectedKey: "mykey",
		},
		{
			name: "flexible framing response with status",
			packet: func() []byte {
				pkt := makeAltResponseHeader(OpcodeGet, 3, 0, 0, 3, StatusKeyNotFound, 12345, 0)
				pkt = append(pkt, []byte{0x02, 0x00, 0x0f}...) // framing extras
				return pkt
			}(),
			expectedKey: "",
		},
		{
			name: "flexible framing truncated framing extras",
			packet: func() []byte {
				pkt := makeAltRequestHeader(OpcodeGet, 3, 5, 0, 8, 100, 12345, 0)
				pkt = append(pkt, []byte{0x02}...) // only 1 byte of framing extras
				return pkt
			}(),
			expectedKey: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := ParsePacket(tt.packet)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedKey, packet.KeyString())
		})
	}
}

func TestParsePackets(t *testing.T) {
	tests := []struct {
		name          string
		segment       []byte
		expectErr     bool
		expectedCount int
	}{
		{
			name: "single packet",
			segment: func() []byte {
				pkt := makeRequestHeader(OpcodeGet, 3, 0, 3, 0, 1, 0)
				return append(pkt, []byte("key")...)
			}(),
			expectErr:     false,
			expectedCount: 1,
		},
		{
			name: "two pipelined packets",
			segment: func() []byte {
				pkt1 := makeRequestHeader(OpcodeGet, 4, 0, 4, 0, 1, 0)
				pkt1 = append(pkt1, []byte("key1")...)
				pkt2 := makeRequestHeader(OpcodeGet, 4, 0, 4, 0, 2, 0)
				pkt2 = append(pkt2, []byte("key2")...)
				return append(pkt1, pkt2...)
			}(),
			expectErr:     false,
			expectedCount: 2,
		},
		{
			name: "three pipelined packets",
			segment: func() []byte {
				pkt1 := makeRequestHeader(OpcodeGet, 4, 0, 4, 0, 1, 0)
				pkt1 = append(pkt1, []byte("key1")...)
				pkt2 := makeRequestHeader(OpcodeGet, 4, 0, 4, 0, 2, 0)
				pkt2 = append(pkt2, []byte("key2")...)
				pkt3 := makeRequestHeader(OpcodeGet, 4, 0, 4, 0, 3, 0)
				pkt3 = append(pkt3, []byte("key3")...)
				return append(append(pkt1, pkt2...), pkt3...)
			}(),
			expectErr:     false,
			expectedCount: 3,
		},
		{
			name:          "partial header ignored",
			segment:       make([]byte, 10), // Less than HeaderLen
			expectErr:     false,
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var packets []Packet
			var parseErr error
			for pkt, err := range ParsePackets(tt.segment) {
				if err != nil {
					parseErr = err
					break
				}
				packets = append(packets, pkt)
			}

			if tt.expectErr {
				assert.Error(t, parseErr)
				return
			}

			require.NoError(t, parseErr)
			assert.Len(t, packets, tt.expectedCount)
		})
	}
}

func TestHeaderTotalLen(t *testing.T) {
	pkt := makeRequestHeader(OpcodeGet, 0, 0, 100, 0, 0, 0)
	header, err := ParseHeader(pkt)
	require.NoError(t, err)
	assert.Equal(t, HeaderLen+100, header.TotalLen())
}

func TestHeaderValueLen(t *testing.T) {
	tests := []struct {
		name     string
		packet   []byte
		expected int
	}{
		{
			name:     "no extras, no key",
			packet:   makeRequestHeader(OpcodeGet, 0, 0, 10, 0, 0, 0),
			expected: 10,
		},
		{
			name:     "with extras and key",
			packet:   makeRequestHeader(OpcodeSet, 5, 8, 20, 0, 0, 0),
			expected: 7, // 20 - 8 - 5
		},
		{
			name:     "only extras",
			packet:   makeRequestHeader(OpcodeSet, 0, 8, 8, 0, 0, 0),
			expected: 0,
		},
		{
			name:     "with framing extras (flexible framing)",
			packet:   makeAltRequestHeader(OpcodeGet, 3, 5, 4, 20, 0, 0, 0),
			expected: 8, // 20 - 3 - 4 - 5
		},
		{
			name:     "flexible framing with only framing extras",
			packet:   makeAltRequestHeader(OpcodeGet, 3, 0, 0, 3, 0, 0, 0),
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := ParseHeader(tt.packet)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, h.ValueLen())
		})
	}
}

func TestParseHeaderTruncation(t *testing.T) {
	// Create a valid header
	validPacket := makeRequestHeader(OpcodeGet, 5, 0, 5, 100, 12345, 0)

	// Test truncation at various points
	for i := 1; i < len(validPacket); i++ {
		t.Run("truncated", func(t *testing.T) {
			truncated := validPacket[:i]
			_, err := ParseHeader(truncated)
			assert.Error(t, err, "expected error for truncated packet at position %d", i)
		})
	}
}
