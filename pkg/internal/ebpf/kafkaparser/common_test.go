// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func TestNewKafkaRequestHeader(t *testing.T) {
	tests := []struct {
		name                  string
		packet                []byte
		expectErr             bool
		flexible              bool
		expectedMessageSize   int32
		expectedAPIKey        KafkaAPIKey
		expectedAPIVersion    int16
		expectedCorrelationID int32
		expectedClientID      string
	}{
		{
			name: "valid fetch request header v1",
			packet: func() []byte {
				pkt := make([]byte, 20)
				binary.BigEndian.PutUint32(pkt[0:4], 100)    // MessageSize
				binary.BigEndian.PutUint16(pkt[4:6], 1)      // APIKey (Fetch)
				binary.BigEndian.PutUint16(pkt[6:8], 1)      // APIVersion
				binary.BigEndian.PutUint32(pkt[8:12], 12345) // CorrelationID
				binary.BigEndian.PutUint16(pkt[12:14], 4)    // ClientID length
				copy(pkt[14:18], "test")                     // ClientID
				return pkt
			}(),
			expectErr:             false,
			expectedMessageSize:   100,
			expectedAPIKey:        1,
			expectedAPIVersion:    1,
			expectedCorrelationID: 12345,
			expectedClientID:      "test",
		},
		{
			name: "valid produce request header v9 (flexible)",
			packet: func() []byte {
				pkt := make([]byte, 21)
				binary.BigEndian.PutUint32(pkt[0:4], 150)    // MessageSize
				binary.BigEndian.PutUint16(pkt[4:6], 0)      // APIKey (Produce)
				binary.BigEndian.PutUint16(pkt[6:8], 9)      // APIVersion
				binary.BigEndian.PutUint32(pkt[8:12], 54321) // CorrelationID
				binary.BigEndian.PutUint16(pkt[12:14], 6)    // ClientID length
				copy(pkt[14:20], "client")                   // ClientID
				pkt[20] = 0                                  // 0 tagged_fields
				return pkt
			}(),
			expectErr:             false,
			flexible:              true,
			expectedMessageSize:   150,
			expectedAPIKey:        0,
			expectedAPIVersion:    9,
			expectedCorrelationID: 54321,
			expectedClientID:      "client",
		},
		{
			name: "valid metadata request header v10",
			packet: func() []byte {
				pkt := make([]byte, 15)                      // MinKafkaRequestLen + 1 for tagged fields byte
				binary.BigEndian.PutUint32(pkt[0:4], 100)    // MessageSize
				binary.BigEndian.PutUint16(pkt[4:6], 3)      // APIKey (Metadata)
				binary.BigEndian.PutUint16(pkt[6:8], 10)     // APIVersion
				binary.BigEndian.PutUint32(pkt[8:12], 98765) // CorrelationID
				binary.BigEndian.PutUint16(pkt[12:14], 0)    // ClientID length (empty)
				pkt[14] = 0                                  // tagged fields = 0
				return pkt
			}(),
			expectErr:             false,
			flexible:              true,
			expectedMessageSize:   100,
			expectedAPIKey:        3,
			expectedAPIVersion:    10,
			expectedCorrelationID: 98765,
			expectedClientID:      "",
		},
		{
			name: "packet too short",
			packet: func() []byte {
				return make([]byte, 10) // Less than MinKafkaRequestLen
			}(),
			expectErr: true,
		},
		{
			name: "invalid API key",
			packet: func() []byte {
				pkt := make([]byte, 14)
				binary.BigEndian.PutUint32(pkt[0:4], 100)    // MessageSize
				binary.BigEndian.PutUint16(pkt[4:6], 99)     // Invalid APIKey
				binary.BigEndian.PutUint16(pkt[6:8], 1)      // APIVersion
				binary.BigEndian.PutUint32(pkt[8:12], 12345) // CorrelationID
				binary.BigEndian.PutUint16(pkt[12:14], 0)    // ClientID length
				return pkt
			}(),
			expectErr: true,
		},
		{
			name: "unsupported fetch version",
			packet: func() []byte {
				pkt := make([]byte, 14)
				binary.BigEndian.PutUint32(pkt[0:4], 100)    // MessageSize
				binary.BigEndian.PutUint16(pkt[4:6], 1)      // APIKey (Fetch)
				binary.BigEndian.PutUint16(pkt[6:8], 25)     // Unsupported APIVersion
				binary.BigEndian.PutUint32(pkt[8:12], 12345) // CorrelationID
				binary.BigEndian.PutUint16(pkt[12:14], 0)    // ClientID length
				return pkt
			}(),
			expectErr: true,
		},
		{
			name: "negative client ID size",
			packet: func() []byte {
				pkt := make([]byte, 14)
				binary.BigEndian.PutUint32(pkt[0:4], 100)     // MessageSize
				binary.BigEndian.PutUint16(pkt[4:6], 1)       // APIKey (Fetch)
				binary.BigEndian.PutUint16(pkt[6:8], 1)       // APIVersion
				binary.BigEndian.PutUint32(pkt[8:12], 12345)  // CorrelationID
				binary.BigEndian.PutUint16(pkt[12:14], 65535) // Negative ClientID length (-1)
				return pkt
			}(),
			expectErr: true,
		},
		{
			name: "packet too short for client ID",
			packet: func() []byte {
				pkt := make([]byte, 16)
				binary.BigEndian.PutUint32(pkt[0:4], 100)    // MessageSize
				binary.BigEndian.PutUint16(pkt[4:6], 1)      // APIKey (Fetch)
				binary.BigEndian.PutUint16(pkt[6:8], 1)      // APIVersion
				binary.BigEndian.PutUint32(pkt[8:12], 12345) // CorrelationID
				binary.BigEndian.PutUint16(pkt[12:14], 10)   // ClientID length > available bytes
				return pkt
			}(),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, err := NewKafkaRequestHeader(largebuf.NewLargeBufferFrom(tt.packet))

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			assert.Equal(t, tt.expectedMessageSize, header.MessageSize())
			assert.Equal(t, tt.expectedAPIKey, header.APIKey())
			assert.Equal(t, tt.expectedAPIVersion, header.APIVersion())
			assert.Equal(t, tt.expectedCorrelationID, header.CorrelationID())
			assert.Equal(t, tt.expectedClientID, header.ClientID())

			expectedBodyOffset := MinKafkaRequestLen + len(tt.expectedClientID)
			if tt.flexible {
				expectedBodyOffset++ // Account for tagged fields byte
			}
			assert.Equal(t, expectedBodyOffset, int(header.bodyOffset))
		})
	}
}

func TestValidateKafkaHeader(t *testing.T) {
	tests := []struct {
		name          string
		msgSize       int32
		apiKey        KafkaAPIKey
		apiVersion    int16
		correlationID int32
		expectErr     bool
	}{
		{
			name:          "valid fetch header",
			msgSize:       100,
			apiKey:        APIKeyFetch,
			apiVersion:    5,
			correlationID: 123,
		},
		{
			name:          "valid produce header",
			msgSize:       200,
			apiKey:        APIKeyProduce,
			apiVersion:    8,
			correlationID: 456,
		},
		{
			name:          "valid metadata header",
			msgSize:       150,
			apiKey:        APIKeyMetadata,
			apiVersion:    12,
			correlationID: 789,
		},
		{
			name:          "message size too small",
			msgSize:       5,
			apiKey:        APIKeyFetch,
			apiVersion:    1,
			correlationID: 123,
			expectErr:     true,
		},
		{
			name:          "message size too large",
			msgSize:       KafkaMaxPayloadLen + 1,
			apiKey:        APIKeyFetch,
			apiVersion:    1,
			correlationID: 123,
			expectErr:     true,
		},
		{
			name:          "negative API version",
			msgSize:       100,
			apiKey:        APIKeyFetch,
			apiVersion:    -1,
			correlationID: 123,
			expectErr:     true,
		},
		{
			name:          "negative correlation ID",
			msgSize:       100,
			apiKey:        APIKeyFetch,
			apiVersion:    1,
			correlationID: -1,
			expectErr:     true,
		},
		{
			name:          "unsupported metadata version (too low)",
			msgSize:       100,
			apiKey:        APIKeyMetadata,
			apiVersion:    9,
			correlationID: 123,
			expectErr:     true,
		},
		{
			name:          "unsupported metadata version (too high)",
			msgSize:       100,
			apiKey:        APIKeyMetadata,
			apiVersion:    14,
			correlationID: 123,
			expectErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lb := buildRawHeaderBuf(tt.msgSize, tt.apiKey, tt.apiVersion, tt.correlationID)
			h := KafkaRequestHeader{lb: lb}
			err := h.validate()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsFlexible(t *testing.T) {
	tests := []struct {
		name     string
		header   KafkaRequestHeader
		expected bool
	}{
		{name: "produce v8 - not flexible", header: newUncheckedHeader(APIKeyProduce, 8), expected: false},
		{name: "produce v9 - flexible", header: newUncheckedHeader(APIKeyProduce, 9), expected: true},
		{name: "fetch v11 - not flexible", header: newUncheckedHeader(APIKeyFetch, 11), expected: false},
		{name: "fetch v12 - flexible", header: newUncheckedHeader(APIKeyFetch, 12), expected: true},
		{name: "metadata v8 - not flexible", header: newUncheckedHeader(APIKeyMetadata, 8), expected: false},
		{name: "metadata v9 - flexible", header: newUncheckedHeader(APIKeyMetadata, 9), expected: true},
		{name: "unknown API key", header: newUncheckedHeader(99, 1), expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isFlexible(tt.header)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReadArrayLength(t *testing.T) {
	tests := []struct {
		name           string
		packet         []byte
		header         KafkaRequestHeader
		offset         int
		expectedLength int
		expectedOffset int
		expectErr      bool
	}{
		{
			name: "non-flexible array length",
			packet: func() []byte {
				pkt := make([]byte, 8)
				binary.BigEndian.PutUint32(pkt[0:4], 5) // Array length
				return pkt
			}(),
			header:         newUncheckedHeader(APIKeyFetch, 5),
			offset:         0,
			expectedLength: 5,
			expectedOffset: 4,
			expectErr:      false,
		},
		{
			name: "flexible array length with varint",
			packet: func() []byte {
				// Varint encoding of 6 (5+1 for flexible arrays)
				return []byte{0x06, 0x00, 0x00, 0x00}
			}(),
			header:         newUncheckedHeader(APIKeyFetch, 12),
			offset:         0,
			expectedLength: 5,
			expectedOffset: 1,
			expectErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := largebuf.NewLargeBufferFrom(tt.packet[tt.offset:]).NewReader()
			length, err := readArrayLength(&r, tt.header)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedLength, length)
			assert.Equal(t, tt.expectedOffset-tt.offset, r.ReadOffset())
		})
	}
}

func TestReadUUID(t *testing.T) {
	tests := []struct {
		name           string
		packet         []byte
		offset         int
		expectedUUID   UUID
		expectedOffset int
		expectErr      bool
	}{
		{
			name: "valid UUID",
			packet: func() []byte {
				pkt := make([]byte, 20)
				// Set some recognizable UUID bytes
				for i := range UUIDLen {
					pkt[i] = byte(i)
				}
				return pkt
			}(),
			offset: 0,
			expectedUUID: func() UUID {
				var uuid UUID
				for i := range UUIDLen {
					uuid[i] = byte(i)
				}
				return uuid
			}(),
			expectedOffset: UUIDLen,
			expectErr:      false,
		},
		{
			name: "packet too short for UUID",
			packet: func() []byte {
				return make([]byte, 10) // Less than UUIDLen
			}(),
			offset:    0,
			expectErr: true,
		},
		{
			name: "UUID at offset",
			packet: func() []byte {
				pkt := make([]byte, 25)
				// Set UUID starting at offset 5
				for i := range UUIDLen {
					pkt[5+i] = byte(i + 10)
				}
				return pkt
			}(),
			offset: 5,
			expectedUUID: func() UUID {
				var uuid UUID
				for i := range UUIDLen {
					uuid[i] = byte(i + 10)
				}
				return uuid
			}(),
			expectedOffset: 5 + UUIDLen,
			expectErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := largebuf.NewLargeBufferFrom(tt.packet[tt.offset:]).NewReader()
			uuid, err := readUUID(&r)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, uuid)
			assert.Equal(t, tt.expectedUUID, *uuid)
			assert.Equal(t, tt.expectedOffset-tt.offset, r.ReadOffset())
		})
	}
}

func TestReadString(t *testing.T) {
	tests := []struct {
		name           string
		packet         []byte
		header         KafkaRequestHeader
		offset         int
		nullable       bool
		expectedString string
		expectedOffset int
		expectErr      bool
	}{
		{
			name: "non-flexible string",
			packet: func() []byte {
				pkt := make([]byte, 10)
				binary.BigEndian.PutUint16(pkt[0:2], 5) // String length
				copy(pkt[2:7], "hello")
				return pkt
			}(),
			header:         newUncheckedHeader(APIKeyFetch, 5),
			offset:         0,
			nullable:       false,
			expectedString: "hello",
			expectedOffset: 7,
			expectErr:      false,
		},
		{
			name: "flexible string with varint",
			packet: func() []byte {
				// Varint encoding of 6 (5+1 for flexible strings) followed by "world"
				pkt := []byte{0x06}
				pkt = append(pkt, []byte("world")...)
				return pkt
			}(),
			header:         newUncheckedHeader(APIKeyFetch, 12),
			offset:         0,
			nullable:       false,
			expectedString: "world",
			expectedOffset: 6,
			expectErr:      false,
		},
		{
			name: "string size exceeds packet",
			packet: func() []byte {
				pkt := make([]byte, 5)
				binary.BigEndian.PutUint16(pkt[0:2], 10) // String length > available
				return pkt
			}(),
			header:    newUncheckedHeader(APIKeyFetch, 5),
			offset:    0,
			nullable:  false,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := largebuf.NewLargeBufferFrom(tt.packet[tt.offset:]).NewReader()
			str, err := readString(&r, tt.header, tt.nullable)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedString, str)
			assert.Equal(t, tt.expectedOffset-tt.offset, r.ReadOffset())
		})
	}
}

func TestReadUnsignedVarint(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		offset        int
		expectedValue int
		expectedBytes int // bytes consumed
		expectErr     bool
	}{
		{
			name:          "single byte varint",
			data:          []byte{0x05},
			offset:        0,
			expectedValue: 5,
			expectedBytes: 1,
			expectErr:     false,
		},
		{
			name:          "multi-byte varint",
			data:          []byte{0x96, 0x01}, // 150 in varint
			offset:        0,
			expectedValue: 150,
			expectedBytes: 2,
			expectErr:     false,
		},
		{
			name:          "large varint",
			data:          []byte{0xFF, 0xFF, 0x7F}, // Large number
			offset:        0,
			expectedValue: 2097151,
			expectedBytes: 3,
			expectErr:     false,
		},
		{
			name:      "incomplete varint",
			data:      []byte{0x96}, // Missing continuation
			offset:    0,
			expectErr: true,
		},
		{
			name:      "varint too long",
			data:      []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, // Too many bytes
			offset:    0,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := largebuf.NewLargeBufferFrom(tt.data[tt.offset:]).NewReader()
			value, err := readUnsignedVarint(&r)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedValue, value)
			assert.Equal(t, tt.expectedBytes, r.ReadOffset())
		})
	}
}

func TestSkip(t *testing.T) {
	tests := []struct {
		name          string
		packet        []byte
		offset        int
		length        int
		expectedBytes int // bytes consumed by Skip
		expectErr     bool
	}{
		{
			name:          "valid skip",
			packet:        make([]byte, 20),
			offset:        5,
			length:        10,
			expectedBytes: 10,
			expectErr:     false,
		},
		{
			name:      "skip exceeds packet",
			packet:    make([]byte, 10),
			offset:    5,
			length:    10, // 5 remaining, but skip 10
			expectErr: true,
		},
		{
			name:          "skip zero bytes",
			packet:        make([]byte, 10),
			offset:        3,
			length:        0,
			expectedBytes: 0,
			expectErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := largebuf.NewLargeBufferFrom(tt.packet[tt.offset:]).NewReader()
			err := r.Skip(tt.length)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedBytes, r.ReadOffset())
		})
	}
}

// Truncation tests to simulate incomplete packets
func TestNewKafkaRequestHeaderTruncation(t *testing.T) {
	// Create a valid header first
	validPacket := make([]byte, 18)
	binary.BigEndian.PutUint32(validPacket[0:4], 100)    // MessageSize
	binary.BigEndian.PutUint16(validPacket[4:6], 1)      // APIKey
	binary.BigEndian.PutUint16(validPacket[6:8], 1)      // APIVersion
	binary.BigEndian.PutUint32(validPacket[8:12], 12345) // CorrelationID
	binary.BigEndian.PutUint16(validPacket[12:14], 4)    // ClientID length
	copy(validPacket[14:18], "test")                     // ClientID

	// Test truncation at various points
	for i := 1; i < len(validPacket); i++ {
		t.Run(fmt.Sprintf("truncated_at_%d", i), func(t *testing.T) {
			truncated := validPacket[:i]
			_, err := NewKafkaRequestHeader(largebuf.NewLargeBufferFrom(truncated))
			assert.Error(t, err, "expected error for truncated packet at position %d", i)
		})
	}
}
