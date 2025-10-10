// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKafkaRequestHeader(t *testing.T) {
	tests := []struct {
		name      string
		packet    []byte
		expectErr bool
		flexible  bool
		expected  *KafkaRequestHeader
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
			expectErr: false,
			expected: &KafkaRequestHeader{
				MessageSize:   100,
				APIKey:        1,
				APIVersion:    1,
				CorrelationID: 12345,
				ClientID:      "test",
			},
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
			expectErr: false,
			flexible:  true,
			expected: &KafkaRequestHeader{
				MessageSize:   150,
				APIKey:        0,
				APIVersion:    9,
				CorrelationID: 54321,
				ClientID:      "client",
			},
		},
		{
			name: "valid metadata request header v10",
			packet: func() []byte {
				pkt := make([]byte, 14)
				binary.BigEndian.PutUint32(pkt[0:4], 100)    // MessageSize
				binary.BigEndian.PutUint16(pkt[4:6], 3)      // APIKey (Metadata)
				binary.BigEndian.PutUint16(pkt[6:8], 10)     // APIVersion
				binary.BigEndian.PutUint32(pkt[8:12], 98765) // CorrelationID
				binary.BigEndian.PutUint16(pkt[12:14], 0)    // ClientID length (empty)
				return pkt
			}(),
			expectErr: false,
			expected: &KafkaRequestHeader{
				MessageSize:   100,
				APIKey:        3,
				APIVersion:    10,
				CorrelationID: 98765,
				ClientID:      "",
			},
		},
		{
			name: "packet too short",
			packet: func() []byte {
				return make([]byte, 10) // Less than MinKafkaRequestLen
			}(),
			expectErr: true,
			expected:  nil,
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
			expected:  nil,
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
			expected:  nil,
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
			expected:  nil,
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
			expected:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, offset, err := ParseKafkaRequestHeader(tt.packet)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, header)

			assert.Equal(t, tt.expected.MessageSize, header.MessageSize)
			assert.Equal(t, tt.expected.APIKey, header.APIKey)
			assert.Equal(t, tt.expected.APIVersion, header.APIVersion)
			assert.Equal(t, tt.expected.CorrelationID, header.CorrelationID)
			assert.Equal(t, tt.expected.ClientID, header.ClientID)

			expectedOffset := MinKafkaRequestLen + len(tt.expected.ClientID)
			if tt.flexible {
				expectedOffset++ // Account for tagged fields byte
			}
			assert.Equal(t, expectedOffset, offset)
		})
	}
}

func TestValidateKafkaHeader(t *testing.T) {
	tests := []struct {
		name      string
		header    *KafkaRequestHeader
		expectErr bool
	}{
		{
			name: "valid fetch header",
			header: &KafkaRequestHeader{
				MessageSize:   100,
				APIKey:        APIKeyFetch,
				APIVersion:    5,
				CorrelationID: 123,
			},
			expectErr: false,
		},
		{
			name: "valid produce header",
			header: &KafkaRequestHeader{
				MessageSize:   200,
				APIKey:        APIKeyProduce,
				APIVersion:    8,
				CorrelationID: 456,
			},
			expectErr: false,
		},
		{
			name: "valid metadata header",
			header: &KafkaRequestHeader{
				MessageSize:   150,
				APIKey:        APIKeyMetadata,
				APIVersion:    12,
				CorrelationID: 789,
			},
			expectErr: false,
		},
		{
			name: "message size too small",
			header: &KafkaRequestHeader{
				MessageSize:   5,
				APIKey:        APIKeyFetch,
				APIVersion:    1,
				CorrelationID: 123,
			},
			expectErr: true,
		},
		{
			name: "message size too large",
			header: &KafkaRequestHeader{
				MessageSize:   KafkaMaxPayloadLen + 1,
				APIKey:        APIKeyFetch,
				APIVersion:    1,
				CorrelationID: 123,
			},
			expectErr: true,
		},
		{
			name: "negative API version",
			header: &KafkaRequestHeader{
				MessageSize:   100,
				APIKey:        APIKeyFetch,
				APIVersion:    -1,
				CorrelationID: 123,
			},
			expectErr: true,
		},
		{
			name: "negative correlation ID",
			header: &KafkaRequestHeader{
				MessageSize:   100,
				APIKey:        APIKeyFetch,
				APIVersion:    1,
				CorrelationID: -1,
			},
			expectErr: true,
		},
		{
			name: "unsupported metadata version (too low)",
			header: &KafkaRequestHeader{
				MessageSize:   100,
				APIKey:        APIKeyMetadata,
				APIVersion:    9,
				CorrelationID: 123,
			},
			expectErr: true,
		},
		{
			name: "unsupported metadata version (too high)",
			header: &KafkaRequestHeader{
				MessageSize:   100,
				APIKey:        APIKeyMetadata,
				APIVersion:    14,
				CorrelationID: 123,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKafkaRequestHeader(tt.header)
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
		header   *KafkaRequestHeader
		expected bool
	}{
		{
			name: "produce v8 - not flexible",
			header: &KafkaRequestHeader{
				APIKey:     APIKeyProduce,
				APIVersion: 8,
			},
			expected: false,
		},
		{
			name: "produce v9 - flexible",
			header: &KafkaRequestHeader{
				APIKey:     APIKeyProduce,
				APIVersion: 9,
			},
			expected: true,
		},
		{
			name: "fetch v11 - not flexible",
			header: &KafkaRequestHeader{
				APIKey:     APIKeyFetch,
				APIVersion: 11,
			},
			expected: false,
		},
		{
			name: "fetch v12 - flexible",
			header: &KafkaRequestHeader{
				APIKey:     APIKeyFetch,
				APIVersion: 12,
			},
			expected: true,
		},
		{
			name: "metadata v8 - not flexible",
			header: &KafkaRequestHeader{
				APIKey:     APIKeyMetadata,
				APIVersion: 8,
			},
			expected: false,
		},
		{
			name: "metadata v9 - flexible",
			header: &KafkaRequestHeader{
				APIKey:     APIKeyMetadata,
				APIVersion: 9,
			},
			expected: true,
		},
		{
			name: "unknown API key",
			header: &KafkaRequestHeader{
				APIKey:     99,
				APIVersion: 1,
			},
			expected: false,
		},
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
		header         *KafkaRequestHeader
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
			header: &KafkaRequestHeader{
				APIKey:     APIKeyFetch,
				APIVersion: 5, // Non-flexible
			},
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
			header: &KafkaRequestHeader{
				APIKey:     APIKeyFetch,
				APIVersion: 12, // Flexible
			},
			offset:         0,
			expectedLength: 5,
			expectedOffset: 1,
			expectErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			length, offset, err := readArrayLength(tt.packet, tt.header, tt.offset)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedLength, length)
			assert.Equal(t, tt.expectedOffset, offset)
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
				for i := 0; i < UUIDLen; i++ {
					pkt[i] = byte(i)
				}
				return pkt
			}(),
			offset: 0,
			expectedUUID: func() UUID {
				var uuid UUID
				for i := 0; i < UUIDLen; i++ {
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
				for i := 0; i < UUIDLen; i++ {
					pkt[5+i] = byte(i + 10)
				}
				return pkt
			}(),
			offset: 5,
			expectedUUID: func() UUID {
				var uuid UUID
				for i := 0; i < UUIDLen; i++ {
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
			uuid, offset, err := readUUID(tt.packet, tt.offset)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, uuid)
			assert.Equal(t, tt.expectedUUID, *uuid)
			assert.Equal(t, tt.expectedOffset, offset)
		})
	}
}

func TestReadString(t *testing.T) {
	tests := []struct {
		name           string
		packet         []byte
		header         *KafkaRequestHeader
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
			header: &KafkaRequestHeader{
				APIKey:     APIKeyFetch,
				APIVersion: 5, // Non-flexible
			},
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
			header: &KafkaRequestHeader{
				APIKey:     APIKeyFetch,
				APIVersion: 12, // Flexible
			},
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
			header: &KafkaRequestHeader{
				APIKey:     APIKeyFetch,
				APIVersion: 5,
			},
			offset:    0,
			nullable:  false,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str, offset, err := readString(tt.packet, tt.header, tt.offset, tt.nullable)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedString, str)
			assert.Equal(t, tt.expectedOffset, offset)
		})
	}
}

func TestReadUnsignedVarint(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		offset         int
		expectedValue  int
		expectedOffset int
		expectErr      bool
	}{
		{
			name:           "single byte varint",
			data:           []byte{0x05},
			offset:         0,
			expectedValue:  5,
			expectedOffset: 1,
			expectErr:      false,
		},
		{
			name:           "multi-byte varint",
			data:           []byte{0x96, 0x01}, // 150 in varint
			offset:         0,
			expectedValue:  150,
			expectedOffset: 2,
			expectErr:      false,
		},
		{
			name:           "large varint",
			data:           []byte{0xFF, 0xFF, 0x7F}, // Large number
			offset:         0,
			expectedValue:  2097151,
			expectedOffset: 3,
			expectErr:      false,
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
			value, offset, err := readUnsignedVarint(tt.data, tt.offset)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedValue, value)
			assert.Equal(t, tt.expectedOffset, offset)
		})
	}
}

func TestSkipBytes(t *testing.T) {
	tests := []struct {
		name           string
		packet         []byte
		offset         int
		length         int
		expectedOffset int
		expectErr      bool
	}{
		{
			name:           "valid skip",
			packet:         make([]byte, 20),
			offset:         5,
			length:         10,
			expectedOffset: 15,
			expectErr:      false,
		},
		{
			name:      "skip exceeds packet",
			packet:    make([]byte, 10),
			offset:    5,
			length:    10, // 5 + 10 > 10
			expectErr: true,
		},
		{
			name:           "skip zero bytes",
			packet:         make([]byte, 10),
			offset:         3,
			length:         0,
			expectedOffset: 3,
			expectErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offset, err := skipBytes(tt.packet, tt.offset, tt.length)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedOffset, offset)
		})
	}
}

// Truncation tests to simulate incomplete packets
func TestParseKafkaRequestHeaderTruncation(t *testing.T) {
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
			_, _, err := ParseKafkaRequestHeader(truncated)
			assert.Error(t, err, "expected error for truncated packet at position %d", i)
		})
	}
}
