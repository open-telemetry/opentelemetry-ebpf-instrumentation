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

func TestParseProduceRequest(t *testing.T) {
	tests := []struct {
		name                   string
		packet                 []byte
		header                 *KafkaRequestHeader
		expectErr              bool
		expectedTopicCount     int
		expectedTopicName      string
		expectedTopicPartition int
	}{
		{
			name: "produce request v3 non-flexible",
			packet: func() []byte {
				pkt := make([]byte, 100)
				offset := 0

				// transactional_id (nullable string) - null
				binary.BigEndian.PutUint16(pkt[offset:], 0) // null string
				offset += 2

				// acks
				binary.BigEndian.PutUint16(pkt[offset:], 1) // acks
				offset += 2

				// timeout_ms
				binary.BigEndian.PutUint32(pkt[offset:], 30000) // timeout_ms
				offset += 4

				// Topics array
				binary.BigEndian.PutUint32(pkt[offset:], 1) // Topics count
				offset += 4

				// Topic Name
				binary.BigEndian.PutUint16(pkt[offset:], 8) // topic Name length
				offset += 2
				copy(pkt[offset:], "my-topic")
				offset += 8

				return pkt[:offset]
			}(),
			header: &KafkaRequestHeader{
				APIKey:     APIKeyProduce,
				APIVersion: 3,
			},
			expectErr:          false,
			expectedTopicCount: 1,
			expectedTopicName:  "my-topic",
		},
		{
			name: "produce request v8 non-flexible with transaction ID",
			packet: func() []byte {
				pkt := make([]byte, 100)
				offset := 0

				// transactional_id (nullable string) - with value
				binary.BigEndian.PutUint16(pkt[offset:], 6) // string length
				offset += 2
				copy(pkt[offset:], "tx-123")
				offset += 6

				// acks
				binary.BigEndian.PutUint16(pkt[offset:], 0xFFFF) // acks (all, -1 as uint16)
				offset += 2

				// timeout_ms
				binary.BigEndian.PutUint32(pkt[offset:], 30000) // timeout_ms
				offset += 4

				// Topics array
				binary.BigEndian.PutUint32(pkt[offset:], 1) // Topics count
				offset += 4

				// Topic Name
				binary.BigEndian.PutUint16(pkt[offset:], 13) // topic Name length
				offset += 2
				copy(pkt[offset:], "another-topic")
				offset += 13

				return pkt[:offset]
			}(),
			header: &KafkaRequestHeader{
				APIKey:     APIKeyProduce,
				APIVersion: 8,
			},
			expectErr:          false,
			expectedTopicCount: 1,
			expectedTopicName:  "another-topic",
		},
		{
			name: "produce request v9 flexible",
			packet: func() []byte {
				pkt := make([]byte, 100)
				offset := 0

				// transactional_id (compact nullable string) - null
				pkt[offset] = 0x00 // varint 0 for null
				offset++

				// acks
				binary.BigEndian.PutUint16(pkt[offset:], 1) // acks
				offset += 2

				// timeout_ms
				binary.BigEndian.PutUint32(pkt[offset:], 30000) // timeout_ms
				offset += 4

				// Topics array (flexible)
				pkt[offset] = 0x02 // varint for 1 topic (1+1)
				offset++

				// Topic Name (compact string)
				pkt[offset] = 0x09 // varint for length 8 (8+1)
				offset++
				copy(pkt[offset:], "my-topic")
				offset += 8

				return pkt[:offset]
			}(),
			header: &KafkaRequestHeader{
				APIKey:     APIKeyProduce,
				APIVersion: 9,
			},
			expectErr:          false,
			expectedTopicCount: 1,
			expectedTopicName:  "my-topic",
		},
		{
			name: "produce request v12 flexible with transaction ID",
			packet: func() []byte {
				pkt := make([]byte, 100)
				offset := 0

				// transactional_id (compact nullable string) - with value
				pkt[offset] = 0x07 // varint for length 6 (6+1)
				offset++
				copy(pkt[offset:], "tx-456")
				offset += 6

				// acks
				binary.BigEndian.PutUint16(pkt[offset:], 1) // acks
				offset += 2

				// timeout_ms
				binary.BigEndian.PutUint32(pkt[offset:], 30000) // timeout_ms
				offset += 4

				// Topics array (flexible)
				pkt[offset] = 0x03 // varint for 2 Topics (2+1)
				offset++

				// First topic Name (compact string)
				pkt[offset] = 0x07 // varint for length 6 (6+1)
				offset++
				copy(pkt[offset:], "topic1")
				offset += 6

				return pkt[:offset]
			}(),
			header: &KafkaRequestHeader{
				APIKey:     APIKeyProduce,
				APIVersion: 12,
			},
			expectErr:          false,
			expectedTopicCount: 1,
			expectedTopicName:  "topic1", // We'll check the first topic
		},
		{
			name: "produce request v12 flexible with Partition",
			packet: func() []byte {
				pkt := make([]byte, 100)
				offset := 0

				// transactional_id (compact nullable string) - with value
				pkt[offset] = 0x07 // varint for length 6 (6+1)
				offset++
				copy(pkt[offset:], "tx-456")
				offset += 6

				// acks
				binary.BigEndian.PutUint16(pkt[offset:], 1) // acks
				offset += 2

				// timeout_ms
				binary.BigEndian.PutUint32(pkt[offset:], 30000) // timeout_ms
				offset += 4

				// Topics array (flexible)
				pkt[offset] = 0x03 // varint for 2 Topics (2+1)
				offset++

				// First topic Name (compact string)
				pkt[offset] = 0x07 // varint for length 6 (6+1)
				offset++
				copy(pkt[offset:], "topic1")
				offset += 6
				// Partition array (flexible)
				pkt[offset] = 0x02 // varint for 1 Partition (1+1)
				offset++
				// Partition
				binary.BigEndian.PutUint32(pkt[offset:], 5) // Partition
				offset += 4
				return pkt[:offset]
			}(),
			header: &KafkaRequestHeader{
				APIKey:     APIKeyProduce,
				APIVersion: 12,
			},
			expectErr:              false,
			expectedTopicCount:     1,
			expectedTopicName:      "topic1", // We'll check the first topic
			expectedTopicPartition: 5,
		},
		{
			name: "produce request with no Topics",
			packet: func() []byte {
				pkt := make([]byte, 50)
				offset := 0

				// transactional_id (nullable string) - null
				binary.BigEndian.PutUint16(pkt[offset:], 0) // null string
				offset += 2

				// acks
				binary.BigEndian.PutUint16(pkt[offset:], 1) // acks
				offset += 2

				// timeout_ms
				binary.BigEndian.PutUint32(pkt[offset:], 30000) // timeout_ms
				offset += 4

				// Topics array with zero Topics
				binary.BigEndian.PutUint32(pkt[offset:], 0) // Topics count
				offset += 4

				return pkt[:offset]
			}(),
			header: &KafkaRequestHeader{
				APIKey:     APIKeyProduce,
				APIVersion: 3,
			},
			expectErr: true, // Should error on no Topics
		},
		{
			name:   "produce request packet too short",
			packet: []byte{0x01, 0x02}, // Too short
			header: &KafkaRequestHeader{
				APIKey:     APIKeyProduce,
				APIVersion: 3,
			},
			expectErr: true,
		},
		{
			name: "produce request invalid transaction ID length",
			packet: func() []byte {
				pkt := make([]byte, 10)
				// transactional_id with length > available bytes
				binary.BigEndian.PutUint16(pkt[0:], 100) // length too large
				return pkt
			}(),
			header: &KafkaRequestHeader{
				APIKey:     APIKeyProduce,
				APIVersion: 3,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ParseProduceRequest(tt.packet, tt.header, 0)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, req)

			assert.Len(t, req.Topics, tt.expectedTopicCount)

			if tt.expectedTopicCount > 0 {
				firstTopic := req.Topics[0]
				if tt.expectedTopicName != "" {
					assert.Equal(t, tt.expectedTopicName, firstTopic.Name)
				}
				if tt.expectedTopicPartition != 0 {
					assert.Equal(t, tt.expectedTopicPartition, *firstTopic.Partition)
				}
			}
		})
	}
}

func TestProduceRequestSkipUntilTopics(t *testing.T) {
	tests := []struct {
		name           string
		packet         []byte
		header         *KafkaRequestHeader
		expectedOffset int
		expectErr      bool
	}{
		{
			name: "v3-v8 non-flexible with null transaction ID",
			packet: func() []byte {
				pkt := make([]byte, 20)
				offset := 0

				// transactional_id (nullable string) - null
				binary.BigEndian.PutUint16(pkt[offset:], 0) // null string
				offset += 2

				// acks
				binary.BigEndian.PutUint16(pkt[offset:], 1) // acks
				offset += 2

				// timeout_ms
				binary.BigEndian.PutUint32(pkt[offset:], 30000) // timeout_ms

				return pkt
			}(),
			header: &KafkaRequestHeader{
				APIVersion: 5,
			},
			expectedOffset: 8,
			expectErr:      false,
		},
		{
			name: "v3-v8 non-flexible with transaction ID",
			packet: func() []byte {
				pkt := make([]byte, 20)
				offset := 0

				// transactional_id (nullable string) - with value
				binary.BigEndian.PutUint16(pkt[offset:], 6) // string length
				offset += 2
				copy(pkt[offset:], "tx-123")
				offset += 6

				// acks
				binary.BigEndian.PutUint16(pkt[offset:], 1) // acks
				offset += 2

				// timeout_ms
				binary.BigEndian.PutUint32(pkt[offset:], 30000) // timeout_ms

				return pkt
			}(),
			header: &KafkaRequestHeader{
				APIVersion: 7,
			},
			expectedOffset: 14,
			expectErr:      false,
		},
		{
			name: "v9+ flexible with null transaction ID",
			packet: func() []byte {
				pkt := make([]byte, 20)
				offset := 0

				// transactional_id (compact nullable string) - null
				pkt[offset] = 0x00 // varint 0 for null
				offset++

				// acks
				binary.BigEndian.PutUint16(pkt[offset:], 1) // acks
				offset += 2

				// timeout_ms
				binary.BigEndian.PutUint32(pkt[offset:], 30000) // timeout_ms

				return pkt
			}(),
			header: &KafkaRequestHeader{
				APIVersion: 9,
			},
			expectedOffset: 7,
			expectErr:      false,
		},
		{
			name: "v9+ flexible with transaction ID",
			packet: func() []byte {
				pkt := make([]byte, 20)
				offset := 0

				// transactional_id (compact nullable string) - with value
				pkt[offset] = 0x07 // varint for length 6 (6+1)
				offset++
				copy(pkt[offset:], "tx-789")
				offset += 6

				// acks
				binary.BigEndian.PutUint16(pkt[offset:], 1) // acks
				offset += 2

				// timeout_ms
				binary.BigEndian.PutUint32(pkt[offset:], 30000) // timeout_ms

				return pkt
			}(),
			header: &KafkaRequestHeader{
				APIVersion: 10,
			},
			expectedOffset: 13,
			expectErr:      false,
		},
		{
			name:   "packet too short for non-flexible",
			packet: make([]byte, 5),
			header: &KafkaRequestHeader{
				APIVersion: 5,
			},
			expectErr: true,
		},
		{
			name:   "packet too short for flexible",
			packet: make([]byte, 3),
			header: &KafkaRequestHeader{
				APIVersion: 9,
			},
			expectErr: true,
		},
		{
			name: "invalid transaction ID length in non-flexible",
			packet: func() []byte {
				pkt := make([]byte, 5)
				binary.BigEndian.PutUint16(pkt[0:], 100) // length too large
				return pkt
			}(),
			header: &KafkaRequestHeader{
				APIVersion: 5,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offset, err := produceRequestSkipUntilTopics(tt.packet, tt.header, 0)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedOffset, offset)
		})
	}
}

// Comprehensive truncation tests for produce requests
func TestParseProduceRequestTruncation(t *testing.T) {
	// Create a valid produce request packet for each version
	versions := []int16{3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

	for _, version := range versions {
		t.Run(fmt.Sprintf("version_%d_truncation", version), func(t *testing.T) {
			header := &KafkaRequestHeader{
				APIKey:     APIKeyProduce,
				APIVersion: version,
			}

			// Create a valid packet for this version
			validPacket := createValidProducePacket(version)

			// Test truncation at various points
			for i := 1; i < len(validPacket); i++ {
				t.Run(fmt.Sprintf("truncated_at_%d", i), func(t *testing.T) {
					truncated := validPacket[:i]
					_, err := ParseProduceRequest(truncated, header, 0)
					assert.Error(t, err, "expected error for truncated packet at position %d for version %d", i, version)
				})
			}
		})
	}
}

// Test all produce API versions individually
func TestParseProduceRequestAllVersions(t *testing.T) {
	versions := []int16{3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

	for _, version := range versions {
		t.Run(fmt.Sprintf("version_%d", version), func(t *testing.T) {
			header := &KafkaRequestHeader{
				APIKey:     APIKeyProduce,
				APIVersion: version,
			}

			// Create a valid packet for this version
			validPacket := createValidProducePacket(version)

			req, err := ParseProduceRequest(validPacket, header, 0)
			require.NoError(t, err, "unexpected error for version %d", version)
			require.NotNil(t, req)

			assert.Len(t, req.Topics, 1, "version %d: expected 1 topic", version)
			assert.Equal(t, "my-topic", req.Topics[0].Name, "version %d: expected topic Name 'my-topic'", version)
		})
	}
}

// Helper function to create valid produce packets for different versions
func createValidProducePacket(version int16) []byte {
	pkt := make([]byte, 200)
	offset := 0

	if version >= 9 { // Flexible versions
		// transactional_id (compact nullable string) - null
		pkt[offset] = 0x00 // varint 0 for null
		offset++

		// acks
		binary.BigEndian.PutUint16(pkt[offset:], 1) // acks
		offset += 2

		// timeout_ms
		binary.BigEndian.PutUint32(pkt[offset:], 30000) // timeout_ms
		offset += 4

		// Topics array (flexible)
		pkt[offset] = 0x02 // varint for 1 topic (1+1)
		offset++

		// Topic Name (compact string)
		pkt[offset] = 0x09 // varint for length 8 (8+1)
		offset++
		copy(pkt[offset:], "my-topic")
		offset += 8
	} else {
		// Non-flexible versions
		// transactional_id (nullable string) - null
		binary.BigEndian.PutUint16(pkt[offset:], 0) // null string
		offset += 2

		// acks
		binary.BigEndian.PutUint16(pkt[offset:], 1) // acks
		offset += 2

		// timeout_ms
		binary.BigEndian.PutUint32(pkt[offset:], 30000) // timeout_ms
		offset += 4

		// Topics array
		binary.BigEndian.PutUint32(pkt[offset:], 1) // Topics count
		offset += 4

		// Topic Name
		binary.BigEndian.PutUint16(pkt[offset:], 8) // topic Name length
		offset += 2
		copy(pkt[offset:], "my-topic")
		offset += 8
	}

	return pkt[:offset]
}

// Test edge cases for produce requests
func TestParseProduceRequestEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		version   int16
		packet    func() []byte
		expectErr bool
	}{
		{
			name:    "extremely long topic Name non-flexible",
			version: 5,
			packet: func() []byte {
				// Create a topic Name that's very long
				topicName := make([]byte, 1000)
				for i := range topicName {
					topicName[i] = 'a'
				}

				pkt := make([]byte, 2000)
				offset := 0

				// transactional_id - null
				binary.BigEndian.PutUint16(pkt[offset:], 0)
				offset += 2

				// acks
				binary.BigEndian.PutUint16(pkt[offset:], 1)
				offset += 2

				// timeout_ms
				binary.BigEndian.PutUint32(pkt[offset:], 30000)
				offset += 4

				// Topics array
				binary.BigEndian.PutUint32(pkt[offset:], 1)
				offset += 4

				// Topic Name
				binary.BigEndian.PutUint16(pkt[offset:], uint16(len(topicName)))
				offset += 2
				copy(pkt[offset:], topicName)
				offset += len(topicName)

				return pkt[:offset]
			},
			expectErr: false,
		},
		{
			name:    "maximum Topics count",
			version: 5,
			packet: func() []byte {
				pkt := make([]byte, 5000)
				offset := 0

				// transactional_id - null
				binary.BigEndian.PutUint16(pkt[offset:], 0)
				offset += 2

				// acks
				binary.BigEndian.PutUint16(pkt[offset:], 1)
				offset += 2

				// timeout_ms
				binary.BigEndian.PutUint32(pkt[offset:], 30000)
				offset += 4

				// Topics array - 100 Topics
				topicCount := 100
				binary.BigEndian.PutUint32(pkt[offset:], uint32(topicCount))
				offset += 4

				for i := 0; i < topicCount; i++ {
					topicName := fmt.Sprintf("topic%d", i)
					binary.BigEndian.PutUint16(pkt[offset:], uint16(len(topicName)))
					offset += 2
					copy(pkt[offset:], topicName)
					offset += len(topicName)
				}

				return pkt[:offset]
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := &KafkaRequestHeader{
				APIKey:     APIKeyProduce,
				APIVersion: tt.version,
			}

			packet := tt.packet()
			_, err := ParseProduceRequest(packet, header, 0)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
