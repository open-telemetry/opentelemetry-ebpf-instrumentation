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

func TestParseMetadataResponse(t *testing.T) {
	tests := []struct {
		name               string
		packet             []byte
		header             *KafkaRequestHeader
		expectErr          bool
		expectedTopicCount int
		expectedTopicName  string
		expectedTopicUUID  *UUID
	}{
		{
			name: "metadata response v10",
			packet: func() []byte {
				pkt := make([]byte, 200)
				offset := 0

				// throttle_time_ms
				binary.BigEndian.PutUint32(pkt[offset:], 100)
				offset += 4

				// brokers array (flexible)
				pkt[offset] = 0x02 // varint for 1 broker (1+1)
				offset++

				// Broker: node_id
				binary.BigEndian.PutUint32(pkt[offset:], 2)
				offset += 4
				// Broker: host (compact string)
				pkt[offset] = 0x0A // varint for length 9 (9+1)
				offset++
				copy(pkt[offset:], "localhost")
				offset += 9
				// Broker: port
				binary.BigEndian.PutUint32(pkt[offset:], 9092)
				offset += 4
				// Broker: rack (compact nullable string) - null
				pkt[offset] = 0x00 // varint 0 for null
				offset++

				// tagged_fields (empty for this test)
				pkt[offset] = 0x00 // varint 0 for null
				offset++

				// cluster_id (compact nullable string) - with value
				pkt[offset] = 0x08 // varint for length 7 (7+1)
				offset++
				copy(pkt[offset:], "cluster")
				offset += 7

				// controller_id
				binary.BigEndian.PutUint32(pkt[offset:], 2)
				offset += 4

				// Topics array (flexible)
				pkt[offset] = 0x02 // varint for 1 topic (1+1)
				offset++

				// Topic: error_code
				binary.BigEndian.PutUint16(pkt[offset:], 0)
				offset += 2

				pkt[offset] = 0x0B // varint for length 11 (10+1)
				offset++
				copy(pkt[offset:], "topic-test")
				offset += 10

				// Topic: topic_id (UUID)
				expectedUUID := UUID{
					0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
					0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
				}
				copy(pkt[offset:], expectedUUID[:])
				offset += UUIDLen

				return pkt[:offset]
			}(),
			header: &KafkaRequestHeader{
				APIKey:     APIKeyMetadata,
				APIVersion: 12,
			},
			expectErr:          false,
			expectedTopicCount: 1,
			expectedTopicName:  "topic-test",
			expectedTopicUUID: &UUID{
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
			},
		},
		{
			name: "metadata response v12 nullable topic Name",
			packet: func() []byte {
				pkt := make([]byte, 200)
				offset := 0

				// throttle_time_ms
				binary.BigEndian.PutUint32(pkt[offset:], 100)
				offset += 4

				// brokers array (flexible)
				pkt[offset] = 0x02 // varint for 1 broker (1+1)
				offset++

				// Broker: node_id
				binary.BigEndian.PutUint32(pkt[offset:], 2)
				offset += 4
				// Broker: host (compact string)
				pkt[offset] = 0x0A // varint for length 9 (9+1)
				offset++
				copy(pkt[offset:], "localhost")
				offset += 9
				// Broker: port
				binary.BigEndian.PutUint32(pkt[offset:], 9092)
				offset += 4
				// Broker: rack (compact nullable string) - null
				pkt[offset] = 0x00 // varint 0 for null
				offset++

				// tagged_fields (empty for this test)
				pkt[offset] = 0x00 // varint 0 for null
				offset++

				// cluster_id (compact nullable string) - with value
				pkt[offset] = 0x08 // varint for length 7 (7+1)
				offset++
				copy(pkt[offset:], "cluster")
				offset += 7

				// controller_id
				binary.BigEndian.PutUint32(pkt[offset:], 2)
				offset += 4

				// Topics array (flexible)
				pkt[offset] = 0x02 // varint for 1 topic (1+1)
				offset++

				// Topic: error_code
				binary.BigEndian.PutUint16(pkt[offset:], 0)
				offset += 2

				// Topic: Name (compact nullable string) - null in v12+
				pkt[offset] = 0x00 // varint 0 for null
				offset++

				// Topic: topic_id (UUID)
				expectedUUID := UUID{
					0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
					0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
				}
				copy(pkt[offset:], expectedUUID[:])
				offset += UUIDLen

				return pkt[:offset]
			}(),
			header: &KafkaRequestHeader{
				APIKey:     APIKeyMetadata,
				APIVersion: 12,
			},
			expectErr:          false,
			expectedTopicCount: 1,
			expectedTopicName:  "", // null Name in v12+
			expectedTopicUUID: &UUID{
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
			},
		},
		{
			name: "metadata response v13 (latest)",
			packet: func() []byte {
				pkt := make([]byte, 200)
				offset := 0

				// throttle_time_ms
				binary.BigEndian.PutUint32(pkt[offset:], 0)
				offset += 4

				// brokers array (flexible)
				pkt[offset] = 0x03 // varint for 2 brokers (2+1)
				offset++

				// First broker
				binary.BigEndian.PutUint32(pkt[offset:], 1)
				offset += 4
				pkt[offset] = 0x0A // varint for length 9 (9+1)
				offset++
				copy(pkt[offset:], "localhost")
				offset += 9
				binary.BigEndian.PutUint32(pkt[offset:], 9092)
				offset += 4
				pkt[offset] = 0x00 // null rack
				offset++
				// tagged_fields (empty for this test)
				pkt[offset] = 0x00 // varint 0 for null
				offset++

				// Second broker
				binary.BigEndian.PutUint32(pkt[offset:], 2)
				offset += 4
				pkt[offset] = 0x0A // varint for length 9 (9+1)
				offset++
				copy(pkt[offset:], "localhost")
				offset += 9
				binary.BigEndian.PutUint32(pkt[offset:], 9093)
				offset += 4
				pkt[offset] = 0x06 // varint for length 5 (5+1)
				offset++
				copy(pkt[offset:], "rack1")
				offset += 5
				// tagged_fields (empty for this test)
				pkt[offset] = 0x00 // varint 0 for null
				offset++

				// cluster_id (compact nullable string) - null
				pkt[offset] = 0x00
				offset++

				// controller_id
				binary.BigEndian.PutUint32(pkt[offset:], 1)
				offset += 4

				// Topics array (flexible) - multiple Topics
				pkt[offset] = 0x03 // varint for 2 Topics (2+1)
				offset++

				// First topic
				binary.BigEndian.PutUint16(pkt[offset:], 0) // error_code
				offset += 2
				pkt[offset] = 0x07 // varint for length 6 (6+1)
				offset++
				copy(pkt[offset:], "topic1")
				offset += 6
				uuid1 := UUID{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				}
				copy(pkt[offset:], uuid1[:])
				offset += UUIDLen

				pkt[offset] = 0x00 // varint for 0 partitions (0)
				offset++

				binary.BigEndian.PutUint32(pkt[offset:], 0) // topic_authorized_operations
				offset += 4
				// tagged_fields (empty for this test)
				pkt[offset] = 0x00 // varint 0 for null
				offset++

				// Second topic
				binary.BigEndian.PutUint16(pkt[offset:], 0) // error_code
				offset += 2
				pkt[offset] = 0x07 // varint for length 6 (6+1)
				offset++
				copy(pkt[offset:], "topic2")
				offset += 6
				uuid2 := UUID{
					0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
					0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
				}
				copy(pkt[offset:], uuid2[:])
				offset += UUIDLen

				pkt[offset] = 0x00 // varint for 0 partitions (0)
				offset++

				binary.BigEndian.PutUint32(pkt[offset:], 0) // topic_authorized_operations

				return pkt[:offset]
			}(),
			header: &KafkaRequestHeader{
				APIKey:     APIKeyMetadata,
				APIVersion: 13,
			},
			expectErr:          false,
			expectedTopicCount: 2,
			expectedTopicName:  "topic1", // We'll check the first topic
			expectedTopicUUID: &UUID{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
			},
		},
		{
			name: "metadata response with no Topics",
			packet: func() []byte {
				pkt := make([]byte, 100)
				offset := 0

				// throttle_time_ms
				binary.BigEndian.PutUint32(pkt[offset:], 0)
				offset += 4

				// brokers array - empty
				binary.BigEndian.PutUint32(pkt[offset:], 0)
				offset += 4

				// cluster_id (nullable) - null
				binary.BigEndian.PutUint16(pkt[offset:], 0)
				offset += 2

				// controller_id
				binary.BigEndian.PutUint32(pkt[offset:], 0xFFFFFFFF) // No controller (-1 as uint32)
				offset += 4

				// Topics array - empty
				binary.BigEndian.PutUint32(pkt[offset:], 0)
				offset += 4

				return pkt[:offset]
			}(),
			header: &KafkaRequestHeader{
				APIKey:     APIKeyMetadata,
				APIVersion: 10,
			},
			expectErr: true, // Should error on no Topics
		},
		{
			name:   "metadata response packet too short",
			packet: []byte{0x01, 0x02}, // Too short
			header: &KafkaRequestHeader{
				APIKey:     APIKeyMetadata,
				APIVersion: 10,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ParseMetadataResponse(tt.packet, tt.header, 0)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)

			assert.Len(t, resp.Topics, tt.expectedTopicCount)

			if tt.expectedTopicCount > 0 {
				firstTopic := resp.Topics[0]
				assert.Equal(t, tt.expectedTopicName, firstTopic.Name)
				if tt.expectedTopicUUID != nil {
					assert.Equal(t, *tt.expectedTopicUUID, firstTopic.UUID)
				}
			}
		})
	}
}

// Comprehensive truncation tests for metadata responses
func TestParseMetadataResponseTruncation(t *testing.T) {
	// Create a valid metadata response packet for each version
	versions := []int16{10, 11, 12, 13}

	for _, version := range versions {
		t.Run(fmt.Sprintf("version_%d_truncation", version), func(t *testing.T) {
			header := &KafkaRequestHeader{
				APIKey:     APIKeyMetadata,
				APIVersion: version,
			}

			// Create a valid packet for this version
			validPacket := createValidMetadataPacket(version)

			// Test truncation at various points
			for i := 1; i < len(validPacket); i++ {
				t.Run(fmt.Sprintf("truncated_at_%d", i), func(t *testing.T) {
					truncated := validPacket[:i]
					_, err := ParseMetadataResponse(truncated, header, 0)
					assert.Error(t, err, "expected error for truncated packet at position %d for version %d", i, version)
				})
			}
		})
	}
}

// Test all metadata API versions individually
func TestParseMetadataResponseAllVersions(t *testing.T) {
	versions := []int16{10, 11, 12, 13}

	for _, version := range versions {
		t.Run(fmt.Sprintf("version_%d", version), func(t *testing.T) {
			header := &KafkaRequestHeader{
				APIKey:     APIKeyMetadata,
				APIVersion: version,
			}

			// Create a valid packet for this version
			validPacket := createValidMetadataPacket(version)

			resp, err := ParseMetadataResponse(validPacket, header, 0)
			require.NoError(t, err, "unexpected error for version %d", version)
			require.NotNil(t, resp)

			assert.Len(t, resp.Topics, 1, "version %d: expected 1 topic", version)

			expectedName := "my-topic"
			if version >= 12 {
				expectedName = "" // nullable Name in v12+
			}

			assert.Equal(t, expectedName, resp.Topics[0].Name, "version %d: expected topic Name '%s'", version, expectedName)
		})
	}
}

// Helper function to create valid metadata packets for different versions
func createValidMetadataPacket(version int16) []byte {
	pkt := make([]byte, 200)
	offset := 0

	// throttle_time_ms
	binary.BigEndian.PutUint32(pkt[offset:], 0)
	offset += 4

	if version >= 9 { // Flexible versions
		// brokers array (flexible)
		pkt[offset] = 0x02 // varint for 1 broker (1+1)
		offset++

		// Broker
		binary.BigEndian.PutUint32(pkt[offset:], 1)
		offset += 4
		pkt[offset] = 0x0A // varint for length 9 (9+1)
		offset++
		copy(pkt[offset:], "localhost")
		offset += 9
		binary.BigEndian.PutUint32(pkt[offset:], 9092)
		offset += 4
		pkt[offset] = 0x00 // null rack
		offset++
		// tagged_fields (empty for this test)
		pkt[offset] = 0x00 // varint 0 for null
		offset++

		// cluster_id (compact nullable string) - null
		pkt[offset] = 0x00
		offset++

		// controller_id
		binary.BigEndian.PutUint32(pkt[offset:], 1)
		offset += 4

		// Topics array (flexible)
		pkt[offset] = 0x02 // varint for 1 topic (1+1)
		offset++

		// Topic
		binary.BigEndian.PutUint16(pkt[offset:], 0) // error_code
		offset += 2

		if version >= 12 {
			// Name (compact nullable string) - null in v12+
			pkt[offset] = 0x00 // varint 0 for null
			offset++
		} else {
			// Name (compact string)
			pkt[offset] = 0x09 // varint for length 8 (8+1)
			offset++
			copy(pkt[offset:], "my-topic")
			offset += 8
		}

		// topic_id (UUID)
		uuid := UUID{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		}
		copy(pkt[offset:], uuid[:])
		offset += UUIDLen
	} else {
		// Non-flexible versions (not used since we only support v10+)
		// This is just for completeness
		binary.BigEndian.PutUint32(pkt[offset:], 1) // brokers count
		offset += 4

		// Broker
		binary.BigEndian.PutUint32(pkt[offset:], 1)
		offset += 4
		binary.BigEndian.PutUint16(pkt[offset:], 9) // host length
		offset += 2
		copy(pkt[offset:], "localhost")
		offset += 9
		binary.BigEndian.PutUint32(pkt[offset:], 9092)
		offset += 4
		binary.BigEndian.PutUint16(pkt[offset:], 0) // null rack
		offset += 2
		// tagged_fields (empty for this test)
		pkt[offset] = 0x00 // varint 0 for null
		offset++

		// cluster_id (nullable) - null
		binary.BigEndian.PutUint16(pkt[offset:], 0)
		offset += 2

		// controller_id
		binary.BigEndian.PutUint32(pkt[offset:], 1)
		offset += 4

		// Topics array
		binary.BigEndian.PutUint32(pkt[offset:], 1) // Topics count
		offset += 4

		// Topic
		binary.BigEndian.PutUint16(pkt[offset:], 0) // error_code
		offset += 2
		binary.BigEndian.PutUint16(pkt[offset:], 8) // Name length
		offset += 2
		copy(pkt[offset:], "my-topic")
		offset += 8

		// topic_id (UUID)
		uuid := UUID{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
		}
		copy(pkt[offset:], uuid[:])
		offset += UUIDLen
	}

	return pkt[:offset]
}
