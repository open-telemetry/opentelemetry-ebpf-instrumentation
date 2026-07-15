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

func TestParseFetchRequest(t *testing.T) {
	tests := []struct {
		name               string
		packet             []byte
		header             KafkaRequestHeader
		expectErr          bool
		expectedTopicCount int
		expectedTopicName  string
		expectedTopicUUID  *UUID
	}{
		{
			name: "fetch request v4 with topic Name",
			packet: func() []byte {
				pkt := make([]byte, 100)
				offset := 0

				// Skip fields until Topics (v4): replica_id, max_wait_ms, min_bytes, max_bytes, isolation_level
				binary.BigEndian.PutUint32(pkt[offset:], 123) // replica_id
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1000) // max_wait_ms
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1) // min_bytes
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1024) // max_bytes
				offset += 4
				pkt[offset] = 0 // isolation_level
				offset++

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
			header:             newTestHeader(APIKeyFetch, 4),
			expectErr:          false,
			expectedTopicCount: 1,
			expectedTopicName:  "my-topic",
		},
		{
			name: "fetch request v13 with topic UUID",
			packet: func() []byte {
				pkt := make([]byte, 100)
				offset := 0

				// Skip fields until Topics (v13): replica_id, max_wait_ms, min_bytes, max_bytes, isolation_level, session_id, session_epoch
				binary.BigEndian.PutUint32(pkt[offset:], 1) // replica_id
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1000) // max_wait_ms
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1) // min_bytes
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1024) // max_bytes
				offset += 4
				pkt[offset] = 0 // isolation_level
				offset++
				binary.BigEndian.PutUint32(pkt[offset:], 1) // session_id
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1) // session_epoch
				offset += 4

				// Topics array (flexible version uses varint)
				pkt[offset] = 0x02 // varint for 1 topic (1+1)
				offset++

				// Topic UUID
				expectedUUID := UUID{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				}
				copy(pkt[offset:], expectedUUID[:])
				offset += UUIDLen

				return pkt[:offset]
			}(),
			header:             newTestHeader(APIKeyFetch, 13),
			expectErr:          false,
			expectedTopicCount: 1,
			expectedTopicUUID: &UUID{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
			},
		},
		{
			name: "fetch request v15 with topic UUID",
			packet: func() []byte {
				pkt := make([]byte, 100)
				offset := 0

				// Skip fields until Topics (v15): max_wait_ms, min_bytes, max_bytes, isolation_level, session_id, session_epoch
				binary.BigEndian.PutUint32(pkt[offset:], 1000) // max_wait_ms
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1) // min_bytes
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1024) // max_bytes
				offset += 4
				pkt[offset] = 0 // isolation_level
				offset++
				binary.BigEndian.PutUint32(pkt[offset:], 1) // session_id
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1) // session_epoch
				offset += 4

				// Topics array (flexible version uses varint)
				pkt[offset] = 0x02 // varint for 1 topic (1+1)
				offset++

				// Topic UUID
				expectedUUID := UUID{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				}
				copy(pkt[offset:], expectedUUID[:])
				offset += UUIDLen

				return pkt[:offset]
			}(),
			header:             newTestHeader(APIKeyFetch, 15),
			expectErr:          false,
			expectedTopicCount: 1,
			expectedTopicUUID: &UUID{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
			},
		},
		{
			name: "fetch request v12 flexible with topic Name",
			packet: func() []byte {
				pkt := make([]byte, 100)
				offset := 0

				// Skip fields until Topics (v12): replica_id, max_wait_ms, min_bytes, max_bytes, isolation_level, session_id, session_epoch
				binary.BigEndian.PutUint32(pkt[offset:], 123) // replica_id
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1000) // max_wait_ms
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1) // min_bytes
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1024) // max_bytes
				offset += 4
				pkt[offset] = 0 // isolation_level
				offset++
				binary.BigEndian.PutUint32(pkt[offset:], 1) // session_id
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1) // session_epoch
				offset += 4

				// Topics array (flexible version uses varint)
				pkt[offset] = 0x02 // varint for 1 topic (1+1)
				offset++

				// Topic Name (flexible version uses varint for length)
				pkt[offset] = 0x09 // varint for length 8 (8+1)
				offset++
				copy(pkt[offset:], "my-topic")
				offset += 8

				return pkt[:offset]
			}(),
			header:             newTestHeader(APIKeyFetch, 12),
			expectErr:          false,
			expectedTopicCount: 1,
			expectedTopicName:  "my-topic",
		},
		{
			name: "fetch request v17 (latest) with UUID",
			packet: func() []byte {
				pkt := make([]byte, 100)
				offset := 0

				// Skip fields until Topics (v15+): max_wait_ms, min_bytes, max_bytes, isolation_level, session_id, session_epoch
				binary.BigEndian.PutUint32(pkt[offset:], 1000) // max_wait_ms
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1) // min_bytes
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1024) // max_bytes
				offset += 4
				pkt[offset] = 0 // isolation_level
				offset++
				binary.BigEndian.PutUint32(pkt[offset:], 1) // session_id
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1) // session_epoch
				offset += 4

				// Topics array (flexible version uses varint)
				pkt[offset] = 0x02 // varint for 1 topic (1+1)
				offset++

				// Topic UUID
				expectedUUID := UUID{
					0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
					0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
				}
				copy(pkt[offset:], expectedUUID[:])
				offset += UUIDLen

				return pkt[:offset]
			}(),
			header:             newTestHeader(APIKeyFetch, 17),
			expectErr:          false,
			expectedTopicCount: 1,
			expectedTopicUUID: &UUID{
				0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
				0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
			},
		},
		{
			name: "fetch request with multiple Topics v5",
			packet: func() []byte {
				pkt := make([]byte, 200)
				offset := 0

				// Skip fields until Topics (v5): replica_id, max_wait_ms, min_bytes, max_bytes, isolation_level
				binary.BigEndian.PutUint32(pkt[offset:], 123) // replica_id
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1000) // max_wait_ms
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1) // min_bytes
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1024) // max_bytes
				offset += 4
				pkt[offset] = 0 // isolation_level
				offset++

				// Topics array
				binary.BigEndian.PutUint32(pkt[offset:], 2) // Topics count
				offset += 4

				// First topic
				binary.BigEndian.PutUint16(pkt[offset:], 6) // topic Name length
				offset += 2
				copy(pkt[offset:], "topic1")
				offset += 6
				binary.BigEndian.PutUint32(pkt[offset:], 0) // 0 partitions
				offset += 4
				// Second topic
				binary.BigEndian.PutUint16(pkt[offset:], 6) // topic Name length
				offset += 2
				copy(pkt[offset:], "topic2")
				offset += 6

				return pkt[:offset]
			}(),
			header:             newTestHeader(APIKeyFetch, 5),
			expectErr:          false,
			expectedTopicCount: 2,
			expectedTopicName:  "topic1", // We'll check the first topic
		},
		{
			name: "fetch request with no Topics",
			packet: func() []byte {
				pkt := make([]byte, 50)
				offset := 0

				// Skip fields until Topics (v4): replica_id, max_wait_ms, min_bytes, max_bytes, isolation_level
				binary.BigEndian.PutUint32(pkt[offset:], 123) // replica_id
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1000) // max_wait_ms
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1) // min_bytes
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1024) // max_bytes
				offset += 4
				pkt[offset] = 0 // isolation_level
				offset++

				// Topics array with zero Topics
				binary.BigEndian.PutUint32(pkt[offset:], 0) // Topics count
				offset += 4

				return pkt[:offset]
			}(),
			header:    newTestHeader(APIKeyFetch, 4),
			expectErr: true, // Should error on no Topics
		},
		{
			name:      "fetch request packet too short for skip",
			packet:    []byte{0x01, 0x02}, // Too short
			header:    newTestHeader(APIKeyFetch, 4),
			expectErr: true,
		},
		{
			name: "fetch request offset exceeds packet",
			packet: func() []byte {
				pkt := make([]byte, 21) // Exactly enough for skip but not for Topics
				offset := 0

				// Skip fields until Topics (v4): replica_id, max_wait_ms, min_bytes, max_bytes, isolation_level
				binary.BigEndian.PutUint32(pkt[offset:], 123) // replica_id
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1000) // max_wait_ms
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1) // min_bytes
				offset += 4
				binary.BigEndian.PutUint32(pkt[offset:], 1024) // max_bytes
				offset += 4
				pkt[offset] = 0 // isolation_level
				offset++

				// No space for Topics array length
				return pkt[:offset]
			}(),
			header:    newTestHeader(APIKeyFetch, 4),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := largebuf.NewLargeBufferFrom(tt.packet).NewReader()
			req, err := ParseFetchRequest(&r, tt.header)

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
				if tt.expectedTopicUUID != nil {
					assert.Equal(t, tt.expectedTopicUUID, firstTopic.UUID)
				}
			}
		})
	}
}

// TestParseFetchRequestMultiTopicWithPartitions parses a v13 (flexible) request
// with multiple topics, each with a fully-populated partition, and asserts
// topics[1] (UUID + partition) parses correctly, i.e. the reader stayed aligned
// across topics.
func TestParseFetchRequestMultiTopicWithPartitions(t *testing.T) {
	uuid1 := UUID{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	}
	uuid2 := UUID{
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	}

	// Writes one full v12+ partition entry: partition_index, current_leader_epoch,
	// fetch_offset, last_fetched_epoch, log_start_offset, partition_max_bytes,
	// and the per-partition _tagged_fields.
	writePartition := func(pkt []byte, offset int, idx int32, fetchOffset int64) int {
		binary.BigEndian.PutUint32(pkt[offset:], uint32(idx)) // partition_index
		offset += 4
		binary.BigEndian.PutUint32(pkt[offset:], 5) // current_leader_epoch
		offset += 4
		binary.BigEndian.PutUint64(pkt[offset:], uint64(fetchOffset)) // fetch_offset
		offset += 8
		binary.BigEndian.PutUint32(pkt[offset:], 0xFFFFFFFF) // last_fetched_epoch (-1)
		offset += 4
		binary.BigEndian.PutUint64(pkt[offset:], 0) // log_start_offset
		offset += 8
		binary.BigEndian.PutUint32(pkt[offset:], 1048576) // partition_max_bytes
		offset += 4
		pkt[offset] = 0x00 // partition _tagged_fields (empty)
		offset++
		return offset
	}

	pkt := make([]byte, 300)
	offset := 0

	// v13 header fields (v7-14 branch): replica_id, max_wait_ms, min_bytes,
	// max_bytes, isolation_level, session_id, session_epoch.
	binary.BigEndian.PutUint32(pkt[offset:], 1) // replica_id
	offset += 4
	binary.BigEndian.PutUint32(pkt[offset:], 1000) // max_wait_ms
	offset += 4
	binary.BigEndian.PutUint32(pkt[offset:], 1) // min_bytes
	offset += 4
	binary.BigEndian.PutUint32(pkt[offset:], 1024) // max_bytes
	offset += 4
	pkt[offset] = 0 // isolation_level
	offset++
	binary.BigEndian.PutUint32(pkt[offset:], 1) // session_id
	offset += 4
	binary.BigEndian.PutUint32(pkt[offset:], 1) // session_epoch
	offset += 4

	// Topics COMPACT_ARRAY: 2 topics => varint 3 (N+1).
	pkt[offset] = 0x03
	offset++

	// Topic 1: UUID, 1 partition, topic tagged fields.
	copy(pkt[offset:], uuid1[:])
	offset += UUIDLen
	pkt[offset] = 0x02 // partitions COMPACT_ARRAY: 1 => varint 2
	offset++
	offset = writePartition(pkt, offset, 0, 100)
	pkt[offset] = 0x00 // topic _tagged_fields (empty)
	offset++

	// Topic 2: only parsed correctly if topic 1's partition was fully consumed.
	copy(pkt[offset:], uuid2[:])
	offset += UUIDLen
	pkt[offset] = 0x02 // 1 partition
	offset++
	offset = writePartition(pkt, offset, 3, 200)
	pkt[offset] = 0x00 // topic _tagged_fields (empty)
	offset++

	r := largebuf.NewLargeBufferFrom(pkt[:offset]).NewReader()
	req, err := ParseFetchRequest(&r, newTestHeader(APIKeyFetch, 13))
	require.NoError(t, err)
	require.Len(t, req.Topics, 2)

	assert.Equal(t, &uuid1, req.Topics[0].UUID)
	require.NotNil(t, req.Topics[0].Partition)
	assert.Equal(t, 0, req.Topics[0].Partition.Partition)
	assert.Equal(t, int64(100), req.Topics[0].Partition.FetchOffset)

	// The regression assertion: without fully consuming topic 1's partition,
	// this UUID (and partition) would be read from the wrong offset.
	assert.Equal(t, &uuid2, req.Topics[1].UUID)
	require.NotNil(t, req.Topics[1].Partition)
	assert.Equal(t, 3, req.Topics[1].Partition.Partition)
	assert.Equal(t, int64(200), req.Topics[1].Partition.FetchOffset)
}

// Comprehensive truncation tests for fetch requests
func TestParseFetchRequestTruncation(t *testing.T) {
	// Create a valid fetch request packet for each version
	versions := []int16{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}

	for _, version := range versions {
		t.Run(fmt.Sprintf("version_%d_truncation", version), func(t *testing.T) {
			header := newTestHeader(APIKeyFetch, version)

			// Create a valid packet for this version
			validPacket := createValidFetchPacket(version)

			// Test truncation at various points
			for i := 1; i < len(validPacket); i++ {
				t.Run(fmt.Sprintf("truncated_at_%d", i), func(t *testing.T) {
					truncated := validPacket[:i]
					r := largebuf.NewLargeBufferFrom(truncated).NewReader()
					_, err := ParseFetchRequest(&r, header)
					assert.Error(t, err, "expected error for truncated packet at position %d for version %d", i, version)
				})
			}
		})
	}
}

// Helper function to create valid fetch packets for different versions
func createValidFetchPacket(version int16) []byte {
	pkt := make([]byte, 200)
	offset := 0

	switch {
	case version >= 15:
		// v15+: max_wait_ms, min_bytes, max_bytes, isolation_level, session_id, session_epoch
		binary.BigEndian.PutUint32(pkt[offset:], 1000) // max_wait_ms
		offset += 4
		binary.BigEndian.PutUint32(pkt[offset:], 1) // min_bytes
		offset += 4
		binary.BigEndian.PutUint32(pkt[offset:], 1024) // max_bytes
		offset += 4
		pkt[offset] = 0 // isolation_level
		offset++
		binary.BigEndian.PutUint32(pkt[offset:], 1) // session_id
		offset += 4
		binary.BigEndian.PutUint32(pkt[offset:], 1) // session_epoch
		offset += 4
	case version >= 7:
		// v7-14: replica_id, max_wait_ms, min_bytes, max_bytes, isolation_level, session_id, session_epoch
		binary.BigEndian.PutUint32(pkt[offset:], 123) // replica_id
		offset += 4
		binary.BigEndian.PutUint32(pkt[offset:], 1000) // max_wait_ms
		offset += 4
		binary.BigEndian.PutUint32(pkt[offset:], 1) // min_bytes
		offset += 4
		binary.BigEndian.PutUint32(pkt[offset:], 1024) // max_bytes
		offset += 4
		pkt[offset] = 0 // isolation_level
		offset++
		binary.BigEndian.PutUint32(pkt[offset:], 1) // session_id
		offset += 4
		binary.BigEndian.PutUint32(pkt[offset:], 1) // session_epoch
		offset += 4
	case version >= 4:
		// v4-6: replica_id, max_wait_ms, min_bytes, max_bytes, isolation_level
		binary.BigEndian.PutUint32(pkt[offset:], 123) // replica_id
		offset += 4
		binary.BigEndian.PutUint32(pkt[offset:], 1000) // max_wait_ms
		offset += 4
		binary.BigEndian.PutUint32(pkt[offset:], 1) // min_bytes
		offset += 4
		binary.BigEndian.PutUint32(pkt[offset:], 1024) // max_bytes
		offset += 4
		pkt[offset] = 0 // isolation_level
		offset++
	}

	// Add Topics
	if version >= 12 { // Flexible versions
		pkt[offset] = 0x02 // varint for 1 topic (1+1)
		offset++

		if version >= 13 {
			// Topic UUID
			uuid := UUID{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
			}
			copy(pkt[offset:], uuid[:])
			offset += UUIDLen
		} else {
			// Topic Name with varint length
			pkt[offset] = 0x09 // varint for length 8 (8+1)
			offset++
			copy(pkt[offset:], "my-topic")
			offset += 8
		}
	} else {
		// Non-flexible versions
		binary.BigEndian.PutUint32(pkt[offset:], 1) // Topics count
		offset += 4
		binary.BigEndian.PutUint16(pkt[offset:], 8) // topic Name length
		offset += 2
		copy(pkt[offset:], "my-topic")
		offset += 8
	}

	return pkt[:offset]
}
