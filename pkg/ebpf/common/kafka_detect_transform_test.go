// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func TestProcessKafkaRequest(t *testing.T) {
	type requestBytes struct {
		request  []byte
		response []byte
	}
	tests := []struct {
		name        string
		request     []byte
		preRequests []requestBytes
		expected    *KafkaInfo
		err         bool
	}{
		{
			name:    "Produce request (v13, UUID topic, not in cache)",
			request: []byte{0, 0, 1, 199, 0, 0, 0, 13, 0, 0, 81, 17, 0, 21, 107, 97, 102, 107, 97, 45, 112, 114, 111, 100, 117, 99, 101, 114, 45, 102, 105, 103, 104, 116, 115, 0, 0, 0, 1, 0, 0, 117, 48, 2, 172, 231, 101, 123, 36, 212, 77, 228, 142, 87, 26, 240, 250, 236, 204, 15, 2, 0, 0, 0, 0, 134, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 121, 255, 255, 255, 255, 2, 33, 31, 232, 172, 0, 0, 0, 0, 0, 0, 0, 0, 1, 157, 95, 9, 222, 235, 0, 0, 1, 157, 95, 9, 222, 235, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 1, 140, 5, 0, 0, 0, 1, 254, 4, 0, 0, 0, 0, 1, 2, 16, 50, 52, 48, 57, 52, 54, 56, 57, 242, 172, 244, 232, 231, 174, 167, 6, 26, 68, 97, 110, 110, 121, 32, 80, 104, 97, 110, 116, 111, 109, 240, 159, 5, 2, 246, 1, 104, 116, 116, 112, 115, 58, 47, 47, 114, 97, 119, 46, 103, 105, 116, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expected: &KafkaInfo{
				ClientID:  "kafka-producer-fights",
				Operation: Produce,
				Topic:     "*", // UUID not in cache
				PartitionInfo: &PartitionInfo{
					Partition: 0,
				},
			},
		},
		{
			name:    "Produce request (v13, UUID topic, not in cache), another version",
			request: []byte{0, 0, 1, 189, 0, 0, 0, 13, 0, 0, 81, 21, 0, 21, 107, 97, 102, 107, 97, 45, 112, 114, 111, 100, 117, 99, 101, 114, 45, 102, 105, 103, 104, 116, 115, 0, 0, 0, 1, 0, 0, 117, 48, 2, 172, 231, 101, 123, 36, 212, 77, 228, 142, 87, 26, 240, 250, 236, 204, 15, 2, 0, 0, 0, 0, 252, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 111, 255, 255, 255, 255, 2, 136, 54, 30, 204, 0, 0, 0, 0, 0, 0, 0, 0, 1, 157, 95, 9, 223, 232, 0, 0, 1, 157, 95, 9, 223, 232, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 1, 248, 4, 0, 0, 0, 1, 234, 4, 0, 0, 0, 0, 1, 2, 16, 50, 52, 48, 57, 52, 54, 57, 51, 212, 227, 147, 233, 231, 174, 167, 6, 12, 80, 104, 111, 116, 111, 110, 128, 236, 193, 133, 1, 2, 242, 1, 104, 116, 116, 112, 115, 58, 47, 47, 114, 97, 119, 46, 103, 105, 116, 104, 117, 98, 117, 115, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expected: &KafkaInfo{
				ClientID:  "kafka-producer-fights",
				Operation: Produce,
				Topic:     "*", // UUID not in cache
				PartitionInfo: &PartitionInfo{
					Partition: 0,
				},
			},
		},
		{
			name:    "Fetch request (v11)",
			request: []byte{0, 0, 0, 94, 0, 1, 0, 11, 0, 0, 0, 224, 0, 6, 115, 97, 114, 97, 109, 97, 255, 255, 255, 255, 0, 0, 1, 244, 0, 0, 0, 1, 6, 64, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 1, 0, 9, 105, 109, 112, 111, 114, 116, 97, 110, 116, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0},
			expected: &KafkaInfo{
				ClientID:  "sarama",
				Operation: Fetch,
				Topic:     "important",
				PartitionInfo: &PartitionInfo{
					Partition: 0,
					Offset:    19,
				},
			},
		},
		{
			// KIP-227 incremental fetch session: the topic list lives in the
			// broker's session state, so a request with an empty topics array
			// carries no topic information and cannot produce a KafkaInfo.
			name: "Fetch request (v12, incremental session, no topics)",
			request: []byte{
				0, 0, 0, 52, 0, 1, 0, 12, 0, 0, 1, 3, 0, 12,
				99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, // "consumer-1-1"
				0, // header tagged fields
				// replica_id .. session_epoch
				255, 255, 255, 255, 0, 0, 1, 244, 0, 0, 0, 1, 3, 32, 0, 0, 0, 30, 37, 158, 231, 0, 0, 0, 156,
				1, // topics: empty compact array
				1, // forgotten_topics: empty compact array
				1, // rack_id: empty compact string
				0, // tagged fields
			},
			err: true,
		},
		{
			name: "Fetch request (v17) without metadata",
			request: []byte{
				0, 0, 0, 80, 0, 1, 0, 17, 0, 0, 0, 179, 0, 26,
				99, 111, 110, 115, 117, 109, 101, 114, 45, 102, 114, 97, 117, 100, 45, 100,
				101, 116, 101, 99, 116, 105, 111, 110, 45, 49,
				0, 0, 0, 1, 244, 0, 0, 0, 1, 3, 32, 0, 0, 0,
				35, 105, 175, 157, 0, 0, 0, 134, 2,
				// UUID
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
				// 0 partitions
				1,
			},
			expected: &KafkaInfo{
				ClientID:  "consumer-fraud-detection-1",
				Operation: Fetch,
				Topic:     "*",
			},
		},
		{
			name: "Fetch request (v17) with metadata",
			preRequests: []requestBytes{
				{
					request: []byte{
						/*
							type KafkaRequestHeader struct {
								MessageSize   int32
								APIKey        KafkaAPIKey
								APIVersion    int16
								CorrelationID int32
								ClientID      string
							}
						*/
						0, 0, 0, 80, 0, 3, 0, 12, 2, 0, 0, 0, 0, 0, 0,
					},
					response: []byte{
						// Header
						0, 0, 0, 80, 2, 0, 0, 0, 0,
						0, 0, 0, 0, 3, 0, 0, 0, 1, 10, 108, 111, 99, 97, 108, 104, 111, 115, 116, 0, 0, 35, 132, 0, 0, 0, 0, 0, 2, 10, 108, 111, 99, 97, 108, 104,
						111, 115, 116, 0, 0, 35, 133, 6, 114, 97, 99, 107, 49, 0, 0, 0, 0, 0, 1, 3, 0, 0, 7, 116, 111, 112, 105, 99, 49,
						// Topic UUID
						1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
						0, 0, 0, 0,
						0, 0, 0, 7, 116, 111, 112, 105, 99, 50, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 0,
					},
				},
			},
			request: []byte{
				0, 0, 0, 80, 0, 1, 0, 17, 0, 0, 0, 179, 0, 26,
				99, 111, 110, 115, 117, 109, 101, 114, 45, 102, 114, 97, 117, 100, 45, 100,
				101, 116, 101, 99, 116, 105, 111, 110, 45, 49,
				0, 0, 0, 1, 244, 0, 0, 0, 1, 3, 32, 0, 0, 0,
				35, 105, 175, 157, 0, 0, 0, 134, 2,
				// UUID
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
				// 0 partitions
				1,
			},
			expected: &KafkaInfo{
				ClientID:  "consumer-fraud-detection-1",
				Operation: Fetch,
				Topic:     "topic1",
			},
		},
		{
			name:    "Produce request (v7)",
			request: []byte{0, 0, 0, 123, 0, 0, 0, 7, 0, 0, 0, 2, 0, 6, 115, 97, 114, 97, 109, 97, 255, 255, 255, 255, 0, 0, 39, 16, 0, 0, 0, 1, 0, 9, 105, 109, 112, 111, 114, 116, 97, 110, 116, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 72, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 60, 0, 0, 0, 0, 2, 249, 236, 167, 144, 0, 0, 0, 0, 0, 0, 0, 0, 1, 143, 191, 130, 165, 117, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 1, 20, 0, 0, 0, 1, 8, 100, 97, 116, 97, 0},
			expected: &KafkaInfo{
				ClientID:  "sarama",
				Operation: Produce,
				Topic:     "important",
				PartitionInfo: &PartitionInfo{
					Partition: 0,
				},
			},
		},
		{
			name:    "Produce request (v9)",
			request: []byte{0, 0, 0, 124, 0, 0, 0, 9, 0, 0, 0, 8, 0, 10, 112, 114, 111, 100, 117, 99, 101, 114, 45, 49, 0, 0, 0, 1, 0, 0, 117, 48, 2, 9, 109, 121, 45, 116, 111, 112, 105, 99, 2, 0, 0, 0, 0, 78, 103, 0, 0, 0, 1, 2, 0, 0, 9, 109, 121, 45, 116, 111, 112, 105, 99, 193, 136, 51, 44, 67, 57, 71, 124, 178, 93, 33, 21, 191, 31, 138, 233, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 2, 0, 0, 0, 1, 2, 0, 0, 0, 1, 1, 0, 128, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 16, 0, 0, 0, 4, 0, 0, 17},
			expected: &KafkaInfo{
				ClientID:  "producer-1",
				Operation: Produce,
				Topic:     "my-topic",
				PartitionInfo: &PartitionInfo{
					Partition: 0,
				},
			},
		},
		{
			name:    "Invalid request",
			request: []byte{0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 2, 0, 6, 115, 97, 114, 97, 109, 97, 255, 255, 255, 255, 0, 0, 39, 16, 0, 0, 0, 1, 0, 9, 105, 109, 112, 111, 114, 116, 97, 110, 116, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 72},
			err:     true,
		},
		{
			name:    "Redis request",
			request: []byte{42, 51, 13, 10, 36, 52, 13, 10, 72, 71, 69, 84, 13, 10, 36, 51, 54, 13, 10, 56, 97, 100, 48, 101, 56, 99, 97, 45, 101, 97, 49, 57, 45, 52, 50, 97, 57, 45, 98, 51, 55, 48, 45, 98, 99, 97, 102, 102, 50, 55, 54, 55, 98, 56, 54, 13, 10, 36, 52, 13, 10, 99, 97, 114, 116, 13, 10, 103, 58, 32, 34, 51, 49, 117, 50, 107, 97, 100, 98, 108, 113, 53, 106, 34, 13, 10, 99, 111, 110, 116, 101, 110, 116, 45, 108, 101, 110, 103, 116, 104, 58, 32, 49, 57, 57, 13, 10, 118, 97, 114, 121, 58, 32, 65, 99, 99, 101, 112, 116, 45, 69, 110, 99, 111, 100, 105, 110, 103, 13, 10, 100, 97, 116, 101, 58, 32, 87, 101, 100, 44, 32, 48, 51, 32, 74, 117, 108, 32, 50, 48, 50, 52, 32, 49, 55, 58, 52, 54, 58, 49, 55, 32, 71, 77, 84, 13, 10, 120, 45, 101, 110, 118, 111, 121, 45, 117, 112, 115, 116, 114, 101, 97, 109, 45, 115, 101, 114, 118, 105, 99, 101, 45, 116, 105, 109, 101, 58, 32, 51, 13, 10, 115, 101, 114, 118, 101, 114, 58, 32, 101, 110, 118, 111, 121, 13, 10, 13, 10, 91, 34, 90, 65, 82, 34, 44, 34, 73, 83, 75, 34, 44, 34, 73, 76, 83, 34, 44, 34, 82, 79, 78, 34, 44, 34, 71, 66, 80, 34, 44, 34, 66, 82, 76, 34, 44, 34},
			err:     true,
		},
		{
			name:    "Redis request 2",
			request: []byte{36, 45, 49, 13, 10, 1, 0, 15, 0, 3, 89, 130, 0, 32, 99, 111, 110, 115, 117, 109, 101, 114, 45, 102, 114, 97, 117, 100, 100, 101, 116, 101, 99, 116, 105, 111, 110, 115, 101, 114, 118, 105, 99, 101, 45, 49, 0, 0, 0, 1, 244, 0, 0, 0, 1, 3, 32, 0, 0, 0, 17, 170, 173, 222, 0, 0, 141, 2, 1, 1, 1, 0, 101, 112, 116, 45, 114, 97, 110, 103, 101, 115, 58, 32, 98, 121, 116, 101, 115, 13, 10, 108, 97, 115, 116, 45, 109, 111, 100, 105, 102, 105, 101, 100, 58, 32, 70, 114, 105, 44, 32, 48, 55, 32, 74, 117, 110, 32, 50, 48, 50, 52, 32, 48, 48, 58, 53, 55}[:5],
			err:     true,
		},
		{
			name:    "Redis request 2, mixed up data",
			request: []byte{36, 45, 49, 13, 10, 1, 0, 15, 0, 3, 89, 130, 0, 32, 99, 111, 110, 115, 117, 109, 101, 114, 45, 102, 114, 97, 117, 100, 100, 101, 116, 101, 99, 116, 105, 111, 110, 115, 101, 114, 118, 105, 99, 101, 45, 49, 0, 0, 0, 1, 244, 0, 0, 0, 1, 3, 32, 0, 0, 0, 17, 170, 173, 222, 0, 0, 141, 2, 1, 1, 1, 0, 101, 112, 116, 45, 114, 97, 110, 103, 101, 115, 58, 32, 98, 121, 116, 101, 115, 13, 10, 108, 97, 115, 116, 45, 109, 111, 100, 105, 102, 105, 101, 100, 58, 32, 70, 114, 105, 44, 32, 48, 55, 32, 74, 117, 110, 32, 50, 48, 50, 52, 32, 48, 48, 58, 53, 55}[:20],
			err:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache, _ := simplelru.NewLRU[kafkaparser.UUID, string](1000, nil)
			if len(tt.preRequests) > 0 {
				for _, preInput := range tt.preRequests {
					_, ignore, err := ProcessKafkaEvent(largebuf.NewLargeBufferFrom(preInput.request), largebuf.NewLargeBufferFrom(preInput.response), cache, nil, KafkaProcess{})
					require.NoError(t, err)
					require.True(t, ignore)
				}
			}
			res, _, err := ProcessKafkaEvent(largebuf.NewLargeBufferFrom(tt.request), nil, cache, nil, KafkaProcess{})
			if tt.err {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, res, 1)
			assert.Equal(t, tt.expected, res[0])
		})
	}
}

func TestProcessKafkaRequestProduceV13WithoutTopicCache(t *testing.T) {
	request := []byte{
		0, 0, 1, 199, 0, 0, 0, 13, 0, 0, 81, 17, 0, 21, 107, 97, 102, 107, 97, 45, 112, 114, 111, 100, 117, 99, 101, 114, 45, 102, 105, 103, 104, 116, 115, 0, 0,
		0, 1, 0, 0, 117, 48, 2, 172, 231, 101, 123, 36, 212, 77, 228, 142, 87, 26, 240, 250, 236, 204, 15, 2, 0, 0, 0, 0, 134, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 121, 255, 255,
		255, 255, 2, 33, 31, 232, 172, 0, 0, 0, 0, 0, 0, 0, 0, 1, 157, 95, 9, 222, 235, 0, 0, 1, 157, 95, 9, 222, 235, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 0, 0, 0, 1, 140, 5, 0, 0, 0, 1, 254, 4, 0, 0, 0, 0, 1, 2, 16, 50, 52, 48, 57, 52, 54, 56, 57, 242, 172, 244, 232, 231, 174, 167, 6, 26, 68, 97, 110, 110, 121, 32,
		80, 104, 97, 110, 116, 111, 109, 240, 159, 5, 2, 246, 1, 104, 116, 116, 112, 115, 58, 47, 47, 114, 97, 119, 46, 103, 105, 116, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}

	infos, ignore, err := ProcessKafkaEvent(largebuf.NewLargeBufferFrom(request), nil, nil, nil, KafkaProcess{})
	require.NoError(t, err)
	require.False(t, ignore)
	require.Len(t, infos, 1)
	require.Equal(t, &KafkaInfo{
		ClientID:  "kafka-producer-fights",
		Operation: Produce,
		Topic:     "*",
		PartitionInfo: &PartitionInfo{
			Partition: 0,
		},
	}, infos[0])
}

func TestProcessKafkaRequestProduceV13WithTopicCache(t *testing.T) {
	request := []byte{
		0, 0, 1, 199, 0, 0, 0, 13, 0, 0, 81, 17, 0, 21, 107, 97, 102, 107, 97, 45, 112, 114, 111, 100, 117, 99, 101, 114, 45, 102, 105, 103, 104, 116, 115, 0, 0,
		0, 1, 0, 0, 117, 48, 2, 172, 231, 101, 123, 36, 212, 77, 228, 142, 87, 26, 240, 250, 236, 204, 15, 2, 0, 0, 0, 0, 134, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 121, 255, 255,
		255, 255, 2, 33, 31, 232, 172, 0, 0, 0, 0, 0, 0, 0, 0, 1, 157, 95, 9, 222, 235, 0, 0, 1, 157, 95, 9, 222, 235, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 0, 0, 0, 1, 140, 5, 0, 0, 0, 1, 254, 4, 0, 0, 0, 0, 1, 2, 16, 50, 52, 48, 57, 52, 54, 56, 57, 242, 172, 244, 232, 231, 174, 167, 6, 26, 68, 97, 110, 110, 121, 32,
		80, 104, 97, 110, 116, 111, 109, 240, 159, 5, 2, 246, 1, 104, 116, 116, 112, 115, 58, 47, 47, 114, 97, 119, 46, 103, 105, 116, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}

	cache, _ := simplelru.NewLRU[kafkaparser.UUID, string](1000, nil)

	uuid := kafkaparser.UUID{172, 231, 101, 123, 36, 212, 77, 228, 142, 87, 26, 240, 250, 236, 204, 15}
	cache.Add(uuid, "my-topic")

	infos, ignore, err := ProcessKafkaEvent(largebuf.NewLargeBufferFrom(request), nil, cache, nil, KafkaProcess{})
	require.NoError(t, err)
	require.False(t, ignore)
	require.Len(t, infos, 1)
	require.Equal(t, &KafkaInfo{
		ClientID:  "kafka-producer-fights",
		Operation: Produce,
		Topic:     "my-topic",
		PartitionInfo: &PartitionInfo{
			Partition: 0,
		},
	}, infos[0])
}

// TestProcessKafkaRequestFetchMultiTopic verifies that a single multi-topic Fetch
// request yields one KafkaInfo per topic (not just the first), each with its own
// resolved name and partition. This is the transform-side counterpart to the
// parser-level TestParseFetchRequestMultiTopicWithPartitions.
// fetchV13TwoTopics builds a Fetch v13 request (client id "c") for two UUID-identified
// topics: uuid1 partition 0 offset 100, uuid2 partition 3 offset 200.
func fetchV13TwoTopics(uuid1, uuid2 kafkaparser.UUID) []byte {
	// Writes one full v12+ fetch partition entry.
	writePartition := func(pkt []byte, offset int, idx uint32, fetchOffset uint64) int {
		binary.BigEndian.PutUint32(pkt[offset:], idx) // partition_index
		offset += 4
		binary.BigEndian.PutUint32(pkt[offset:], 5) // current_leader_epoch
		offset += 4
		binary.BigEndian.PutUint64(pkt[offset:], fetchOffset) // fetch_offset
		offset += 8
		binary.BigEndian.PutUint32(pkt[offset:], 0xFFFFFFFF) // last_fetched_epoch
		offset += 4
		binary.BigEndian.PutUint64(pkt[offset:], 0) // log_start_offset
		offset += 8
		binary.BigEndian.PutUint32(pkt[offset:], 1048576) // partition_max_bytes
		offset += 4
		pkt[offset] = 0x00 // partition _tagged_fields
		offset++
		return offset
	}

	pkt := make([]byte, 300)
	offset := 0

	// Request header v2 (flexible): message_size is written last.
	offset += 4                                                               // message_size (filled below)
	binary.BigEndian.PutUint16(pkt[offset:], uint16(kafkaparser.APIKeyFetch)) // api_key
	offset += 2
	binary.BigEndian.PutUint16(pkt[offset:], 13) // api_version
	offset += 2
	binary.BigEndian.PutUint32(pkt[offset:], 1) // correlation_id
	offset += 4
	binary.BigEndian.PutUint16(pkt[offset:], 1) // client_id length
	offset += 2
	pkt[offset] = 'c' // client_id
	offset++
	pkt[offset] = 0x00 // header _tagged_fields (flexible)
	offset++

	// Fetch v13 body: replica_id, max_wait_ms, min_bytes, max_bytes, isolation_level, session_id, session_epoch.
	binary.BigEndian.PutUint32(pkt[offset:], 1)
	offset += 4
	binary.BigEndian.PutUint32(pkt[offset:], 1000)
	offset += 4
	binary.BigEndian.PutUint32(pkt[offset:], 1)
	offset += 4
	binary.BigEndian.PutUint32(pkt[offset:], 1024)
	offset += 4
	pkt[offset] = 0 // isolation_level
	offset++
	binary.BigEndian.PutUint32(pkt[offset:], 1) // session_id
	offset += 4
	binary.BigEndian.PutUint32(pkt[offset:], 1) // session_epoch
	offset += 4

	pkt[offset] = 0x03 // topics COMPACT_ARRAY: 2 topics (N+1)
	offset++
	// topic 1
	copy(pkt[offset:], uuid1[:])
	offset += kafkaparser.UUIDLen
	pkt[offset] = 0x02 // 1 partition
	offset++
	offset = writePartition(pkt, offset, 0, 100)
	pkt[offset] = 0x00 // topic _tagged_fields
	offset++
	// topic 2
	copy(pkt[offset:], uuid2[:])
	offset += kafkaparser.UUIDLen
	pkt[offset] = 0x02 // 1 partition
	offset++
	offset = writePartition(pkt, offset, 3, 200)
	pkt[offset] = 0x00 // topic _tagged_fields
	offset++

	pkt = pkt[:offset]
	binary.BigEndian.PutUint32(pkt[0:], uint32(offset-4)) // message_size
	return pkt
}

var (
	fetchUUID1 = kafkaparser.UUID{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	}
	fetchUUID2 = kafkaparser.UUID{
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	}
)

func TestProcessKafkaRequestFetchMultiTopic(t *testing.T) {
	pkt := fetchV13TwoTopics(fetchUUID1, fetchUUID2)

	cache, _ := simplelru.NewLRU[kafkaparser.UUID, string](1000, nil)
	cache.Add(fetchUUID1, "topic-one")
	cache.Add(fetchUUID2, "topic-two")

	infos, ignore, err := ProcessKafkaEvent(largebuf.NewLargeBufferFrom(pkt), nil, cache, nil, KafkaProcess{})
	require.NoError(t, err)
	require.False(t, ignore)
	require.Len(t, infos, 2)

	require.Equal(t, &KafkaInfo{
		ClientID:      "c",
		Operation:     Fetch,
		Topic:         "topic-one",
		PartitionInfo: &PartitionInfo{Partition: 0, Offset: 100},
	}, infos[0])
	require.Equal(t, &KafkaInfo{
		ClientID:      "c",
		Operation:     Fetch,
		Topic:         "topic-two",
		PartitionInfo: &PartitionInfo{Partition: 3, Offset: 200},
	}, infos[1])
}

func TestProcessKafkaRequestProduceMultiTopic(t *testing.T) {
	writeTopic := func(pkt []byte, offset, partition int, name string) int {
		pkt[offset] = byte(len(name) + 1) // COMPACT_STRING length
		offset++
		copy(pkt[offset:], name)
		offset += len(name)
		pkt[offset] = 0x02 // one partition in the COMPACT_ARRAY
		offset++
		binary.BigEndian.PutUint32(pkt[offset:], uint32(partition))
		offset += 4
		pkt[offset] = 0x02 // one-byte COMPACT_RECORDS payload
		offset++
		pkt[offset] = 0x00
		offset++
		pkt[offset] = 0x00 // partition tagged fields
		offset++
		pkt[offset] = 0x00 // topic tagged fields
		return offset + 1
	}

	pkt := make([]byte, 128)
	offset := 0
	offset += 4 // message_size (filled below)
	binary.BigEndian.PutUint16(pkt[offset:], uint16(kafkaparser.APIKeyProduce))
	offset += 2
	binary.BigEndian.PutUint16(pkt[offset:], 9) // flexible Produce request
	offset += 2
	binary.BigEndian.PutUint32(pkt[offset:], 1) // correlation_id
	offset += 4
	binary.BigEndian.PutUint16(pkt[offset:], 1) // client_id length
	offset += 2
	pkt[offset] = 'c'
	offset++
	pkt[offset] = 0x00 // request header tagged fields
	offset++

	pkt[offset] = 0x00 // null transactional_id
	offset++
	binary.BigEndian.PutUint16(pkt[offset:], 1) // acks
	offset += 2
	binary.BigEndian.PutUint32(pkt[offset:], 30000) // timeout_ms
	offset += 4
	pkt[offset] = 0x03 // two topics in the COMPACT_ARRAY
	offset++
	offset = writeTopic(pkt, offset, 0, "topic-one")
	offset = writeTopic(pkt, offset, 3, "topic-two")
	pkt[offset] = 0x00 // request tagged fields
	offset++

	pkt = pkt[:offset]
	binary.BigEndian.PutUint32(pkt[0:], uint32(offset-4))

	infos, ignore, err := ProcessKafkaEvent(largebuf.NewLargeBufferFrom(pkt), nil, nil, nil, KafkaProcess{})
	require.NoError(t, err)
	require.False(t, ignore)
	require.Len(t, infos, 2)

	require.Equal(t, &KafkaInfo{
		ClientID:      "c",
		Operation:     Produce,
		Topic:         "topic-one",
		PartitionInfo: &PartitionInfo{Partition: 0},
	}, infos[0])
	require.Equal(t, &KafkaInfo{
		ClientID:      "c",
		Operation:     Produce,
		Topic:         "topic-two",
		PartitionInfo: &PartitionInfo{Partition: 3},
	}, infos[1])
}

// Fixtures generated from the Kafka wire schemas (client id "consumer-1-1" in every
// header, member id "member-abc-123" unless said otherwise):
//   - joinGroupMyGroup:    JoinGroup v7, GroupId "my-group",    subscription [orders, audit]
//   - joinGroupOtherGroup: JoinGroup v7, GroupId "other-group", subscription [payments]
//   - joinGroupOtherGroupOrders: JoinGroup v7, GroupId "other-group", subscription [orders]
//   - joinGroupMyGroupAudit: JoinGroup v7, GroupId "my-group", subscription [audit]
//   - joinGroupMyGroupNoMemberID: JoinGroup v7, GroupId "my-group", empty member id (first join), subscription [orders, audit]
//   - joinGroupMyGroupPayments: JoinGroup v7, GroupId "my-group", member id "member-def-456", subscription [payments]
//   - heartbeatHbGroup:    Heartbeat v4, GroupId "hb-group"
//   - heartbeatMyGroupDef: Heartbeat v4, GroupId "my-group", member id "member-def-456"
//   - offsetCommitOtherGroupUUID: OffsetCommit v10, GroupId "other-group", topics fetchUUID1 and fetchUUID2 (by id)
//   - offsetCommitMyGroupOrders: OffsetCommit v8, GroupId "my-group", topic orders
//   - offset*AdminGroup:   OffsetFetch v7 / OffsetCommit v8, GroupId "admin-group", topic orders
//   - leaveGroup*:         LeaveGroup v5, GroupId "my-group" / "other-group"; leaveGroupMyGroupDef / leaveGroupMyGroupUnknown name "member-def-456" / "member-xyz-789"
//   - cghJoinCghGroup:     ConsumerGroupHeartbeat v0, GroupId "cgh-group", member epoch 0, subscription [orders]
//   - cghLeaveCghGroup:    ConsumerGroupHeartbeat v0, GroupId "cgh-group", member epoch -1 (leave)
//   - cghJoinCghGroupAudit / cghUnchangedCghGroup / cghEmptyCghGroup: ConsumerGroupHeartbeat v0, GroupId "cgh-group", subscription [audit] / null (unchanged) / [] (regex member)
//   - joinGroupConnectCluster / heartbeatConnectCluster / leaveGroupConnectCluster: JoinGroup v5 protocol_type "connect" / Heartbeat v4 / LeaveGroup v5, GroupId "connect-cluster"
//   - syncGroupSchemaRegistry: SyncGroup v5, GroupId "schema-registry", protocol_type "sr"
//   - offsetCommitHbGroupOrders: OffsetCommit v8, GroupId "hb-group", topic orders
//   - fetch*:              Fetch v4, one topic, partition 0, offset 19
var (
	joinGroupMyGroup           = []byte{0, 0, 0, 104, 0, 11, 0, 7, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 9, 109, 121, 45, 103, 114, 111, 117, 112, 0, 0, 39, 16, 0, 0, 117, 48, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 9, 99, 111, 110, 115, 117, 109, 101, 114, 2, 6, 114, 97, 110, 103, 101, 30, 0, 1, 0, 0, 0, 2, 0, 6, 111, 114, 100, 101, 114, 115, 0, 5, 97, 117, 100, 105, 116, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0}
	joinGroupOtherGroup        = []byte{0, 0, 0, 102, 0, 11, 0, 7, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 12, 111, 116, 104, 101, 114, 45, 103, 114, 111, 117, 112, 0, 0, 39, 16, 0, 0, 117, 48, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 9, 99, 111, 110, 115, 117, 109, 101, 114, 2, 6, 114, 97, 110, 103, 101, 25, 0, 1, 0, 0, 0, 1, 0, 8, 112, 97, 121, 109, 101, 110, 116, 115, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0}
	joinGroupOtherGroupOrders  = []byte{0, 0, 0, 100, 0, 11, 0, 7, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 12, 111, 116, 104, 101, 114, 45, 103, 114, 111, 117, 112, 0, 0, 39, 16, 0, 0, 117, 48, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 9, 99, 111, 110, 115, 117, 109, 101, 114, 2, 6, 114, 97, 110, 103, 101, 23, 0, 1, 0, 0, 0, 1, 0, 6, 111, 114, 100, 101, 114, 115, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0}
	joinGroupMyGroupAudit      = []byte{0, 0, 0, 96, 0, 11, 0, 7, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 9, 109, 121, 45, 103, 114, 111, 117, 112, 0, 0, 39, 16, 0, 0, 117, 48, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 9, 99, 111, 110, 115, 117, 109, 101, 114, 2, 6, 114, 97, 110, 103, 101, 22, 0, 1, 0, 0, 0, 1, 0, 5, 97, 117, 100, 105, 116, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0}
	joinGroupMyGroupNoMemberID = []byte{0, 0, 0, 90, 0, 11, 0, 7, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 9, 109, 121, 45, 103, 114, 111, 117, 112, 0, 0, 39, 16, 0, 0, 117, 48, 1, 0, 9, 99, 111, 110, 115, 117, 109, 101, 114, 2, 6, 114, 97, 110, 103, 101, 30, 0, 1, 0, 0, 0, 2, 0, 6, 111, 114, 100, 101, 114, 115, 0, 5, 97, 117, 100, 105, 116, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0}
	joinGroupMyGroupPayments   = []byte{0, 0, 0, 99, 0, 11, 0, 7, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 9, 109, 121, 45, 103, 114, 111, 117, 112, 0, 0, 39, 16, 0, 0, 117, 48, 15, 109, 101, 109, 98, 101, 114, 45, 100, 101, 102, 45, 52, 53, 54, 0, 9, 99, 111, 110, 115, 117, 109, 101, 114, 2, 6, 114, 97, 110, 103, 101, 25, 0, 1, 0, 0, 0, 1, 0, 8, 112, 97, 121, 109, 101, 110, 116, 115, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0}
	heartbeatMyGroupDef        = []byte{0, 0, 0, 53, 0, 12, 0, 4, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 9, 109, 121, 45, 103, 114, 111, 117, 112, 0, 0, 0, 3, 15, 109, 101, 109, 98, 101, 114, 45, 100, 101, 102, 45, 52, 53, 54, 0, 0}
	leaveGroupMyGroupDef       = []byte{0, 0, 0, 52, 0, 13, 0, 5, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 9, 109, 121, 45, 103, 114, 111, 117, 112, 2, 15, 109, 101, 109, 98, 101, 114, 45, 100, 101, 102, 45, 52, 53, 54, 0, 0, 0, 0}
	leaveGroupMyGroupUnknown   = []byte{0, 0, 0, 52, 0, 13, 0, 5, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 9, 109, 121, 45, 103, 114, 111, 117, 112, 2, 15, 109, 101, 109, 98, 101, 114, 45, 120, 121, 122, 45, 55, 56, 57, 0, 0, 0, 0}
	heartbeatHbGroup           = []byte{0, 0, 0, 53, 0, 12, 0, 4, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 9, 104, 98, 45, 103, 114, 111, 117, 112, 0, 0, 0, 3, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 0}
	offsetCommitOtherGroupUUID = []byte{0, 0, 0, 129, 0, 8, 0, 10, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 12, 111, 116, 104, 101, 114, 45, 103, 114, 111, 117, 112, 0, 0, 0, 3, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 42, 255, 255, 255, 255, 0, 0, 0, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 42, 255, 255, 255, 255, 0, 0, 0, 0}
	offsetCommitMyGroupOrders  = []byte{0, 0, 0, 81, 0, 8, 0, 8, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 9, 109, 121, 45, 103, 114, 111, 117, 112, 0, 0, 0, 3, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 2, 7, 111, 114, 100, 101, 114, 115, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 42, 255, 255, 255, 255, 0, 0, 0, 0}
	offsetFetchAdminGroup      = []byte{0, 0, 0, 51, 0, 9, 0, 7, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 12, 97, 100, 109, 105, 110, 45, 103, 114, 111, 117, 112, 2, 7, 111, 114, 100, 101, 114, 115, 2, 0, 0, 0, 0, 0, 0, 0}
	offsetCommitAdminGroup     = []byte{0, 0, 0, 84, 0, 8, 0, 8, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 12, 97, 100, 109, 105, 110, 45, 103, 114, 111, 117, 112, 0, 0, 0, 3, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 2, 7, 111, 114, 100, 101, 114, 115, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 42, 255, 255, 255, 255, 0, 0, 0, 0}
	leaveGroupMyGroup          = []byte{0, 0, 0, 52, 0, 13, 0, 5, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 9, 109, 121, 45, 103, 114, 111, 117, 112, 2, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 0, 0, 0}
	leaveGroupOtherGroup       = []byte{0, 0, 0, 55, 0, 13, 0, 5, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 12, 111, 116, 104, 101, 114, 45, 103, 114, 111, 117, 112, 2, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 0, 0, 0}
	cghJoinCghGroup            = []byte{0, 0, 0, 69, 0, 68, 0, 0, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 10, 99, 103, 104, 45, 103, 114, 111, 117, 112, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 2, 7, 111, 114, 100, 101, 114, 115, 0, 0, 0}
	cghJoinCghGroupAudit       = []byte{0, 0, 0, 68, 0, 68, 0, 0, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 10, 99, 103, 104, 45, 103, 114, 111, 117, 112, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 2, 6, 97, 117, 100, 105, 116, 0, 0, 0}
	cghUnchangedCghGroup       = []byte{0, 0, 0, 62, 0, 68, 0, 0, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 10, 99, 103, 104, 45, 103, 114, 111, 117, 112, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 0, 0, 5, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0}
	cghEmptyCghGroup           = []byte{0, 0, 0, 62, 0, 68, 0, 0, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 10, 99, 103, 104, 45, 103, 114, 111, 117, 112, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 0, 0, 5, 0, 0, 255, 255, 255, 255, 1, 0, 0, 0}
	cghLeaveCghGroup           = []byte{0, 0, 0, 62, 0, 68, 0, 0, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 10, 99, 103, 104, 45, 103, 114, 111, 117, 112, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 255, 255, 255, 255, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0}
	joinGroupConnectCluster    = []byte{0, 0, 0, 89, 0, 11, 0, 5, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 15, 99, 111, 110, 110, 101, 99, 116, 45, 99, 108, 117, 115, 116, 101, 114, 0, 0, 39, 16, 0, 0, 117, 48, 0, 0, 255, 255, 0, 7, 99, 111, 110, 110, 101, 99, 116, 0, 0, 0, 1, 0, 5, 114, 97, 110, 103, 101, 0, 0, 0, 14, 0, 1, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0}
	heartbeatConnectCluster    = []byte{0, 0, 0, 60, 0, 12, 0, 4, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 16, 99, 111, 110, 110, 101, 99, 116, 45, 99, 108, 117, 115, 116, 101, 114, 0, 0, 0, 3, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 0}
	leaveGroupConnectCluster   = []byte{0, 0, 0, 59, 0, 13, 0, 5, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 16, 99, 111, 110, 110, 101, 99, 116, 45, 99, 108, 117, 115, 116, 101, 114, 2, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 0, 0, 0}
	syncGroupSchemaRegistry    = []byte{0, 0, 0, 65, 0, 14, 0, 5, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 16, 115, 99, 104, 101, 109, 97, 45, 114, 101, 103, 105, 115, 116, 114, 121, 0, 0, 0, 3, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 3, 115, 114, 0, 1, 0}
	offsetCommitHbGroupOrders  = []byte{0, 0, 0, 81, 0, 8, 0, 8, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 9, 104, 98, 45, 103, 114, 111, 117, 112, 0, 0, 0, 3, 15, 109, 101, 109, 98, 101, 114, 45, 97, 98, 99, 45, 49, 50, 51, 0, 2, 7, 111, 114, 100, 101, 114, 115, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 42, 255, 255, 255, 255, 0, 0, 0, 0}
	fetchOrders                = []byte{0, 0, 0, 71, 0, 1, 0, 4, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 255, 255, 255, 255, 0, 0, 1, 244, 0, 0, 0, 1, 0, 16, 0, 0, 0, 0, 0, 0, 1, 0, 6, 111, 114, 100, 101, 114, 115, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 16, 0, 0}
	fetchPayments              = []byte{0, 0, 0, 73, 0, 1, 0, 4, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 255, 255, 255, 255, 0, 0, 1, 244, 0, 0, 0, 1, 0, 16, 0, 0, 0, 0, 0, 0, 1, 0, 8, 112, 97, 121, 109, 101, 110, 116, 115, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 16, 0, 0}
	fetchImportant             = []byte{0, 0, 0, 74, 0, 1, 0, 4, 0, 0, 0, 7, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 255, 255, 255, 255, 0, 0, 1, 244, 0, 0, 0, 1, 0, 16, 0, 0, 0, 0, 0, 0, 1, 0, 9, 105, 109, 112, 111, 114, 116, 97, 110, 116, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 16, 0, 0}
)

// kafkaEventFromPid builds a client-side (send-first) event; the zero Direction would be
// directionRecv, i.e. a server-side capture, which never learns or reports groups.
func kafkaEventFromPid(ns, pid uint32) *TCPRequestInfo {
	event := &TCPRequestInfo{}
	event.Direction = directionSend
	event.Pid.Ns = ns
	event.Pid.UserPid = pid
	event.Pid.HostPid = pid
	return event
}

func newTestConsumerGroups() *KafkaConsumerGroups {
	return NewKafkaConsumerGroups(64, time.Minute)
}

// processKafka runs one request through the same entry point the TCP pipeline uses.
func processKafka(t *testing.T, groups *KafkaConsumerGroups, event *TCPRequestInfo, request []byte) ([]*KafkaInfo, bool) {
	t.Helper()
	uuidCache, err := simplelru.NewLRU[kafkaparser.UUID, string](16, nil)
	require.NoError(t, err)
	infos, ignore, err := ProcessPossibleKafkaEvent(event, largebuf.NewLargeBufferFrom(request), nil, uuidCache, groups)
	require.NoError(t, err)
	return infos, ignore
}

func fetchGroup(t *testing.T, groups *KafkaConsumerGroups, event *TCPRequestInfo, request []byte) string {
	t.Helper()
	infos, ignore := processKafka(t, groups, event, request)
	require.False(t, ignore)
	require.Len(t, infos, 1)
	assert.Equal(t, Fetch, infos[0].Operation)
	return infos[0].ConsumerGroup
}

func TestProcessKafkaEventConsumerGroup(t *testing.T) {
	groups := newTestConsumerGroups()

	consumer := kafkaEventFromPid(7, 42)
	otherProcess := kafkaEventFromPid(7, 43)
	sameProcessOtherNs := kafkaEventFromPid(8, 42)

	t.Run("group requests are recognized but produce no span", func(t *testing.T) {
		infos, ignore := processKafka(t, groups, consumer, joinGroupMyGroup)
		assert.True(t, ignore)
		assert.Nil(t, infos)
	})

	t.Run("fetch of a subscribed topic from the same pid gets the group", func(t *testing.T) {
		assert.Equal(t, "my-group", fetchGroup(t, groups, consumer, fetchOrders))
	})

	t.Run("fetch of an unknown topic falls back to the single consumer group", func(t *testing.T) {
		// KIP-227 session fetches carry no topic, and a JoinGroup truncated by the
		// kernel buffer may miss topics: the single group seen for the pid is used.
		assert.Equal(t, "my-group", fetchGroup(t, groups, consumer, fetchImportant))
	})

	t.Run("other pid or other namespace stays without group", func(t *testing.T) {
		assert.Empty(t, fetchGroup(t, groups, otherProcess, fetchOrders))
		assert.Empty(t, fetchGroup(t, groups, sameProcessOtherNs, fetchOrders))
	})

	t.Run("second group in the same process: topic decides, unknown topics get nothing", func(t *testing.T) {
		_, ignore := processKafka(t, groups, consumer, joinGroupOtherGroup)
		assert.True(t, ignore)

		assert.Equal(t, "my-group", fetchGroup(t, groups, consumer, fetchOrders))
		assert.Equal(t, "other-group", fetchGroup(t, groups, consumer, fetchPayments))
		assert.Empty(t, fetchGroup(t, groups, consumer, fetchImportant), "two groups: must not guess")
	})

	t.Run("same topic consumed by two groups of one process: no group for that topic", func(t *testing.T) {
		_, ignore := processKafka(t, groups, consumer, joinGroupOtherGroupOrders)
		assert.True(t, ignore)

		assert.Empty(t, fetchGroup(t, groups, consumer, fetchOrders), "topic subscribed by two groups must not guess")
		assert.Equal(t, "my-group", groups.Lookup(KafkaProcess{Ns: 7, Pid: 42}, "audit"), "audit is still my-group's alone")
		// other-group's new subscription is [orders]: payments is nobody's, and the
		// process has two groups, so there is nothing to fall back to
		assert.Empty(t, fetchGroup(t, groups, consumer, fetchPayments))
	})

	t.Run("heartbeat alone (mid-stream attach) is enough for the single consumer group", func(t *testing.T) {
		midStream := kafkaEventFromPid(7, 99)
		_, ignore := processKafka(t, groups, midStream, heartbeatHbGroup)
		assert.True(t, ignore)
		assert.Equal(t, "hb-group", fetchGroup(t, groups, midStream, fetchImportant))
	})

	t.Run("produce never gets a group", func(t *testing.T) {
		produceV9 := []byte{0, 0, 0, 124, 0, 0, 0, 9, 0, 0, 0, 8, 0, 10, 112, 114, 111, 100, 117, 99, 101, 114, 45, 49, 0, 0, 0, 1, 0, 0, 117, 48, 2, 9, 109, 121, 45, 116, 111, 112, 105, 99, 2, 0, 0, 0, 0, 78, 103, 0, 0, 0, 1, 2, 0, 0, 9, 109, 121, 45, 116, 111, 112, 105, 99, 193, 136, 51, 44, 67, 57, 71, 124, 178, 93, 33, 21, 191, 31, 138, 233, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 2, 0, 0, 0, 1, 2, 0, 0, 0, 1, 1, 0, 128, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 16, 0, 0, 0, 4, 0, 0, 17}
		midStream := kafkaEventFromPid(7, 99)
		infos, ignore := processKafka(t, groups, midStream, produceV9)
		require.False(t, ignore)
		require.Len(t, infos, 1)
		assert.Equal(t, Produce, infos[0].Operation)
		assert.Empty(t, infos[0].ConsumerGroup)
	})
}

func TestTCPToKafkaToSpanConsumerGroup(t *testing.T) {
	event := kafkaEventFromPid(7, 42)

	// group known, partition list cut: the group is reported, the partition is not
	span := TCPToKafkaToSpan(event, &KafkaInfo{Operation: Fetch, Topic: "orders", ConsumerGroup: "my-group"})
	require.NotNil(t, span.MessagingInfo)
	assert.Equal(t, "my-group", span.MessagingInfo.ConsumerGroup)
	assert.False(t, span.MessagingInfo.HasPartition)

	span = TCPToKafkaToSpan(event, &KafkaInfo{
		Operation: Fetch, Topic: "orders", ConsumerGroup: "my-group",
		PartitionInfo: &PartitionInfo{Partition: 3, Offset: 42},
	})
	require.NotNil(t, span.MessagingInfo)
	assert.True(t, span.MessagingInfo.HasPartition)
	assert.Equal(t, 3, span.MessagingInfo.Partition)
	assert.Equal(t, int64(42), span.MessagingInfo.Offset)

	// nothing known: no MessagingInfo, so no partition "0" is ever fabricated
	span = TCPToKafkaToSpan(event, &KafkaInfo{Operation: Fetch, Topic: "orders"})
	assert.Nil(t, span.MessagingInfo)
}

// A broker receives every client's JoinGroup/OffsetCommit: server-side events must
// neither learn nor report a consumer group, while the partition is still reported.
func TestProcessKafkaEventConsumerGroupServerSide(t *testing.T) {
	groups := newTestConsumerGroups()

	broker := kafkaEventFromPid(7, 500)
	broker.Direction = directionRecv

	infos, ignore := processKafka(t, groups, broker, joinGroupMyGroup)
	assert.True(t, ignore)
	assert.Nil(t, infos)

	infos, ignore = processKafka(t, groups, broker, fetchOrders)
	require.False(t, ignore)
	require.Len(t, infos, 1)
	assert.Empty(t, infos[0].ConsumerGroup, "server spans never carry a group")
	require.NotNil(t, infos[0].PartitionInfo)

	span := TCPToKafkaToSpan(broker, infos[0])
	assert.Equal(t, request.EventTypeKafkaServer, span.Type)
	require.NotNil(t, span.MessagingInfo)
	assert.True(t, span.MessagingInfo.HasPartition)
	assert.Empty(t, span.MessagingInfo.ConsumerGroup)

	// nothing was learned under the broker pid either
	assert.Empty(t, groups.Lookup(KafkaProcess{Ns: 7, Pid: 500}, "orders"))
	assert.Empty(t, groups.Lookup(KafkaProcess{Ns: 7, Pid: 500}, ""))
}

// Fetch v13+ identifies topics by UUID: the group lookup must use the name resolved
// through the Metadata cache, otherwise per-topic entries never match and a process
// with two groups gets nothing.
func TestProcessKafkaEventConsumerGroupFetchByUUID(t *testing.T) {
	groups := newTestConsumerGroups()
	uuidCache, err := simplelru.NewLRU[kafkaparser.UUID, string](16, nil)
	require.NoError(t, err)
	uuidCache.Add(fetchUUID1, "orders")
	uuidCache.Add(fetchUUID2, "payments")

	consumer := kafkaEventFromPid(7, 42)
	for _, join := range [][]byte{joinGroupMyGroup, joinGroupOtherGroup} {
		_, ignore, err := ProcessPossibleKafkaEvent(consumer, largebuf.NewLargeBufferFrom(join), nil, uuidCache, groups)
		require.NoError(t, err)
		require.True(t, ignore)
	}

	infos, ignore, err := ProcessPossibleKafkaEvent(consumer, largebuf.NewLargeBufferFrom(fetchV13TwoTopics(fetchUUID1, fetchUUID2)), nil, uuidCache, groups)
	require.NoError(t, err)
	require.False(t, ignore)
	require.Len(t, infos, 2)
	assert.Equal(t, "orders", infos[0].Topic)
	assert.Equal(t, "my-group", infos[0].ConsumerGroup)
	assert.Equal(t, "payments", infos[1].Topic)
	assert.Equal(t, "other-group", infos[1].ConsumerGroup)
}

// OffsetCommit v10 names topics by UUID: Enrich must resolve them through the Metadata
// cache to fill the per-topic entries, and skip the ones the cache does not know yet.
func TestProcessKafkaEventConsumerGroupEnrichByUUID(t *testing.T) {
	groups := newTestConsumerGroups()
	uuidCache, err := simplelru.NewLRU[kafkaparser.UUID, string](16, nil)
	require.NoError(t, err)
	uuidCache.Add(fetchUUID1, "orders") // fetchUUID2 (payments) is not resolved yet

	consumer := kafkaEventFromPid(7, 42)
	for _, req := range [][]byte{joinGroupOtherGroup, offsetCommitOtherGroupUUID, joinGroupMyGroup} {
		_, ignore, err := ProcessPossibleKafkaEvent(consumer, largebuf.NewLargeBufferFrom(req), nil, uuidCache, groups)
		require.NoError(t, err)
		require.True(t, ignore)
	}
	proc := KafkaProcess{Ns: 7, Pid: 42}

	// the commit recorded orders -> other-group before my-group (orders, audit) joined,
	// so orders is now seen with two groups: that ambiguity proves the UUID was
	// translated into the name the JoinGroup subscription and the Fetch lookup use
	assert.Empty(t, groups.Lookup(proc, "orders"), "orders: other-group (by UUID) then my-group")
	assert.Equal(t, "my-group", groups.Lookup(proc, "audit"))
	assert.Equal(t, "other-group", groups.Lookup(proc, "payments"))

	// the unresolved UUID was skipped, not learned under an empty or wrong name:
	// resolving it later does not retroactively make "payments" ambiguous
	uuidCache.Add(fetchUUID2, "payments")
	assert.Equal(t, "other-group", groups.Lookup(proc, "payments"))
}

// OffsetCommit and OffsetFetch name a group without proving membership: the admin
// client sends them for operator-chosen groups. They must never establish a group and
// must only add topics to the group the process actually joined.
func TestProcessKafkaEventConsumerGroupOffsetRequestsDoNotJoin(t *testing.T) {
	groups := newTestConsumerGroups()
	consumer := kafkaEventFromPid(7, 42)

	t.Run("offset requests alone establish nothing", func(t *testing.T) {
		processKafka(t, groups, consumer, offsetFetchAdminGroup)
		processKafka(t, groups, consumer, offsetCommitAdminGroup)
		assert.Empty(t, fetchGroup(t, groups, consumer, fetchOrders))
	})

	t.Run("offset requests for another group leave the membership untouched", func(t *testing.T) {
		processKafka(t, groups, consumer, heartbeatHbGroup)
		processKafka(t, groups, consumer, offsetCommitAdminGroup)
		processKafka(t, groups, consumer, offsetFetchAdminGroup)
		assert.Equal(t, "hb-group", fetchGroup(t, groups, consumer, fetchOrders), "still the single group, not relabeled")
	})

	t.Run("offset commit adds topics only for a group the process joined", func(t *testing.T) {
		member := kafkaEventFromPid(7, 43)
		processKafka(t, groups, member, joinGroupOtherGroup) // other-group: payments
		processKafka(t, groups, member, heartbeatHbGroup)    // hb-group, no topics: two groups, no fallback
		processKafka(t, groups, member, offsetCommitMyGroupOrders)
		assert.Empty(t, fetchGroup(t, groups, member, fetchOrders), "not a member of my-group: ignored")
		processKafka(t, groups, member, offsetCommitHbGroupOrders)
		assert.Equal(t, "hb-group", fetchGroup(t, groups, member, fetchOrders), "member of hb-group: orders learned")
		assert.Equal(t, "other-group", fetchGroup(t, groups, member, fetchPayments))
	})
}

// LeaveGroup and a ConsumerGroupHeartbeat with a negative member epoch end the
// membership: the group must be forgotten, not learned, so that leaving group A and
// joining group B yields B rather than a two-group process forever.
func TestProcessKafkaEventConsumerGroupLeave(t *testing.T) {
	groups := newTestConsumerGroups()
	consumer := kafkaEventFromPid(7, 42)

	t.Run("leave of another group (admin removing members) keeps the membership", func(t *testing.T) {
		processKafka(t, groups, consumer, joinGroupMyGroup)
		processKafka(t, groups, consumer, leaveGroupOtherGroup)
		assert.Equal(t, "my-group", fetchGroup(t, groups, consumer, fetchOrders))
	})

	t.Run("leave of the joined group forgets it", func(t *testing.T) {
		processKafka(t, groups, consumer, leaveGroupMyGroup)
		assert.Empty(t, fetchGroup(t, groups, consumer, fetchOrders))
		assert.Empty(t, fetchGroup(t, groups, consumer, fetchImportant))
	})

	t.Run("leave A then join B resolves to B, not a two-group process", func(t *testing.T) {
		processKafka(t, groups, consumer, joinGroupOtherGroup)
		assert.Equal(t, "other-group", fetchGroup(t, groups, consumer, fetchPayments))
		assert.Equal(t, "other-group", fetchGroup(t, groups, consumer, fetchImportant), "single group again: fallback applies")
		assert.Equal(t, "other-group", fetchGroup(t, groups, consumer, fetchOrders), "my-group's subscription is gone")
	})

	t.Run("leaving one of two groups leaves the other as the single group", func(t *testing.T) {
		processKafka(t, groups, consumer, joinGroupMyGroup)
		assert.Empty(t, fetchGroup(t, groups, consumer, fetchImportant), "two groups: no fallback")
		processKafka(t, groups, consumer, leaveGroupMyGroup)
		assert.Equal(t, "other-group", fetchGroup(t, groups, consumer, fetchImportant), "single group again")
		assert.Equal(t, "other-group", fetchGroup(t, groups, consumer, fetchOrders), "my-group's topic entries are gone")
		processKafka(t, groups, consumer, heartbeatHbGroup)
		assert.Empty(t, fetchGroup(t, groups, consumer, fetchImportant))
	})

	t.Run("KIP-848 heartbeat: epoch 0 joins, negative epoch leaves", func(t *testing.T) {
		kip848 := kafkaEventFromPid(7, 77)
		processKafka(t, groups, kip848, cghJoinCghGroup)
		assert.Equal(t, "cgh-group", fetchGroup(t, groups, kip848, fetchOrders))
		processKafka(t, groups, kip848, cghLeaveCghGroup)
		assert.Empty(t, fetchGroup(t, groups, kip848, fetchOrders))
	})
}

// A membership expires when no membership request renewed it, and Fetch lookups do not
// renew it. The deadline is per membership: a recycled pid heartbeating for its own
// group must not keep the previous process' groups alive.
func TestProcessKafkaEventConsumerGroupExpiry(t *testing.T) {
	const ttl = time.Minute
	groups := NewKafkaConsumerGroups(64, ttl)
	start := time.Now()
	clock := start
	groups.now = func() time.Time { return clock }
	consumer := kafkaEventFromPid(7, 42)

	processKafka(t, groups, consumer, joinGroupMyGroup)
	clock = start.Add(ttl / 2)
	assert.Equal(t, "my-group", fetchGroup(t, groups, consumer, fetchOrders))
	clock = start.Add(ttl + ttl/4)
	assert.Empty(t, fetchGroup(t, groups, consumer, fetchOrders), "lookups must not extend the ttl")
	assert.Equal(t, 0, groups.lru.Len(), "a process without memberships is dropped")

	// pid reused within the ttl: the previous process joined my-group, the new one
	// heartbeats for hb-group only
	clock = start.Add(2 * ttl)
	processKafka(t, groups, consumer, joinGroupMyGroup)
	clock = start.Add(2*ttl + ttl/2)
	processKafka(t, groups, consumer, heartbeatHbGroup)
	assert.Empty(t, fetchGroup(t, groups, consumer, fetchImportant), "two groups until the inherited one expires")
	clock = start.Add(3*ttl + ttl/4)
	assert.Equal(t, "hb-group", fetchGroup(t, groups, consumer, fetchImportant), "inherited membership expired, own group is the single one")
	assert.Equal(t, "hb-group", fetchGroup(t, groups, consumer, fetchOrders), "the inherited subscription is gone too")
}

// Kafka Connect workers (protocol_type "connect") and Schema Registry ("sr") coordinate
// through JoinGroup/SyncGroup/Heartbeat too, but those groups are no consumer groups:
// they must not count as a membership, so a Connect worker's sink consumer keeps its
// single group and a registry reports none.
func TestProcessKafkaEventConsumerGroupForeignProtocol(t *testing.T) {
	groups := newTestConsumerGroups()

	worker := kafkaEventFromPid(7, 42)
	processKafka(t, groups, worker, heartbeatConnectCluster) // seen first: protocol type unknown yet
	processKafka(t, groups, worker, joinGroupMyGroup)
	assert.Empty(t, fetchGroup(t, groups, worker, fetchImportant), "two memberships, protocol of the first unknown")
	processKafka(t, groups, worker, joinGroupConnectCluster) // the next rebalance names protocol_type "connect"
	assert.Equal(t, "my-group", fetchGroup(t, groups, worker, fetchImportant), "the only consumer group")
	processKafka(t, groups, worker, heartbeatConnectCluster) // later heartbeats do not undo it
	assert.Equal(t, "my-group", fetchGroup(t, groups, worker, fetchImportant))

	// the worker leaving its coordination group changes nothing for the sink consumer;
	// leaving the sink group too drops the process entirely
	processKafka(t, groups, worker, leaveGroupConnectCluster)
	assert.Equal(t, "my-group", fetchGroup(t, groups, worker, fetchImportant))
	processKafka(t, groups, worker, leaveGroupMyGroup)
	assert.Empty(t, fetchGroup(t, groups, worker, fetchOrders))
	assert.Empty(t, groups.Lookup(KafkaProcess{Ns: 7, Pid: 42}, ""), "no membership left")

	registry := kafkaEventFromPid(7, 43)
	processKafka(t, groups, registry, syncGroupSchemaRegistry)
	assert.Empty(t, fetchGroup(t, groups, registry, fetchOrders), "an election group is not a consumer group")

	// topics learned while the group still passed for a consumer group are released
	early := KafkaProcess{Ns: 7, Pid: 44}
	groups.Join(early, &kafkaparser.GroupRequest{GroupID: "connect-cluster", Topics: []*kafkaparser.GroupTopic{{Name: "orders"}}}, nil)
	groups.Join(early, &kafkaparser.GroupRequest{GroupID: "connect-cluster", ProtocolType: "connect"}, nil)
	state, found := groups.lru.Get(early)
	require.True(t, found)
	assert.True(t, state.groups["connect-cluster"].foreign)
	assert.Empty(t, state.groups["connect-cluster"].members[""].topics)
}

// Subscriptions are recomputed from what each group currently subscribes to, so a group
// leaving or re-subscribing on a rebalance releases the topics it no longer consumes.
func TestProcessKafkaEventConsumerGroupSubscriptionChanges(t *testing.T) {
	groups := newTestConsumerGroups()
	consumer := kafkaEventFromPid(7, 42)
	proc := KafkaProcess{Ns: 7, Pid: 42}

	t.Run("a topic shared by two groups goes back to the remaining one", func(t *testing.T) {
		processKafka(t, groups, consumer, joinGroupMyGroup)          // my-group: orders, audit
		processKafka(t, groups, consumer, joinGroupOtherGroupOrders) // other-group: orders
		assert.Empty(t, fetchGroup(t, groups, consumer, fetchOrders))
		processKafka(t, groups, consumer, leaveGroupOtherGroup)
		assert.Equal(t, "my-group", fetchGroup(t, groups, consumer, fetchOrders))
	})

	t.Run("a complete subscription replaces the previous one", func(t *testing.T) {
		processKafka(t, groups, consumer, joinGroupMyGroupAudit)     // rebalance: my-group now [audit]
		processKafka(t, groups, consumer, joinGroupOtherGroupOrders) // other-group: orders
		assert.Equal(t, "other-group", fetchGroup(t, groups, consumer, fetchOrders), "orders left my-group's subscription")
		assert.Equal(t, "my-group", groups.Lookup(proc, "audit"))
	})

	t.Run("a KIP-848 heartbeat with a non-null subscription replaces it, a null one keeps it", func(t *testing.T) {
		kip848 := kafkaEventFromPid(7, 77)
		processKafka(t, groups, kip848, cghJoinCghGroup)  // cgh-group: orders
		processKafka(t, groups, kip848, joinGroupMyGroup) // my-group: orders, audit
		assert.Empty(t, fetchGroup(t, groups, kip848, fetchOrders), "orders subscribed by both")
		processKafka(t, groups, kip848, cghJoinCghGroupAudit) // cgh-group now [audit]
		assert.Equal(t, "my-group", fetchGroup(t, groups, kip848, fetchOrders), "orders released by cgh-group")
		assert.Empty(t, groups.Lookup(KafkaProcess{Ns: 7, Pid: 77}, "audit"), "audit now shared")
		processKafka(t, groups, kip848, cghUnchangedCghGroup) // null subscription: unchanged
		assert.Empty(t, groups.Lookup(KafkaProcess{Ns: 7, Pid: 77}, "audit"), "still shared")
		processKafka(t, groups, kip848, cghEmptyCghGroup) // empty, non-null: the member moved to a regex subscription
		assert.Equal(t, "my-group", groups.Lookup(KafkaProcess{Ns: 7, Pid: 77}, "audit"), "released by cgh-group")
	})

	t.Run("a partial subscription (cut by the kernel buffer) only adds", func(t *testing.T) {
		groups.Join(proc, &kafkaparser.GroupRequest{GroupID: "my-group", Topics: []*kafkaparser.GroupTopic{{Name: "payments"}}}, nil)
		assert.Equal(t, "my-group", groups.Lookup(proc, "audit"), "kept")
		assert.Equal(t, "my-group", fetchGroup(t, groups, consumer, fetchPayments), "added")
	})
}

// A process hosts several members of one group when it runs several consumers with the
// same group.id (every Kafka Streams thread is one). Each keeps its own subscription and
// the group's is their union, so a member joining must not drop another's topics.
func TestProcessKafkaEventConsumerGroupMultipleMembers(t *testing.T) {
	groups := newTestConsumerGroups()
	consumer := kafkaEventFromPid(7, 42)
	proc := KafkaProcess{Ns: 7, Pid: 42}

	t.Run("a second member adds its subscription to the group's", func(t *testing.T) {
		processKafka(t, groups, consumer, joinGroupMyGroup)         // member abc: orders, audit
		processKafka(t, groups, consumer, joinGroupMyGroupPayments) // member def: payments
		processKafka(t, groups, consumer, joinGroupOtherGroupOrders)
		assert.Empty(t, fetchGroup(t, groups, consumer, fetchOrders), "orders: my-group (abc) and other-group")
		assert.Equal(t, "my-group", groups.Lookup(proc, "audit"))
		assert.Equal(t, "my-group", fetchGroup(t, groups, consumer, fetchPayments))
	})

	t.Run("a leave forgets that member only", func(t *testing.T) {
		processKafka(t, groups, consumer, leaveGroupMyGroupUnknown) // another process' member, removed by an admin
		assert.Equal(t, "my-group", fetchGroup(t, groups, consumer, fetchPayments))
		processKafka(t, groups, consumer, leaveGroupMyGroupDef)
		assert.Empty(t, fetchGroup(t, groups, consumer, fetchPayments), "nobody's topic in a two-group process")
		assert.Equal(t, "my-group", groups.Lookup(proc, "audit"), "abc is still a member")
		processKafka(t, groups, consumer, leaveGroupMyGroup)
		assert.Equal(t, "other-group", fetchGroup(t, groups, consumer, fetchOrders), "my-group has no member left")
	})

	t.Run("a member's subscription expires with it, not with the group", func(t *testing.T) {
		const ttl = time.Minute
		groups := NewKafkaConsumerGroups(64, ttl)
		start := time.Now()
		clock := start
		groups.now = func() time.Time { return clock }

		processKafka(t, groups, consumer, joinGroupMyGroup)         // abc: orders, audit
		processKafka(t, groups, consumer, joinGroupMyGroupPayments) // def: payments
		clock = start.Add(ttl / 2)
		processKafka(t, groups, consumer, heartbeatMyGroupDef) // only def is still heartbeating
		clock = start.Add(ttl + ttl/4)
		assert.Equal(t, "my-group", fetchGroup(t, groups, consumer, fetchPayments))
		state, found := groups.lru.Get(proc)
		require.True(t, found)
		assert.NotContains(t, state.groups["my-group"].members, "member-abc-123", "abc expired")
		assert.Contains(t, state.groups["my-group"].members, "member-def-456")
	})

	t.Run("offset commits of a member the process does not host are ignored", func(t *testing.T) {
		groups := newTestConsumerGroups()
		processKafka(t, groups, consumer, joinGroupMyGroupPayments) // def only
		processKafka(t, groups, consumer, joinGroupOtherGroup)
		processKafka(t, groups, consumer, offsetCommitMyGroupOrders) // member abc
		assert.Empty(t, fetchGroup(t, groups, consumer, fetchOrders), "orders not learned for my-group")
	})
}

// A first JoinGroup carries no member id: the coordinator assigns one and the member
// rejoins with it. Both requests are the same member, so the second must take over the
// first's state rather than leave a member behind that only the ttl would remove.
func TestProcessKafkaEventConsumerGroupMemberIDAssigned(t *testing.T) {
	groups := newTestConsumerGroups()
	consumer := kafkaEventFromPid(7, 42)
	proc := KafkaProcess{Ns: 7, Pid: 42}

	processKafka(t, groups, consumer, joinGroupMyGroupNoMemberID)
	processKafka(t, groups, consumer, joinGroupMyGroup)
	state, found := groups.lru.Get(proc)
	require.True(t, found)
	assert.Len(t, state.groups["my-group"].members, 1)
	assert.Contains(t, state.groups["my-group"].members, "member-abc-123")

	// an older broker accepts the first join as is: the id first shows up in a Heartbeat
	processKafka(t, groups, consumer, leaveGroupMyGroup)
	processKafka(t, groups, consumer, joinGroupMyGroupNoMemberID)
	processKafka(t, groups, consumer, heartbeatMyGroupDef)
	assert.Equal(t, "my-group", fetchGroup(t, groups, consumer, fetchOrders), "the subscription followed the id")
	processKafka(t, groups, consumer, leaveGroupMyGroupDef)
	assert.Empty(t, fetchGroup(t, groups, consumer, fetchOrders), "no member without an id left behind")
}

// A process holds at most maxGroupsPerProcess memberships and maxMembersPerGroup members
// in each: a client cycling through group or member ids cannot grow the entry until the
// TTL trims it.
func TestKafkaConsumerGroupsMembershipCap(t *testing.T) {
	groups := newTestConsumerGroups()
	proc := KafkaProcess{Ns: 7, Pid: 42}
	for i := range maxGroupsPerProcess + 5 {
		groups.Join(proc, &kafkaparser.GroupRequest{GroupID: fmt.Sprintf("group-%d", i), MemberID: "member"}, nil)
	}
	for i := range maxMembersPerGroup + 5 {
		groups.Join(proc, &kafkaparser.GroupRequest{GroupID: "group-0", MemberID: fmt.Sprintf("member-%d", i)}, nil)
	}
	state, found := groups.lru.Get(proc)
	require.True(t, found)
	assert.Len(t, state.groups, maxGroupsPerProcess)
	assert.Contains(t, state.groups, "group-0", "the first memberships are kept")
	assert.NotContains(t, state.groups, fmt.Sprintf("group-%d", maxGroupsPerProcess))
	assert.Len(t, state.groups["group-0"].members, maxMembersPerGroup)
	assert.Contains(t, state.groups["group-0"].members, "member", "the first members are kept")
	assert.NotContains(t, state.groups["group-0"].members, fmt.Sprintf("member-%d", maxMembersPerGroup-1))
}
