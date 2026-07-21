// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"testing"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		// TODO these tests don't seem like valid kafka packets, check that
		//{
		//	name:  "Fetch request (v12)",
		//	request: []byte{0, 0, 0, 52, 0, 1, 0, 12, 0, 0, 1, 3, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 255, 255, 255, 255, 0, 0, 1, 244, 0, 0, 0, 1, 3, 32, 0, 0, 0, 30, 37, 158, 231, 0, 0, 0, 156, 1, 1, 1, 0, 53, 99, 48, 57, 45, 52, 52, 48, 48, 45, 98, 54, 101, 101, 45, 56, 54, 102, 97, 102, 101, 102, 57, 52, 102, 101, 98, 0, 2, 9, 109, 121, 45, 116, 111, 112, 105, 99, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 0, 0, 0, 0, 1, 0, 0, 0, 101, 121, 12, 118, 97, 108, 117, 101, 51, 0, 30, 0, 0},
		//	expected: &KafkaInfo{
		//		ClientID:  "consumer-1-1",
		//		Operation: Fetch,
		//		Topic:     "my-topic",
		//	},
		// },
		//{
		//	name:  "Fetch request (v15)",
		//	request: []byte{0, 0, 0, 68, 0, 1, 0, 15, 0, 0, 38, 94, 0, 32, 99, 111, 110, 115, 117, 109, 101, 114, 45, 102, 114, 97, 117, 100, 100, 101, 116, 101, 99, 116, 105, 111, 110, 115, 101, 114, 118, 105, 99, 101, 45, 49, 0, 0, 0, 1, 244, 0, 0, 0, 1, 3, 32, 0, 0, 0, 33, 62, 224, 94, 0, 0, 30, 44, 2, 1, 1, 0, 1, 70, 99, 111, 110, 115, 117, 109, 101, 114, 45, 102, 114, 97, 117, 100, 100, 101, 116, 101, 99, 116, 105, 111, 110, 115, 101, 114, 118, 105, 99, 101, 45, 49, 45, 50, 51, 48, 98, 51, 55, 101, 100, 45, 98, 101, 57, 102, 45, 52, 97, 53, 99, 45, 97, 52},
		//	expected: &KafkaInfo{
		//		ClientID:    "consumer-frauddetectionservice-1",
		//		Operation:   Fetch,
		//		Topic:       "*",
		//	},
		// },
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
					_, ignore, err := ProcessKafkaEvent(largebuf.NewLargeBufferFrom(preInput.request), largebuf.NewLargeBufferFrom(preInput.response), cache)
					require.NoError(t, err)
					require.True(t, ignore)
				}
			}
			res, _, err := ProcessKafkaEvent(largebuf.NewLargeBufferFrom(tt.request), nil, cache)
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

	infos, ignore, err := ProcessKafkaRequest(largebuf.NewLargeBufferFrom(request), nil)
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

	infos, ignore, err := ProcessKafkaRequest(largebuf.NewLargeBufferFrom(request), cache)
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
func TestProcessKafkaRequestFetchMultiTopic(t *testing.T) {
	uuid1 := kafkaparser.UUID{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	}
	uuid2 := kafkaparser.UUID{
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
	}

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

	cache, _ := simplelru.NewLRU[kafkaparser.UUID, string](1000, nil)
	cache.Add(uuid1, "topic-one")
	cache.Add(uuid2, "topic-two")

	infos, ignore, err := ProcessKafkaRequest(largebuf.NewLargeBufferFrom(pkt), cache)
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
