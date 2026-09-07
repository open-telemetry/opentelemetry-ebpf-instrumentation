// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

// reqBuilder encodes Kafka wire primitives for hand-built request fixtures.
// Compact variants are the flexible-version encodings (uvarint length + 1).
type reqBuilder struct {
	buf []byte
}

func (b *reqBuilder) i8(v int8)   { b.buf = append(b.buf, byte(v)) }
func (b *reqBuilder) i16(v int16) { b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(v)) }
func (b *reqBuilder) i32(v int32) { b.buf = binary.BigEndian.AppendUint32(b.buf, uint32(v)) }
func (b *reqBuilder) i64(v int64) { b.buf = binary.BigEndian.AppendUint64(b.buf, uint64(v)) }
func (b *reqBuilder) uvarint(v uint64) {
	b.buf = binary.AppendUvarint(b.buf, v)
}
func (b *reqBuilder) raw(p []byte) { b.buf = append(b.buf, p...) }
func (b *reqBuilder) uuid(u UUID)  { b.buf = append(b.buf, u[:]...) }
func (b *reqBuilder) tagged()      { b.buf = append(b.buf, 0) }

func (b *reqBuilder) str(s string) {
	b.i16(int16(len(s)))
	b.raw([]byte(s))
}
func (b *reqBuilder) nullStr() { b.i16(-1) }

func (b *reqBuilder) compactStr(s string) {
	b.uvarint(uint64(len(s) + 1))
	b.raw([]byte(s))
}
func (b *reqBuilder) compactNullStr() { b.uvarint(0) }

func (b *reqBuilder) bytes(p []byte) {
	b.i32(int32(len(p)))
	b.raw(p)
}
func (b *reqBuilder) nullBytes() { b.i32(-1) }

func (b *reqBuilder) compactBytes(p []byte) {
	b.uvarint(uint64(len(p) + 1))
	b.raw(p)
}

func (b *reqBuilder) arrayLen(n int)        { b.i32(int32(n)) }
func (b *reqBuilder) compactArrayLen(n int) { b.uvarint(uint64(n + 1)) }
func (b *reqBuilder) compactNullArray()     { b.uvarint(0) }

// testClientID is the client_id written in every fixture header (Java's default for
// group "1", first consumer).
const testClientID = "consumer-1-1"

// buildRequest prepends the request header (message_size, api_key, api_version,
// correlation_id, client_id and, for flexible versions, empty tagged fields) to body.
func buildRequest(apiKey KafkaAPIKey, version int16, flexible bool, body []byte) []byte {
	h := &reqBuilder{}
	h.i32(0) // message_size, patched below
	h.i16(int16(apiKey))
	h.i16(version)
	h.i32(7) // correlation_id
	h.str(testClientID)
	if flexible {
		h.tagged()
	}
	h.raw(body)
	binary.BigEndian.PutUint32(h.buf[0:4], uint32(len(h.buf)-Int32Len))
	return h.buf
}

// consumerSubscription encodes ConsumerProtocolSubscription v1 (the JoinGroup
// protocol metadata payload sent by consumers): version, topics, user_data,
// owned_partitions.
func consumerSubscription(topics ...string) []byte {
	b := &reqBuilder{}
	b.i16(1)
	b.arrayLen(len(topics))
	for _, t := range topics {
		b.str(t)
	}
	b.nullBytes() // user_data
	b.arrayLen(0) // owned_partitions
	return b.buf
}

func joinGroupV5(groupID, protocolType string, topics ...string) []byte {
	b := &reqBuilder{}
	b.str(groupID)
	b.i32(10000) // session_timeout_ms
	b.i32(30000) // rebalance_timeout_ms
	b.str("")    // member_id
	b.nullStr()  // group_instance_id
	b.str(protocolType)
	b.arrayLen(1)
	b.str("range")
	b.bytes(consumerSubscription(topics...))
	return buildRequest(APIKeyJoinGroup, 5, false, b.buf)
}

func joinGroupV7(groupID string, topics ...string) []byte {
	b := &reqBuilder{}
	b.compactStr(groupID)
	b.i32(10000)
	b.i32(30000)
	b.compactStr("")   // member_id
	b.compactNullStr() // group_instance_id
	b.compactStr("consumer")
	b.compactArrayLen(1)
	b.compactStr("range")
	b.compactBytes(consumerSubscription(topics...))
	b.tagged() // per-protocol tagged fields
	b.tagged() // request tagged fields
	return buildRequest(APIKeyJoinGroup, 7, true, b.buf)
}

func heartbeatV3(groupID string) []byte {
	b := &reqBuilder{}
	b.str(groupID)
	b.i32(3)                // generation_id
	b.str("member-abc-123") // member_id
	b.nullStr()             // group_instance_id
	return buildRequest(APIKeyHeartbeat, 3, false, b.buf)
}

func heartbeatV4(groupID string) []byte {
	b := &reqBuilder{}
	b.compactStr(groupID)
	b.i32(3)
	b.compactStr("member-abc-123")
	b.compactNullStr()
	b.tagged()
	return buildRequest(APIKeyHeartbeat, 4, true, b.buf)
}

func syncGroupV5(groupID string) []byte {
	b := &reqBuilder{}
	b.compactStr(groupID)
	b.i32(3) // generation_id
	b.compactStr("member-abc-123")
	b.compactNullStr()   // group_instance_id
	b.compactNullStr()   // protocol_type
	b.compactNullStr()   // protocol_name
	b.compactArrayLen(0) // assignments
	b.tagged()
	return buildRequest(APIKeySyncGroup, 5, true, b.buf)
}

func leaveGroupV5(groupID string) []byte {
	b := &reqBuilder{}
	b.compactStr(groupID)
	b.compactArrayLen(1) // members
	b.compactStr("member-abc-123")
	b.compactNullStr() // group_instance_id
	b.compactNullStr() // reason (v5+)
	b.tagged()
	b.tagged()
	return buildRequest(APIKeyLeaveGroup, 5, true, b.buf)
}

func offsetFetchV7(groupID string, topics ...string) []byte {
	b := &reqBuilder{}
	b.compactStr(groupID)
	b.compactArrayLen(len(topics))
	for _, t := range topics {
		b.compactStr(t)
		b.compactArrayLen(1)
		b.i32(0) // partition_index
		b.tagged()
	}
	b.i8(0) // require_stable
	b.tagged()
	return buildRequest(APIKeyOffsetFetch, 7, true, b.buf)
}

func offsetFetchV8(groupID string, topics ...string) []byte {
	b := &reqBuilder{}
	b.compactArrayLen(1) // groups
	b.compactStr(groupID)
	b.compactArrayLen(len(topics))
	for _, t := range topics {
		b.compactStr(t)
		b.compactArrayLen(1)
		b.i32(0)
		b.tagged()
	}
	b.tagged() // per-group tagged fields
	b.i8(0)    // require_stable
	b.tagged()
	return buildRequest(APIKeyOffsetFetch, 8, true, b.buf)
}

func offsetCommitV8(groupID string, topics ...string) []byte {
	b := &reqBuilder{}
	b.compactStr(groupID)
	b.i32(3) // generation_id_or_member_epoch
	b.compactStr("member-abc-123")
	b.compactNullStr() // group_instance_id
	b.compactArrayLen(len(topics))
	for _, t := range topics {
		b.compactStr(t)
		b.compactArrayLen(1)
		b.i32(3)           // partition_index
		b.i64(42)          // committed_offset
		b.i32(-1)          // committed_leader_epoch
		b.compactNullStr() // committed_metadata
		b.tagged()
		b.tagged()
	}
	b.tagged()
	return buildRequest(APIKeyOffsetCommit, 8, true, b.buf)
}

func offsetCommitV10(groupID string, topicIDs ...UUID) []byte {
	b := &reqBuilder{}
	b.compactStr(groupID)
	b.i32(3)
	b.compactStr("member-abc-123")
	b.compactNullStr()
	b.compactArrayLen(len(topicIDs))
	for _, id := range topicIDs {
		b.uuid(id)
		b.compactArrayLen(1)
		b.i32(3)
		b.i64(42)
		b.i32(-1)
		b.compactNullStr()
		b.tagged()
		b.tagged()
	}
	b.tagged()
	return buildRequest(APIKeyOffsetCommit, 10, true, b.buf)
}

// consumerGroupHeartbeatV0 encodes the KIP-848 heartbeat. subscribed == nil
// encodes a null SubscribedTopicNames (unchanged since the last heartbeat).
func consumerGroupHeartbeatV0(groupID string, subscribed []string, owned []UUID) []byte {
	b := &reqBuilder{}
	b.compactStr(groupID)
	b.compactStr("member-abc-123")
	b.i32(0)           // member_epoch: 0 = join
	b.compactNullStr() // instance_id
	b.compactNullStr() // rack_id
	b.i32(-1)          // rebalance_timeout_ms
	if subscribed == nil {
		b.compactNullArray()
	} else {
		b.compactArrayLen(len(subscribed))
		for _, t := range subscribed {
			b.compactStr(t)
		}
	}
	b.compactNullStr() // server_assignor
	if owned == nil {
		b.compactNullArray()
	} else {
		b.compactArrayLen(len(owned))
		for _, id := range owned {
			b.uuid(id)
			b.compactArrayLen(1)
			b.i32(0)
			b.tagged()
		}
	}
	b.tagged()
	return buildRequest(APIKeyConsumerGroupHeartbeat, 0, true, b.buf)
}

var (
	ordersUUID = UUID{0xac, 0xe7, 0x65, 0x7b, 0x24, 0xd4, 0x4d, 0xe4, 0x8e, 0x57, 0x1a, 0xf0, 0xfa, 0xec, 0xcc, 0x0f}
	auditUUID  = UUID{0xc1, 0x88, 0x33, 0x2c, 0x43, 0x39, 0x47, 0x7c, 0xb2, 0x5d, 0x21, 0x15, 0xbf, 0x1f, 0x8a, 0xe9}
)

func TestParseGroupRequest(t *testing.T) {
	tests := []struct {
		name          string
		packet        []byte
		expectErr     bool
		expectGroupID string
		expectTopics  []string
		expectUUIDs   []UUID
	}{
		{
			name:          "join group v5 (non-flexible), consumer subscription",
			packet:        joinGroupV5("my-group", "consumer", "orders", "audit"),
			expectGroupID: "my-group",
			expectTopics:  []string{"orders", "audit"},
		},
		{
			name:          "join group v7 (flexible), consumer subscription",
			packet:        joinGroupV7("my-group", "orders", "audit"),
			expectGroupID: "my-group",
			expectTopics:  []string{"orders", "audit"},
		},
		{
			// Groups with another protocol_type (e.g. Kafka Connect's "connect") carry
			// opaque metadata: group id only. Kafka Streams uses "consumer" and is parsed.
			name:          "join group v5 with non-consumer protocol type",
			packet:        joinGroupV5("connect-cluster", "connect", "orders"),
			expectGroupID: "connect-cluster",
		},
		{
			name:          "heartbeat v3 (non-flexible)",
			packet:        heartbeatV3("my-group"),
			expectGroupID: "my-group",
		},
		{
			name:          "heartbeat v4 (flexible)",
			packet:        heartbeatV4("my-group"),
			expectGroupID: "my-group",
		},
		{
			name:          "sync group v5",
			packet:        syncGroupV5("my-group"),
			expectGroupID: "my-group",
		},
		{
			name:          "leave group v5",
			packet:        leaveGroupV5("my-group"),
			expectGroupID: "my-group",
		},
		{
			name:          "offset fetch v7 (top-level group id)",
			packet:        offsetFetchV7("my-group", "orders"),
			expectGroupID: "my-group",
			expectTopics:  []string{"orders"},
		},
		{
			name:          "offset fetch v8 (groups array)",
			packet:        offsetFetchV8("my-group", "orders", "audit"),
			expectGroupID: "my-group",
			expectTopics:  []string{"orders", "audit"},
		},
		{
			name:          "offset commit v8 (topic names)",
			packet:        offsetCommitV8("my-group", "orders", "audit"),
			expectGroupID: "my-group",
			expectTopics:  []string{"orders", "audit"},
		},
		{
			name:          "offset commit v10 (topic ids)",
			packet:        offsetCommitV10("my-group", ordersUUID, auditUUID),
			expectGroupID: "my-group",
			expectUUIDs:   []UUID{ordersUUID, auditUUID},
		},
		{
			name:          "consumer group heartbeat v0, subscribed topic names",
			packet:        consumerGroupHeartbeatV0("my-group", []string{"orders", "audit"}, nil),
			expectGroupID: "my-group",
			expectTopics:  []string{"orders", "audit"},
		},
		{
			name:          "consumer group heartbeat v0, unchanged subscription, owned partitions",
			packet:        consumerGroupHeartbeatV0("my-group", nil, []UUID{ordersUUID}),
			expectGroupID: "my-group",
			expectUUIDs:   []UUID{ordersUUID},
		},
		{
			name:          "consumer group heartbeat v0, nothing but the group id",
			packet:        consumerGroupHeartbeatV0("my-group", nil, nil),
			expectGroupID: "my-group",
		},
		{
			// The kernel forwards at most k_tcp_max_len bytes of a request, so a
			// cut topic list is the normal case: the group id must still come out.
			name:          "offset commit truncated inside the topic list",
			packet:        offsetCommitV8("my-group", "orders", "audit")[:88],
			expectGroupID: "my-group",
			expectTopics:  []string{"orders"},
		},
		{
			name:      "empty group id",
			packet:    heartbeatV4(""),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr, err := NewKafkaRequestHeader(largebuf.NewLargeBufferFrom(tt.packet))
			require.NoError(t, err)
			assert.Equal(t, testClientID, hdr.ClientID())

			r, err := hdr.NewBodyReader()
			require.NoError(t, err)

			req, err := ParseGroupRequest(&r, hdr)
			if tt.expectErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, req)
			assert.Equal(t, tt.expectGroupID, req.GroupID)

			var names []string
			var uuids []UUID
			for _, topic := range req.Topics {
				if topic.UUID != nil {
					uuids = append(uuids, *topic.UUID)
					continue
				}
				names = append(names, topic.Name)
			}
			assert.Equal(t, tt.expectTopics, names)
			assert.Equal(t, tt.expectUUIDs, uuids)
		})
	}
}

func TestIsFlexibleGroupAPIs(t *testing.T) {
	tests := []struct {
		apiKey   KafkaAPIKey
		version  int16
		expected bool
	}{
		{APIKeyOffsetCommit, 7, false},
		{APIKeyOffsetCommit, 8, true},
		{APIKeyOffsetFetch, 5, false},
		{APIKeyOffsetFetch, 6, true},
		{APIKeyJoinGroup, 5, false},
		{APIKeyJoinGroup, 6, true},
		{APIKeyHeartbeat, 3, false},
		{APIKeyHeartbeat, 4, true},
		{APIKeyLeaveGroup, 3, false},
		{APIKeyLeaveGroup, 4, true},
		{APIKeySyncGroup, 3, false},
		{APIKeySyncGroup, 4, true},
		{APIKeyConsumerGroupHeartbeat, 0, true},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, isFlexible(newUncheckedHeader(tt.apiKey, tt.version)),
			"api key %d version %d", tt.apiKey, tt.version)
	}
}
