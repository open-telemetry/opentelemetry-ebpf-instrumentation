// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

// GroupTopic is a topic referenced by a group request, by name or (KIP-516) by UUID.
type GroupTopic struct {
	Name string
	UUID *UUID
}

// GroupRequest is the consumer-group view of a group-coordination or offset
// request: the group id, plus the topics the request mentions when it carries any.
type GroupRequest struct {
	GroupID string
	Topics  []*GroupTopic
}

const (
	maxGroupTopics = 100

	consumerProtocolType = "consumer"
)

var errKafkaInvalidGroupID = errors.New("invalid group id")

// ParseGroupRequest parses the body of a group-coordination or offset request.
// Only the group id is mandatory: the kernel forwards a bounded prefix of every
// request, so the topic list may be cut and is returned as far as it was read.
func ParseGroupRequest(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*GroupRequest, error) {
	switch header.APIKey() {
	case APIKeyJoinGroup:
		return parseJoinGroup(r, header)
	case APIKeyOffsetCommit:
		return parseOffsetCommit(r, header)
	case APIKeyOffsetFetch:
		return parseOffsetFetch(r, header)
	case APIKeyConsumerGroupHeartbeat:
		return parseConsumerGroupHeartbeat(r, header)
	case APIKeyHeartbeat, APIKeyLeaveGroup, APIKeySyncGroup:
		groupID, err := readGroupID(r, header)
		if err != nil {
			return nil, err
		}
		return &GroupRequest{GroupID: groupID}, nil
	default:
		return nil, errKafkaReqUnsupportedAPIKey
	}
}

/*
JoinGroup Request (Version: 0-9) => group_id session_timeout_ms rebalance_timeout_ms member_id group_instance_id protocol_type [protocols] reason _tagged_fields

	group_id => STRING / COMPACT_STRING
	session_timeout_ms => INT32
	rebalance_timeout_ms => INT32 (1+)
	member_id => STRING / COMPACT_STRING (empty on the first join)
	group_instance_id => NULLABLE_STRING (5+)
	protocol_type => STRING / COMPACT_STRING
	protocols => name metadata _tagged_fields
	  name => STRING / COMPACT_STRING
	  metadata => BYTES / COMPACT_BYTES (ConsumerProtocolSubscription when protocol_type == "consumer")
*/
func parseJoinGroup(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*GroupRequest, error) {
	groupID, err := readGroupID(r, header)
	if err != nil {
		return nil, err
	}
	req := &GroupRequest{GroupID: groupID}

	skipLen := Int32Len // session_timeout_ms
	if header.APIVersion() >= 1 {
		skipLen += Int32Len // rebalance_timeout_ms
	}
	if err = r.Skip(skipLen); err != nil {
		return req, nil
	}
	if err = skipString(r, header); err != nil { // member_id
		return req, nil
	}
	if header.APIVersion() >= 5 {
		if err = skipString(r, header); err != nil { // group_instance_id
			return req, nil
		}
	}
	protocolType, err := readString(r, header, false)
	if err != nil || protocolType != consumerProtocolType {
		return req, nil
	}
	protocolsLen, err := readArrayLength(r, header)
	if err != nil || protocolsLen == 0 {
		return req, nil
	}
	// Every protocol entry lists the same subscription: the first one is enough.
	if err = skipString(r, header); err != nil { // protocols[0].name
		return req, nil
	}
	metadataLen, err := readBytesLength(r, header)
	if err != nil {
		return req, nil
	}
	req.Topics = parseConsumerSubscriptionTopics(r, metadataLen)
	return req, nil
}

// parseConsumerSubscriptionTopics reads the topics of a ConsumerProtocolSubscription
// payload. The payload has its own non-flexible encoding regardless of the
// enclosing request version:
//
//	version => INT16
//	topics => INT32 count, STRING each
//	(user_data, owned_partitions, ... not read)
func parseConsumerSubscriptionTopics(r *largebuf.LargeBufferReader, payloadLen int) []*GroupTopic {
	if payloadLen < Int16Len+Int32Len {
		return nil
	}
	if _, err := readInt16(r); err != nil { // version
		return nil
	}
	count, err := readInt32(r)
	if err != nil {
		return nil
	}
	count = min(count, maxGroupTopics)
	var topics []*GroupTopic
	for range count {
		size, err := readInt16(r)
		if err != nil || size < 1 {
			return topics
		}
		name, err := readValidatedString(r, size)
		if err != nil {
			return topics
		}
		topics = append(topics, &GroupTopic{Name: name})
	}
	return topics
}

/*
OffsetCommit Request (Version: 2-10) => group_id generation_id_or_member_epoch member_id group_instance_id retention_time_ms [topics] _tagged_fields

	group_id => STRING / COMPACT_STRING
	generation_id_or_member_epoch => INT32
	member_id => STRING / COMPACT_STRING
	group_instance_id => NULLABLE_STRING (7+)
	retention_time_ms => INT64 (2-4)
	topics => name topic_id [partitions] _tagged_fields
	  name => STRING / COMPACT_STRING (0-9)
	  topic_id => UUID (10+)
	  partitions => partition_index committed_offset committed_leader_epoch committed_metadata _tagged_fields
	    partition_index => INT32
	    committed_offset => INT64
	    committed_leader_epoch => INT32 (6+)
	    committed_metadata => NULLABLE_STRING
*/
func parseOffsetCommit(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*GroupRequest, error) {
	groupID, err := readGroupID(r, header)
	if err != nil {
		return nil, err
	}
	req := &GroupRequest{GroupID: groupID}

	if err = r.Skip(Int32Len); err != nil { // generation_id_or_member_epoch
		return req, nil
	}
	if err = skipString(r, header); err != nil { // member_id
		return req, nil
	}
	if header.APIVersion() >= 7 {
		if err = skipString(r, header); err != nil { // group_instance_id
			return req, nil
		}
	}
	if header.APIVersion() <= 4 {
		if err = r.Skip(Int64Len); err != nil { // retention_time_ms
			return req, nil
		}
	}
	req.Topics = parseGroupTopics(r, header, header.APIVersion() >= 10, skipOffsetCommitPartition)
	return req, nil
}

func skipOffsetCommitPartition(r *largebuf.LargeBufferReader, header KafkaRequestHeader) error {
	skipLen := Int32Len + Int64Len // partition_index, committed_offset
	if header.APIVersion() >= 6 {
		skipLen += Int32Len // committed_leader_epoch
	}
	if err := r.Skip(skipLen); err != nil {
		return err
	}
	if err := skipString(r, header); err != nil { // committed_metadata
		return err
	}
	return skipTaggedFields(r, header)
}

/*
OffsetFetch Request (Version: 1-7) => group_id [topics] require_stable _tagged_fields

	group_id => STRING / COMPACT_STRING
	topics => name [partition_indexes] _tagged_fields (nullable 2+)
	require_stable => BOOLEAN (7+)

OffsetFetch Request (Version: 8-10) => [groups] require_stable _tagged_fields

	groups => group_id member_id member_epoch [topics] _tagged_fields
	  group_id => COMPACT_STRING
	  member_id => COMPACT_NULLABLE_STRING (9+)
	  member_epoch => INT32 (9+)
	  topics => name topic_id [partition_indexes] _tagged_fields (nullable)
	    name => COMPACT_STRING (8-9)
	    topic_id => UUID (10+)
*/
func parseOffsetFetch(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*GroupRequest, error) {
	if header.APIVersion() >= 8 {
		groupsLen, err := readArrayLength(r, header)
		if err != nil {
			return nil, err
		}
		if groupsLen == 0 {
			return nil, errKafkaInvalidGroupID
		}
	}
	groupID, err := readGroupID(r, header)
	if err != nil {
		return nil, err
	}
	req := &GroupRequest{GroupID: groupID}

	if header.APIVersion() >= 9 {
		if err = skipString(r, header); err != nil { // member_id
			return req, nil
		}
		if err = r.Skip(Int32Len); err != nil { // member_epoch
			return req, nil
		}
	}
	req.Topics = parseGroupTopics(r, header, header.APIVersion() >= 10, skipInt32)
	return req, nil
}

/*
ConsumerGroupHeartbeat Request (Version: 0-1) => group_id member_id member_epoch instance_id rack_id rebalance_timeout_ms [subscribed_topic_names] subscribed_topic_regex server_assignor [topic_partitions] _tagged_fields

	group_id => COMPACT_STRING
	member_id => COMPACT_STRING
	member_epoch => INT32
	instance_id => COMPACT_NULLABLE_STRING
	rack_id => COMPACT_NULLABLE_STRING
	rebalance_timeout_ms => INT32
	subscribed_topic_names => COMPACT_NULLABLE_ARRAY of COMPACT_STRING (null when unchanged)
	subscribed_topic_regex => COMPACT_NULLABLE_STRING (1+)
	server_assignor => COMPACT_NULLABLE_STRING
	topic_partitions => topic_id [partitions] _tagged_fields (null when unchanged)
	  topic_id => UUID
	  partitions => INT32
*/
func parseConsumerGroupHeartbeat(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (*GroupRequest, error) {
	groupID, err := readGroupID(r, header)
	if err != nil {
		return nil, err
	}
	req := &GroupRequest{GroupID: groupID}

	if err = skipString(r, header); err != nil { // member_id
		return req, nil
	}
	if err = r.Skip(Int32Len); err != nil { // member_epoch
		return req, nil
	}
	if err = skipString(r, header); err != nil { // instance_id
		return req, nil
	}
	if err = skipString(r, header); err != nil { // rack_id
		return req, nil
	}
	if err = r.Skip(Int32Len); err != nil { // rebalance_timeout_ms
		return req, nil
	}
	namesLen, err := readArrayLength(r, header)
	if err != nil {
		return req, nil
	}
	for range min(namesLen, maxGroupTopics) {
		name, err := readString(r, header, false)
		if err != nil {
			return req, nil
		}
		req.Topics = append(req.Topics, &GroupTopic{Name: name})
	}
	if header.APIVersion() >= 1 {
		if err = skipString(r, header); err != nil { // subscribed_topic_regex
			return req, nil
		}
	}
	if err = skipString(r, header); err != nil { // server_assignor
		return req, nil
	}
	req.Topics = append(req.Topics, parseGroupTopics(r, header, true, skipInt32)...)
	return req, nil
}

// parseGroupTopics walks a topics array whose entries are
// (name | topic_id) [partitions] _tagged_fields, keeping the reader aligned by
// skipping every partition entry with skipPartition. Errors end the walk and the
// topics read so far are returned: a truncated buffer is the normal case.
func parseGroupTopics(r *largebuf.LargeBufferReader, header KafkaRequestHeader, byUUID bool,
	skipPartition func(*largebuf.LargeBufferReader, KafkaRequestHeader) error,
) []*GroupTopic {
	topicsLen, err := readArrayLength(r, header)
	if err != nil {
		return nil
	}
	var topics []*GroupTopic
	for range min(topicsLen, maxGroupTopics) {
		var topic GroupTopic
		if byUUID {
			topic.UUID, err = readUUID(r)
		} else {
			topic.Name, err = readString(r, header, false)
		}
		if err != nil {
			return topics
		}
		topics = append(topics, &topic)

		partitionsLen, err := readArrayLength(r, header)
		if err != nil {
			return topics
		}
		for range partitionsLen {
			if err = skipPartition(r, header); err != nil {
				return topics
			}
		}
		if err = skipTaggedFields(r, header); err != nil {
			return topics
		}
	}
	return topics
}

func skipInt32(r *largebuf.LargeBufferReader, _ KafkaRequestHeader) error {
	return r.Skip(Int32Len)
}

// readGroupID reads a non-empty group id. Kafka does not restrict the characters
// of a group id the way it does for topic names, so only require printable UTF-8.
func readGroupID(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (string, error) {
	size, err := readStringLength(r, header, false)
	if err != nil {
		return "", err
	}
	if size == 0 {
		return "", errKafkaInvalidGroupID
	}
	if r.Remaining() < size {
		return "", errKafkaStringSizeExceedsPacket
	}
	b, err := r.ReadN(size)
	if err != nil {
		return "", errKafkaStringSizeExceedsPacket
	}
	if !utf8.Valid(b) {
		return "", errKafkaInvalidGroupID
	}
	for _, c := range b {
		if c < ' ' || c == 0x7f {
			return "", errKafkaInvalidGroupID
		}
	}
	return string(b), nil
}

// readValidatedString reads size bytes and applies the topic-name character rules.
func readValidatedString(r *largebuf.LargeBufferReader, size int) (string, error) {
	if r.Remaining() < size {
		return "", errKafkaStringSizeExceedsPacket
	}
	b, err := r.ReadN(size)
	if err != nil {
		return "", errKafkaStringSizeExceedsPacket
	}
	if !validateKafkaString(b, size) {
		return "", errKafkaInvalidCharactersInString
	}
	return string(b), nil
}

// skipString advances past a string field of any nullability, accepting empty
// values (readString rejects them: a first JoinGroup carries an empty member_id).
func skipString(r *largebuf.LargeBufferReader, header KafkaRequestHeader) error {
	var size int
	var err error
	if isFlexible(header) {
		size, err = readCompactLength(r)
	} else {
		size, err = readInt16(r)
	}
	if err != nil {
		return err
	}
	return r.Skip(max(size, 0))
}

// readBytesLength reads the length prefix of a BYTES / COMPACT_BYTES field;
// null (-1 or compact 0) yields 0.
func readBytesLength(r *largebuf.LargeBufferReader, header KafkaRequestHeader) (int, error) {
	if isFlexible(header) {
		return readCompactLength(r)
	}
	b, err := r.ReadN(Int32Len)
	if err != nil {
		return 0, errKafkaDataTooShortForInt32
	}
	return max(int(int32(binary.BigEndian.Uint32(b))), 0), nil
}

// readCompactLength decodes a compact length prefix (uvarint of length + 1);
// null (0) yields 0.
func readCompactLength(r *largebuf.LargeBufferReader) (int, error) {
	size, err := readUnsignedVarint(r)
	if err != nil {
		return 0, err
	}
	return max(size-1, 0), nil
}
