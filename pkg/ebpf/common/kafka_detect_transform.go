// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"
	"unsafe"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"
)

type Operation int8

const (
	Produce Operation = 0
	Fetch   Operation = 1
)

type PartitionInfo struct {
	Partition int
	Offset    int64
}

type KafkaInfo struct {
	Operation     Operation
	Topic         string
	ClientID      string
	PartitionInfo *PartitionInfo
}

func (k Operation) String() string {
	switch k {
	case Produce:
		return request.MessagingPublish
	case Fetch:
		return request.MessagingProcess
	default:
		return "unknown"
	}
}

// ProcessPossibleKafkaEvent processes a TCP packet and returns error if the packet is not a valid Kafka request.
// Otherwise, return kafka.Info with the processed data.
func ProcessPossibleKafkaEvent(event *TCPRequestInfo, pkt *LargeBufferReader, rpkt *LargeBufferReader, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) (*KafkaInfo, bool, error) {
	k, ok, err := ProcessKafkaEvent(pkt, rpkt, kafkaTopicUUIDToName)
	if err != nil {
		// If we are getting the information in the response buffer, the event
		// must be reversed and that's how we captured it.
		// Reset readers before retrying with swapped buffers.
		if pkt != nil {
			pkt.Reset()
		}
		if rpkt != nil {
			rpkt.Reset()
		}
		k, ok, err = ProcessKafkaEvent(rpkt, pkt, kafkaTopicUUIDToName)
		if err == nil {
			reverseTCPEvent(event)
		}
	}
	return k, ok, err
}

func ProcessKafkaEvent(pkt *LargeBufferReader, rpkt *LargeBufferReader, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) (*KafkaInfo, bool, error) {
	hdr, err := kafkaparser.ParseKafkaRequestHeader(pkt)
	if err != nil {
		return nil, true, err
	}
	switch hdr.APIKey {
	case kafkaparser.APIKeyProduce:
		return processProduceRequest(pkt, hdr)
	case kafkaparser.APIKeyFetch:
		return processFetchRequest(pkt, hdr, kafkaTopicUUIDToName)
	case kafkaparser.APIKeyMetadata:
		return processMetadataResponse(rpkt, hdr, kafkaTopicUUIDToName)
	default:
		return nil, true, errors.New("unsupported Kafka API key")
	}
}

func processProduceRequest(pkt *LargeBufferReader, hdr *kafkaparser.KafkaRequestHeader) (*KafkaInfo, bool, error) {
	produceReq, err := kafkaparser.ParseProduceRequest(pkt, hdr)
	if err != nil {
		return nil, true, err
	}
	var partitionInfo *PartitionInfo
	if produceReq.Topics[0].Partition != nil {
		partitionInfo = &PartitionInfo{
			Partition: *produceReq.Topics[0].Partition,
		}
	}
	return &KafkaInfo{
		ClientID:  hdr.ClientID,
		Operation: Produce,
		// TODO: handle multiple topics
		Topic:         produceReq.Topics[0].Name,
		PartitionInfo: partitionInfo,
	}, false, nil
}

func processFetchRequest(pkt *LargeBufferReader, hdr *kafkaparser.KafkaRequestHeader, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) (*KafkaInfo, bool, error) {
	fetchReq, err := kafkaparser.ParseFetchRequest(pkt, hdr)
	if err != nil {
		return nil, true, err
	}
	firstTopic := fetchReq.Topics[0]
	topicName := firstTopic.Name
	// get topic name from UUID if available
	if firstTopic.UUID != nil {
		var found bool
		topicName, found = kafkaTopicUUIDToName.Get(*firstTopic.UUID)
		if !found {
			topicName = "*"
		}
	}
	var partitionInfo *PartitionInfo
	if firstTopic.Partition != nil {
		partitionInfo = &PartitionInfo{
			Partition: firstTopic.Partition.Partition,
			Offset:    firstTopic.Partition.FetchOffset,
		}
	}
	return &KafkaInfo{
		ClientID:  hdr.ClientID,
		Operation: Fetch,
		// TODO: handle multiple topics
		Topic:         topicName,
		PartitionInfo: partitionInfo,
	}, false, nil
}

func processMetadataResponse(rpkt *LargeBufferReader, hdr *kafkaparser.KafkaRequestHeader, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) (*KafkaInfo, bool, error) {
	if rpkt == nil {
		return nil, true, errors.New("no response buffer for metadata request")
	}
	// only interested in response
	_, err := kafkaparser.ParseKafkaResponseHeader(rpkt, hdr)
	if err != nil {
		return nil, true, err
	}
	metadataResponse, err := kafkaparser.ParseMetadataResponse(rpkt, hdr)
	if err != nil {
		return nil, true, err
	}
	for _, topic := range metadataResponse.Topics {
		kafkaTopicUUIDToName.Add(topic.UUID, topic.Name)
	}
	return nil, true, nil
}

func ProcessKafkaRequest(pkt *LargeBufferReader, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) (*KafkaInfo, bool, error) {
	hdr, err := kafkaparser.ParseKafkaRequestHeader(pkt)
	if err != nil {
		return nil, true, err
	}
	switch hdr.APIKey {
	case kafkaparser.APIKeyProduce:
		return processProduceRequest(pkt, hdr)
	case kafkaparser.APIKeyFetch:
		return processFetchRequest(pkt, hdr, kafkaTopicUUIDToName)
	default:
		return nil, true, errors.New("unsupported Kafka API key")
	}
}

func TCPToKafkaToSpan(trace *TCPRequestInfo, data *KafkaInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	reqType := request.EventTypeKafkaClient
	if trace.Direction == 0 {
		reqType = request.EventTypeKafkaServer
	}

	var messagingInfo *request.MessagingInfo

	if data.PartitionInfo != nil {
		messagingInfo = &request.MessagingInfo{
			Partition: data.PartitionInfo.Partition,
			Offset:    data.PartitionInfo.Offset,
		}
	}

	return request.Span{
		Type:          reqType,
		Method:        data.Operation.String(),
		Statement:     data.ClientID,
		Path:          data.Topic,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        0,
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
		MessagingInfo: messagingInfo,
	}
}
