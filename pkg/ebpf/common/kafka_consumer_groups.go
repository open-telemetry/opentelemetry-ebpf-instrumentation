// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"
)

// KafkaProcess identifies the instrumented process a Kafka request was captured from.
// Fetch requests carry no consumer group, and the group-coordination requests that do
// typically travel on a dedicated connection to the group coordinator (Java,
// kafka-python, librdkafka), often a different broker, so the process is the only key
// shared by both.
type KafkaProcess struct {
	Ns  uint32
	Pid uint32
}

type kafkaGroupKey struct {
	KafkaProcess
	// Topic is empty for the process-level entry.
	Topic string
}

type kafkaGroupEntry struct {
	group string
	// ambiguous marks a process that joined more than one group: the process-level
	// entry can no longer be trusted for topics it did not learn explicitly.
	ambiguous bool
}

// KafkaConsumerGroups remembers, per process, which consumer group consumes which
// topic, learned from the requests that name topics (JoinGroup, OffsetCommit,
// OffsetFetch, ConsumerGroupHeartbeat). A process-level entry (empty topic) is learned
// from every group request and backs Fetch requests whose topic is unknown: KIP-227
// session fetches carry no topic, a topic UUID may not be resolved yet, and Heartbeat,
// SyncGroup and LeaveGroup carry no topics at all.
type KafkaConsumerGroups struct {
	lru *simplelru.LRU[kafkaGroupKey, kafkaGroupEntry]
}

func NewKafkaConsumerGroups(size int) (*KafkaConsumerGroups, error) {
	lru, err := simplelru.NewLRU[kafkaGroupKey, kafkaGroupEntry](size, nil)
	if err != nil {
		return nil, err
	}
	return &KafkaConsumerGroups{lru: lru}, nil
}

// Learn records the group of req for proc. Topics referenced by UUID are resolved
// through kafkaTopicUUIDToName and skipped when unknown.
func (g *KafkaConsumerGroups) Learn(proc KafkaProcess, req *kafkaparser.GroupRequest, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) {
	if g == nil {
		return
	}
	for _, topic := range req.Topics {
		name := topic.Name
		if topic.UUID != nil {
			if kafkaTopicUUIDToName == nil {
				continue
			}
			resolved, found := kafkaTopicUUIDToName.Get(*topic.UUID)
			if !found {
				continue
			}
			name = resolved
		}
		if name == "" {
			continue
		}
		g.lru.Add(kafkaGroupKey{KafkaProcess: proc, Topic: name}, kafkaGroupEntry{group: req.GroupID})
	}
	g.learnProcessGroup(proc, req.GroupID)
}

func (g *KafkaConsumerGroups) learnProcessGroup(proc KafkaProcess, group string) {
	key := kafkaGroupKey{KafkaProcess: proc}
	current, found := g.lru.Get(key)
	if !found {
		g.lru.Add(key, kafkaGroupEntry{group: group})
		return
	}
	if current.ambiguous || current.group == group {
		return
	}
	g.lru.Add(key, kafkaGroupEntry{ambiguous: true})
}

// Lookup returns the group consuming topic in proc, or the process-level group when
// the topic is unknown and the process joined a single group. Empty when unknown.
func (g *KafkaConsumerGroups) Lookup(proc KafkaProcess, topic string) string {
	if g == nil {
		return ""
	}
	if topic != "" {
		if entry, found := g.lru.Get(kafkaGroupKey{KafkaProcess: proc, Topic: topic}); found {
			return entry.group
		}
	}
	entry, found := g.lru.Get(kafkaGroupKey{KafkaProcess: proc})
	if !found || entry.ambiguous {
		return ""
	}
	return entry.group
}
